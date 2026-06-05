#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "crypto/CryptoCore.hpp"

namespace neuro_mesh {

class StateJournal {
public:
    explicit StateJournal(const std::string& path = "./journal.log")
        : m_path(path), m_seq(0), m_fd(-1)
    {
        std::ifstream in(path);
        if (in.is_open()) {
            std::string line;
            while (std::getline(in, line)) {
                if (line.empty()) continue;
                uint64_t seq = extract_seq(line);
                if (seq > m_seq.load()) m_seq.store(seq);
            }
        }

        m_fd = ::open(m_path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0644);
        if (m_fd < 0) {
            std::cerr << "[JOURNAL] Failed to open " << path << std::endl;
        }

        uint64_t recovered = m_seq.load();
        if (recovered > 0) {
            std::cout << "[JOURNAL] Recovered " << recovered
                      << " entries from " << path << std::endl;
        }
    }

    ~StateJournal() {
        if (m_fd >= 0) {
            ::fsync(m_fd);
            ::close(m_fd);
        }
    }

    StateJournal(const StateJournal&) = delete;
    StateJournal& operator=(const StateJournal&) = delete;

    uint64_t append(const std::string& stage,
                    const std::string& target_id,
                    const std::string& evidence_json)
    {
        // relaxed: sequence counter is monotonic, no cross-thread ordering dependency
        uint64_t seq = m_seq.fetch_add(1, std::memory_order_relaxed) + 1;

        std::string hash = crypto::IdentityCore::sha256_hex(evidence_json);
        if (hash.empty()) {
            hash = std::string(64, '0');
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        std::string escaped_evidence = evidence_json;
        for (size_t i = 0; i < escaped_evidence.size(); ++i) {
            char c = escaped_evidence[i];
            if (c == '"' || c == '\\') {
                escaped_evidence.insert(i++, 1, '\\');
            } else if (c == '\n') {
                escaped_evidence.replace(i, 1, "\\n");
                ++i;
            } else if (c == '\t') {
                escaped_evidence.replace(i, 1, "\\t");
                ++i;
            } else if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                int n = std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                escaped_evidence.replace(i, 1, std::string(buf, n));
                i += n - 1;
            }
        }

        std::string line = "{\"seq\":" + std::to_string(seq)
                         + ",\"ts\":" + std::to_string(now_ms)
                         + ",\"stage\":\"" + stage + "\""
                         + ",\"target\":\"" + target_id + "\""
                         + ",\"evidence\":\"" + escaped_evidence + "\""
                         + ",\"hash\":\"" + hash + "\"}\n";

        std::lock_guard<std::mutex> lock(m_write_mtx);

        if (m_fd < 0) {
            m_fd = ::open(m_path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0644);
            if (m_fd < 0) return seq;
        }

        struct flock fl;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;

        if (fcntl(m_fd, F_SETLK, &fl) == 0) {
            struct stat st;
            if (fstat(m_fd, &st) == 0 && st.st_size > 10 * 1024 * 1024) {
                // Copy-truncate rotation: preserves fd and POSIX lock
                // throughout, eliminating the TOCTOU race window where
                // rename() releases the lock (BUG-07 fix).
                std::string backup = m_path + ".1";
                int backup_fd = ::open(backup.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (backup_fd >= 0) {
                    // Rewind to beginning of current file
                    if (::lseek(m_fd, 0, SEEK_SET) < 0) {
                        ::close(backup_fd);
                    } else {
                        char buf[65536];
                        ssize_t n;
                        bool copy_ok = true;
                        while ((n = ::read(m_fd, buf, sizeof(buf))) > 0) {
                            ssize_t w = ::write(backup_fd, buf, static_cast<size_t>(n));
                            if (w != n) { copy_ok = false; break; }
                        }
                        ::close(backup_fd);
                        // Only truncate if the full copy succeeded.
                        // Prevents journal data loss when backup write fails.
                        if (copy_ok) {
                            (void)::ftruncate(m_fd, 0);
                        }
                    }
                }
            }
            fl.l_type = F_UNLCK;
            fcntl(m_fd, F_SETLK, &fl);
        }

        ssize_t written = ::write(m_fd, line.data(), line.size());
        ::fsync(m_fd);

        if (written < 0) {
            // Audit A3: log only on first write failure to prevent stderr
            // flooding when the disk is full or the journal is unavailable.
            // The operator can monitor disk health out-of-band.
            if (!m_write_failure_logged.exchange(true)) {
                std::cerr << "[JOURNAL] Write failed: " << m_path
                          << " (further errors suppressed)" << std::endl;
            }
        } else {
            m_write_failure_logged.store(false);
        }

        return seq;
    }

    [[nodiscard]] uint64_t last_seq() const {
        return m_seq.load(std::memory_order_relaxed);
    }

private:
    static uint64_t extract_seq(const std::string& line) {
        auto pos = line.find("\"seq\":");
        if (pos == std::string::npos) return 0;
        pos += 6;
        uint64_t val = 0;
        while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') {
            uint64_t digit = static_cast<uint64_t>(line[pos] - '0');
            if (val > (UINT64_MAX - digit) / 10) return 0;
            val = val * 10 + digit;
            ++pos;
        }
        return val;
    }

    std::string m_path;
    std::atomic<uint64_t> m_seq;
    std::mutex m_write_mtx;
    int m_fd;
    // Audit A3: gate the "write failed" stderr log so a full disk or
    // closed fd doesn't generate one log line per append() call.
    std::atomic<bool> m_write_failure_logged{false};
};

} // namespace neuro_mesh
