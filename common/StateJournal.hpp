#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "crypto/CryptoCore.hpp"

namespace neuro_mesh {

class StateJournal {
public:
    explicit StateJournal(const std::string& path = "./journal.log")
        : m_path(path), m_seq(0)
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
        // Only log if there's recovered state
        uint64_t recovered = m_seq.load();
        if (recovered > 0) {
            std::cout << "[JOURNAL] Recovered " << recovered
                      << " entries from " << path << std::endl;
        }
    }

    uint64_t append(const std::string& stage,
                    const std::string& target_id,
                    const std::string& evidence_json)
    {
        uint64_t seq = m_seq.fetch_add(1, std::memory_order_relaxed) + 1;

        // Cryptographic SHA-256 audit hash — enables forensic verification
        std::string hash = crypto::IdentityCore::sha256_hex(evidence_json);
        if (hash.empty()) {
            hash = std::string(64, '0');  // fallback on crypto failure
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Build JSON line without library dependency
        std::string line = "{\"seq\":" + std::to_string(seq)
                         + ",\"ts\":" + std::to_string(now_ms)
                         + ",\"stage\":\"" + stage + "\""
                         + ",\"target\":\"" + target_id + "\""
                         + ",\"evidence\":" + evidence_json
                         + ",\"hash\":\"" + hash + "\"}\n";

        std::lock_guard<std::mutex> lock(m_write_mtx);

        // Atomic log rotation using flock() - prevents TOCTOU race
        {
            int lock_fd = ::open(m_path.c_str(), O_RDWR);
            if (lock_fd >= 0) {
                struct flock fl;
                fl.l_type = F_WRLCK;
                fl.l_whence = SEEK_SET;
                fl.l_start = 0;
                fl.l_len = 0;

                if (fcntl(lock_fd, F_SETLK, &fl) == 0) {
                    struct stat st;
                    if (fstat(lock_fd, &st) == 0 && st.st_size > 10 * 1024 * 1024) {
                        std::string backup = m_path + ".1";
                        ::rename(m_path.c_str(), backup.c_str());
                    }
                    fl.l_type = F_UNLCK;
                    fcntl(lock_fd, F_SETLK, &fl);
                }
                close(lock_fd);
            }
        }

        int fd = ::open(m_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) return seq;

        ssize_t written = ::write(fd, line.data(), line.size());
        ::fsync(fd);
        ::close(fd);

        if (written < 0) {
            std::cerr << "[JOURNAL] Write failed: " << m_path << std::endl;
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
        pos += 6; // skip "seq":
        uint64_t val = 0;
        while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') {
            val = val * 10 + (line[pos] - '0');
            ++pos;
        }
        return val;
    }


    std::string m_path;
    std::atomic<uint64_t> m_seq;
    std::mutex m_write_mtx;
};

} // namespace neuro_mesh
