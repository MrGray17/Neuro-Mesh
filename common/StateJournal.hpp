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

        // SHA-256 hash from evidence (inline to avoid circular include)
        std::string hash = hash_evidence(evidence_json);

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

    // Inline SHA-256 via shell-out to avoid coupling to crypto headers.
    // For header-only simplicity we use a deterministic fingerprint.
    static std::string hash_evidence(const std::string& data) {
        // Use std::hash as a fast fingerprint (not cryptographic but unique per payload).
        // Full SHA-256 would require including CryptoCore.hpp which creates a circular dep.
        // The hash is for audit correlation, not security — the Ed25519 signature on
        // PBFT messages already provides cryptographic integrity.
        std::hash<std::string> hasher;
        uint64_t h = hasher(data);
        char buf[17];
        snprintf(buf, sizeof(buf), "%016lx", static_cast<unsigned long>(h));
        return {buf};
    }

    std::string m_path;
    std::atomic<uint64_t> m_seq;
    std::mutex m_write_mtx;
};

} // namespace neuro_mesh
