#include "enforcer/MitigationEngine.hpp"
#include "enforcer/PolicyEnforcer.hpp"
#include "crypto/CryptoCore.hpp"

#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/syscall.h>

#include <nlohmann/json.hpp>

namespace neuro_mesh {

// =============================================================================
// Construction
// =============================================================================

MitigationEngine::MitigationEngine(PolicyEnforcer* enforcer)
    : m_enforcer(enforcer)
{}

// =============================================================================
// JSON field extraction — via nlohmann/json (robust, RFC 8259 compliant)
// =============================================================================

std::string MitigationEngine::extract_str(std::string_view json, std::string_view key) {
    try {
        auto j = nlohmann::json::parse(json, nullptr, false);
        if (!j.is_object()) return {};
        auto it = j.find(key);
        if (it == j.end() || !it->is_string()) return {};
        return it->get<std::string>();
    } catch (...) {
        return {};
    }
}

int64_t MitigationEngine::extract_int(std::string_view json, std::string_view key) {
    try {
        auto j = nlohmann::json::parse(json, nullptr, false);
        if (!j.is_object()) return -1;
        auto it = j.find(key);
        if (it == j.end() || !it->is_number_integer()) return -1;
        return it->get<int64_t>();
    } catch (...) {
        return -1;
    }
}

// =============================================================================
// Evidence JSON Schema Validation
// =============================================================================

bool MitigationEngine::validate_evidence_schema(std::string_view json) {
    // Reject empty or oversized evidence
    if (json.empty() || json.size() > 8192) {
        std::cerr << "[VALIDATION] Evidence rejected: empty or oversized (" << json.size() << " bytes)" << std::endl;
        return false;
    }

    // Parse with nlohmann/json — robust against escaped quotes, whitespace,
    // unicode escapes, and nested structures.
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json, nullptr, /* allow_exceptions = */ true);
    } catch (const nlohmann::json::parse_error &e) {
        std::cerr << "[VALIDATION] Evidence rejected: JSON parse error — " << e.what() << std::endl;
        return false;
    }

    if (!j.is_object()) {
        std::cerr << "[VALIDATION] Evidence rejected: not a JSON object" << std::endl;
        return false;
    }

    // Check for at least one known field
    static const char* valid_fields[] = {"event", "verdict", "src_ip", "pid", "node", "entropy", "source"};
    bool has_valid_field = false;
    for (const char* field : valid_fields) {
        if (j.contains(field)) {
            has_valid_field = true;
            break;
        }
    }

    if (!has_valid_field) {
        std::cerr << "[VALIDATION] Evidence rejected: no recognized fields" << std::endl;
        return false;
    }

    return true;
}

// =============================================================================
// PID validation
// =============================================================================

bool MitigationEngine::validate_pid(uint32_t pid) const {
    // Never kill init (PID 1) — it would panic the kernel
    if (pid <= 1) {
        std::cerr << "[ENFORCEMENT] REFUSED: won't kill PID " << pid
                  << " (init/systemd)." << std::endl;
        return false;
    }

    // Never kill ourselves
    if (pid == static_cast<uint32_t>(getpid())) {
        std::cerr << "[ENFORCEMENT] REFUSED: won't kill self (PID " << pid << ")."
                  << std::endl;
        return false;
    }

    // Check if the process exists
    if (kill(static_cast<pid_t>(pid), 0) == -1) {
        if (errno == ESRCH) {
            std::cerr << "[ENFORCEMENT] PID " << pid
                      << " no longer exists (ESRCH). Skipping." << std::endl;
        } else if (errno == EPERM) {
            std::cerr << "[ENFORCEMENT] No permission to signal PID " << pid
                      << " (EPERM). Skipping." << std::endl;
        } else {
            std::cerr << "[ENFORCEMENT] Cannot validate PID " << pid
                      << ": " << strerror(errno) << std::endl;
        }
        return false;
    }

    return true;
}

// =============================================================================
// Process termination
// =============================================================================

bool MitigationEngine::terminate_process(uint32_t pid) {
    if (!validate_pid(pid)) return false;

#if defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
    errno = 0;
    int pidfd = static_cast<int>(
        syscall(SYS_pidfd_open, static_cast<pid_t>(pid), 0));
    if (pidfd >= 0) {
        int rc = static_cast<int>(
            syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0));
        int saved_errno = errno;
        close(pidfd);

        if (rc == 0) {
            std::cout << "[ENFORCEMENT] SIGKILL delivered to PID " << pid
                      << " via pidfd." << std::endl;
            return true;
        }
        if (saved_errno == ESRCH) {
            std::cout << "[ENFORCEMENT] PID " << pid
                      << " already exited. No action needed." << std::endl;
            return true;
        }
        std::cerr << "[ENFORCEMENT] pidfd SIGKILL failed for PID " << pid
                  << ": " << strerror(saved_errno) << std::endl;
        return false;
    }

    if (errno == ESRCH) {
        std::cout << "[ENFORCEMENT] PID " << pid
                  << " already exited. No action needed." << std::endl;
        return true;
    }
    if (errno != ENOSYS && errno != EINVAL) {
        std::cerr << "[ENFORCEMENT] pidfd_open failed for PID " << pid
                  << ": " << strerror(errno) << std::endl;
        return false;
    }
#endif

    // Compatibility fallback for older Linux kernels without pidfd support.
    if (kill(static_cast<pid_t>(pid), SIGKILL) == -1) {
        if (errno == ESRCH) {
            std::cout << "[ENFORCEMENT] PID " << pid
                      << " already exited. No action needed." << std::endl;
            return true;
        }
        std::cerr << "[ENFORCEMENT] SIGKILL failed for PID " << pid
                  << ": " << strerror(errno) << std::endl;
        return false;
    }

    std::cout << "[ENFORCEMENT] SIGKILL delivered to PID " << pid << "." << std::endl;
    return true;
}

// =============================================================================
// IP blocking — delegates to PolicyEnforcer enforcement cascade
// =============================================================================

bool MitigationEngine::block_ip_address(const std::string& ip) {
    if (!m_enforcer) {
        std::cerr << "[ENFORCEMENT] No enforcer available to block IP " << ip << std::endl;
        return false;
    }
    return m_enforcer->block_ip_address(ip);
}

// =============================================================================
// Enforcement logging
// =============================================================================

void MitigationEngine::log_enforcement(const std::string& action,
                                        const std::string& detail,
                                        const std::string& consensus_hash) {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;

    std::ostringstream ts;
    std::tm tm_buf{};
    ts << std::put_time(localtime_r(&now_time_t, &tm_buf), "%Y-%m-%dT%H:%M:%S");
    ts << '.' << std::setfill('0') << std::setw(3) << ms.count();

    // Truncate hash to 16 chars for readability in logs
    std::string short_hash = consensus_hash.substr(0, 16);

    std::cout << "[ENFORCEMENT] " << ts.str()
              << " | action=" << action
              << " | " << detail
              << " | hash=" << short_hash
              << std::endl;
}

// =============================================================================
// Core execution pipeline — called from MeshNode at PBFT EXECUTED stage
// =============================================================================

// D3FEND: Orchestrates D3-PT (Process Termination) and D3-NTF (Network Traffic Filtering)
// based on PBFT consensus verdict. Parses evidence_json for pid/src_ip to dispatch.
bool MitigationEngine::execute_response(const std::string& evidence_json,
                                         const std::string& target_id) {
    // Validate evidence JSON schema before processing
    if (!validate_evidence_schema(evidence_json)) {
        return false;
    }

    // Compute cryptographic hash of the consensus evidence for audit trail
    std::string consensus_hash = crypto::IdentityCore::sha256_hex(evidence_json);
    if (consensus_hash.empty()) {
        std::cerr << "[ENFORCEMENT] Failed to compute consensus hash. Aborting."
                  << std::endl;
        return false;
    }

    // Parse verdict fields from the evidence JSON
    std::string event_type  = extract_str(evidence_json, "event");
    std::string verdict     = extract_str(evidence_json, "verdict");
    std::string src_ip      = extract_str(evidence_json, "src_ip");
    int64_t raw_pid         = extract_int(evidence_json, "pid");

    bool any_action = false;

    // ---- Process termination path ----
    // Trigger on privilege_escalation events carrying a valid PID
    if (event_type == "privilege_escalation" && raw_pid > 0) {
        uint32_t pid = static_cast<uint32_t>(raw_pid);
        log_enforcement("KILL",
                        "pid=" + std::to_string(pid) + " event=" + event_type,
                        consensus_hash);

        if (terminate_process(pid)) {
            any_action = true;
            log_enforcement("KILL_OK",
                            "pid=" + std::to_string(pid) + " SIGKILL delivered",
                            consensus_hash);
        } else {
            log_enforcement("KILL_FAIL",
                            "pid=" + std::to_string(pid) + " not terminated",
                            consensus_hash);
        }
    }

    // ---- Network enforcement path ----
    // Trigger on lateral_movement or any verdict carrying src_ip
    if (!src_ip.empty() &&
        (event_type == "lateral_movement" ||
         verdict == "THREAT" ||
         verdict == "CRITICAL")) {

        // Check safe list BEFORE blocking — if the IP belongs to a
        // safe-listed node, refuse to block it regardless of what the
        // evidence says (prevents spoofed src_ip from isolating trusted peers).
        if (m_enforcer && m_enforcer->is_ip_safe(src_ip)) {
            std::cerr << "[MITIGATION] REFUSED: " << src_ip
                      << " belongs to safe-listed node — skipping block."
                      << std::endl;
            log_enforcement("BLOCK_SAFELISTED",
                            "ip=" + src_ip + " belongs to safe-listed node",
                            consensus_hash);
        } else {
            log_enforcement("BLOCK",
                            "ip=" + src_ip + " event=" + event_type,
                            consensus_hash);

            if (block_ip_address(src_ip)) {
                any_action = true;
                log_enforcement("BLOCK_OK",
                                "ip=" + src_ip + " traffic dropped",
                                consensus_hash);
            } else {
                log_enforcement("BLOCK_FAIL",
                                "ip=" + src_ip + " enforcement cascade failed",
                                consensus_hash);
            }
        }
    }

    // ---- Node-level isolation (existing PolicyEnforcer path) ----
    // Only mark as success if isolation actually succeeded
    if (m_enforcer && !target_id.empty()) {
        bool isolated = m_enforcer->isolate_target(target_id);
        if (isolated) {
            any_action = true;
        } else {
            std::cerr << "[MITIGATION] FAILED: Could not isolate " << target_id
                      << " — enforcement backends unavailable. Consensus reached but isolation incomplete." << std::endl;
        }
    }

    return any_action;
}

} // namespace neuro_mesh
