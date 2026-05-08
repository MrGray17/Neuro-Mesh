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

namespace neuro_mesh {

// =============================================================================
// Construction
// =============================================================================

MitigationEngine::MitigationEngine(PolicyEnforcer* enforcer)
    : m_enforcer(enforcer)
{}

// =============================================================================
// JSON field extraction — simple scan, no library dependency
// =============================================================================

std::string MitigationEngine::extract_str(std::string_view json, std::string_view key) {
    // Search for "key":" — the quoted key followed by colon+quote
    std::string needle;
    needle.reserve(key.size() + 4);
    needle.push_back('"');
    needle.append(key);
    needle.append("\":");

    size_t pos = json.find(needle);
    if (pos == std::string_view::npos) return {};

    // Skip past the needle and the opening quote of the value
    size_t val_start = pos + needle.size();
    if (val_start >= json.size() || json[val_start] != '"') return {};
    ++val_start; // skip opening quote

    // Find closing quote
    size_t val_end = json.find('"', val_start);
    if (val_end == std::string_view::npos) return {};

    return std::string(json.substr(val_start, val_end - val_start));
}

int64_t MitigationEngine::extract_int(std::string_view json, std::string_view key) {
    std::string needle;
    needle.reserve(key.size() + 3);
    needle.push_back('"');
    needle.append(key);
    needle.append("\":");

    size_t pos = json.find(needle);
    if (pos == std::string_view::npos) return -1;

    size_t val_start = pos + needle.size();
    if (val_start >= json.size()) return -1;

    // Skip optional whitespace
    while (val_start < json.size() && json[val_start] == ' ') ++val_start;
    if (val_start >= json.size()) return -1;

    // Parse number
    int64_t val = 0;
    bool negative = false;
    if (json[val_start] == '-') { negative = true; ++val_start; }

    while (val_start < json.size() && json[val_start] >= '0' && json[val_start] <= '9') {
        val = val * 10 + (json[val_start] - '0');
        ++val_start;
    }

    return negative ? -val : val;
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

    if (kill(static_cast<pid_t>(pid), SIGKILL) == -1) {
        if (errno == ESRCH) {
            // Race: process exited between validation and kill — not an error
            std::cout << "[ENFORCEMENT] PID " << pid
                      << " already exited (race). No action needed." << std::endl;
            return true; // desired state achieved
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
    ts << std::put_time(std::localtime(&now_time_t), "%Y-%m-%dT%H:%M:%S");
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

    // ---- Node-level isolation (existing PolicyEnforcer path) ----
    // Always isolate the target node at EXECUTED stage
    if (m_enforcer && !target_id.empty()) {
        m_enforcer->isolate_target(target_id);
        any_action = true;
    }

    return any_action;
}

} // namespace neuro_mesh
