#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <cstdint>

namespace neuro_mesh {

class PolicyEnforcer;

class MitigationEngine {
public:
    explicit MitigationEngine(PolicyEnforcer* jailer);

    // Consume a PBFT EXECUTED verdict and execute the appropriate response.
    // Parses evidence_json for event type, PID, and source IP.
    // Returns true if any enforcement action was taken.
    bool execute_response(const std::string& evidence_json, const std::string& target_id);

    // Exposed for testing / IPC command injection
    bool terminate_process(uint32_t pid);

private:
    // JSON field extraction (no library dependency — simple key-value scanning)
    static std::string extract_str(std::string_view json, std::string_view key);
    static int64_t extract_int(std::string_view json, std::string_view key);

    // Validate evidence JSON schema before processing
    static bool validate_evidence_schema(std::string_view json);

    // Validate PID before sending signal
    bool validate_pid(uint32_t pid) const;

    // Block an IP through the enforcement cascade (delegates to PolicyEnforcer)
    bool block_ip_address(const std::string& ip);

    // Log enforcement action with timestamp and cryptographic consensus hash
    void log_enforcement(const std::string& action, const std::string& detail, const std::string& consensus_hash);

    PolicyEnforcer* m_enforcer;
};

} // namespace neuro_mesh
