#pragma once
#include <string>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <unordered_map>
#include <cstdint>

namespace neuro_mesh {

enum class EnforcementBackend : uint8_t {
    NONE     = 0,
    EBPF     = 1 << 0,
    NFTABLES = 1 << 1,
    IPTABLES = 1 << 2,
};

inline EnforcementBackend operator|(EnforcementBackend a, EnforcementBackend b) {
    return static_cast<EnforcementBackend>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}
inline bool operator&(EnforcementBackend a, EnforcementBackend b) {
    return (static_cast<uint8_t>(a) & static_cast<uint8_t>(b)) != 0;
}

class PolicyEnforcer {
public:
    PolicyEnforcer();
    ~PolicyEnforcer();

    void register_peer_ip(const std::string& node_id, const std::string& ip);
    std::string resolve_target(const std::string& target) const;

    // Execute network isolation against a target (called from PBFT consensus at EXECUTED stage).
    // Resolution flow: safe-list check → loopback check → IP resolution → backends in priority order.
    // Returns true ONLY if at least one backend successfully applies the rule.
    bool isolate_target(const std::string& target);

    // Block a raw IP address through the enforcement cascade (no node-ID resolution).
    // Used by MitigationEngine when evidence_json carries a src_ip field.
    // Returns true if at least one backend successfully applied the drop rule.
    bool block_ip_address(const std::string& ip);

    void suspend_process(uint32_t pid);
    void reset_enforcement();
    void release_target(const std::string& target);
    void add_safe_node(const std::string& node_id);

    // IP validation utilities (stateless, safe for external use)
    static bool is_loopback(const std::string& ip);
    static bool is_loopback_ipv6(const std::string& ip);
    static bool is_valid_ipv4(const std::string& ip);
    static bool is_valid_ipv6(const std::string& ip);
    static bool is_valid_ip(const std::string& ip);
    bool is_safe(const std::string& target_id) const;

private:
    // Returns process-wide available backends (probed once, static — immune to instance corruption)
    static EnforcementBackend available_backends();

    // Init-time capability probe + logging
    static void probe_backends();

    // Backend initialization (idempotent, called at probe time)
    static bool ensure_ebpf_map();
    static bool ensure_nftables_table();

    // Enforcement backends — tried in priority order
    static bool apply_ebpf_drop(const std::string& ip);
    static bool apply_nftables_drop(const std::string& ip);
    static bool apply_iptables_drop(const std::string& ip);

    // Removal backends
    static bool remove_ebpf_drop(const std::string& ip);
    static bool remove_nftables_drop(const std::string& ip);
    static bool remove_iptables_drop(const std::string& ip);

    // Fork+exec helpers
    static bool fork_exec_wait(const char* path, const char* const* argv);
    static std::pair<bool, std::string> fork_exec_capture(const char* path, const char* const* argv);

    std::mutex m_mtx;
    std::set<std::string> m_isolated_nodes;
    std::set<std::string> m_safe_list;
    std::set<uint32_t> m_suspended_pids;

    mutable std::shared_mutex m_ip_map_mtx;
    std::unordered_map<std::string, std::string> m_peer_ip_map;
};

} // namespace neuro_mesh
