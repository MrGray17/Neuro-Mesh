#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <unordered_map>
#include <chrono>
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

    void set_node_id(const std::string& node_id);
    void register_peer_ip(const std::string& node_id, const std::string& ip);
    void register_peer_port(const std::string& node_id, uint16_t port);
    std::string resolve_target(const std::string& target) const;
    uint16_t resolve_port(const std::string& target) const;

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
    static bool is_valid_ip(const std::string& ip);
    static bool is_valid_ipv4(const std::string& ip);
    static bool is_valid_ipv6(const std::string& ip);
    static bool is_loopback(const std::string& ip);
    static bool is_loopback_ipv6(const std::string& ip);
    bool is_safe(const std::string& target_id) const;
    // Caller MUST hold m_mtx. Used internally by isolate_target() to avoid
    // recursive lock acquisition on a non-recursive shared_mutex.
    bool is_safe_locked(const std::string& target_id) const;
    bool is_ip_safe(const std::string& ip);

    // Fork+exec helpers (public so unit tests can verify the output cap and
    // error handling on adversarial inputs — see tools/test_enforcer.cpp).
    // Use these in preference to direct fork()/execv() so all child processes
    // get the same FD-leak protection and output cap.
    static bool fork_exec_wait(const char* path, const char* const* argv);
    static std::pair<bool, std::string> fork_exec_capture(const char* path, const char* const* argv);

private:
    // Returns process-wide available backends (probed once, static — immune to instance corruption)
    static EnforcementBackend available_backends();

    // Init-time capability probe + logging
    static void probe_backends();

    // Backend initialization (idempotent, called at probe time)
    static bool ensure_ebpf_map();
    static bool ensure_nftables_table();

    // Enforcement backends — tried in priority order
    bool apply_ebpf_drop(const std::string& ip);
    bool remove_ebpf_drop(const std::string& ip);

    // nftables backend
    static bool apply_nftables_drop(const std::string& ip);
    static bool apply_nftables_port_drop(const std::string& ip, uint16_t port);
    static bool apply_nftables_loopback_drop(const std::string& ip);
    static bool remove_nftables_drop(const std::string& ip);
    static bool remove_nftables_loopback_drop(const std::string& ip);
    static bool remove_nftables_port_drop(const std::string& ip, uint16_t port);

    // iptables backend
    static bool apply_iptables_drop(const std::string& ip);
    static bool remove_iptables_drop(const std::string& ip);

    // nftables handle-based deletion helpers (v1.0.9 requires handles)
    static std::string list_nftables_rules();
    static std::vector<int> find_nft_handles(const std::string& list_output,
                                              const std::string& match_substr);
    static bool delete_nft_handle(int handle);
    static bool remove_nftables_rules_matching(const std::string& match_substr);

    mutable std::shared_mutex m_mtx;
    std::string m_node_id;
    std::set<std::string> m_isolated_nodes;
    std::set<std::string> m_safe_list;
    std::set<uint32_t> m_suspended_pids;
    std::unordered_map<uint32_t, int> m_suspended_pidfds; // pidfd for PID-reuse-safe signaling

    mutable std::shared_mutex m_ip_map_mtx;
    std::unordered_map<std::string, std::string> m_peer_ip_map;
    std::unordered_map<std::string, uint16_t> m_peer_port_map;

    std::chrono::steady_clock::time_point m_last_enforce_time;
    static constexpr int ENFORCE_COOLDOWN_SEC = 5;
};

} // namespace neuro_mesh
