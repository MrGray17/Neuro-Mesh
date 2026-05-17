#include "enforcer/PolicyEnforcer.hpp"
#include <iostream>
#include <cstring>
#include <csignal>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

namespace neuro_mesh {

// ---------------------------------------------------------------------------
// Static backend probe — cached once per process, immune to instance corruption
// ---------------------------------------------------------------------------

EnforcementBackend PolicyEnforcer::available_backends() {
    static EnforcementBackend s_backends = []() {
        EnforcementBackend b = EnforcementBackend::NONE;

        if (ensure_ebpf_map())     b = b | EnforcementBackend::EBPF;
        if (ensure_nftables_table()) b = b | EnforcementBackend::NFTABLES;

        const char* ipt_args[] = { "/usr/sbin/iptables", "-V", nullptr };
        if (fork_exec_wait("/usr/sbin/iptables", ipt_args))
            b = b | EnforcementBackend::IPTABLES;

        return b;
    }();

    return s_backends;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

PolicyEnforcer::PolicyEnforcer() {
    probe_backends();
}

PolicyEnforcer::~PolicyEnforcer() = default;

void PolicyEnforcer::probe_backends() {
    EnforcementBackend backends = available_backends();

    std::cout << "[INIT] PolicyEnforcer: Enforcement backends probed. Available: ";
    if (backends == EnforcementBackend::NONE) {
        std::cout << "NONE (insufficient privileges — run as root)";
    } else {
        bool first = true;
        if (backends & EnforcementBackend::EBPF)     { std::cout << "eBPF";     first = false; }
        if (backends & EnforcementBackend::NFTABLES) { std::cout << (first ? "" : ", ") << "nftables"; first = false; }
        if (backends & EnforcementBackend::IPTABLES) { std::cout << (first ? "" : ", ") << "iptables"; }
    }
    std::cout << std::endl;
}

// ---------------------------------------------------------------------------
// IP validation
// ---------------------------------------------------------------------------

bool PolicyEnforcer::is_valid_ipv4(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;

    // Round-trip through inet_ntop to reject non-standard formats
    // that inet_aton would accept: "1.2.3" (→1.2.0.3), "0x7f000001", "2130706433", etc.
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) return false;
    return ip == std::string(buf);
}

bool PolicyEnforcer::is_valid_ipv6(const std::string& ip) {
    struct in6_addr addr;
    return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}

bool PolicyEnforcer::is_valid_ip(const std::string& ip) {
    return is_valid_ipv4(ip) || is_valid_ipv6(ip);
}

bool PolicyEnforcer::is_loopback(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    // Check 127.0.0.0/8 range (all loopback addresses)
    return (ntohl(addr.s_addr) & 0xFF000000) == 0x7F000000;
}

bool PolicyEnforcer::is_loopback_ipv6(const std::string& ip) {
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) return false;
    // Check ::1 (loopback) or ::ffff:127.x.x.x (IPv4-mapped loopback)
    if (IN6_IS_ADDR_LOOPBACK(&addr)) return true;
    if (IN6_IS_ADDR_V4MAPPED(&addr)) {
        // Extract IPv4 from ::ffff:127.x.x.x
        uint8_t* p = addr.s6_addr + 12;
        return (p[0] == 127);
    }
    return false;
}

// ---------------------------------------------------------------------------
// Fork+exec helpers
// ---------------------------------------------------------------------------

bool PolicyEnforcer::fork_exec_wait(const char* path, const char* const* argv) {
    pid_t pid = fork();
    if (pid == -1) return false;

    if (pid == 0) {
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        execv(path, const_cast<char* const*>(argv));
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

std::pair<bool, std::string> PolicyEnforcer::fork_exec_capture(const char* path, const char* const* argv) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return {false, "pipe() failed"};

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]); close(pipefd[1]);
        return {false, "fork() failed"};
    }

    if (pid == 0) {
        close(pipefd[0]);
        close(STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        // Close all inherited FDs >= 3 to prevent FD leak to child
        int max_fd = sysconf(_SC_OPEN_MAX);
        for (int fd = 3; fd < max_fd; ++fd) {
            if (fd != STDERR_FILENO) ::close(fd);
        }
        execv(path, const_cast<char* const*>(argv));
        _exit(1);
    }

    close(pipefd[1]);
    std::string stderr_output;
    char buf[256];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        stderr_output += buf;
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return {WIFEXITED(status) && WEXITSTATUS(status) == 0, stderr_output};
}

// ---------------------------------------------------------------------------
// Backend initialization
// ---------------------------------------------------------------------------

bool PolicyEnforcer::ensure_ebpf_map() {
    const char* map_path = "/sys/fs/bpf/neuro_mesh/neuro_blocklist";

    int fd = bpf_obj_get(map_path);
    if (fd >= 0) { close(fd); return true; }

    const char* mount_args[] = { "/usr/bin/mount", "-t", "bpf", "bpf", "/sys/fs/bpf", nullptr };
    fork_exec_wait("/usr/bin/mount", mount_args);

    int map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, nullptr,
                                sizeof(uint32_t), sizeof(uint8_t),
                                1024, nullptr);
    if (map_fd < 0) return false;

    mkdir("/sys/fs/bpf/neuro_mesh", 0755);
    if (bpf_obj_pin(map_fd, map_path) != 0) {
        close(map_fd);
        return false;
    }

    close(map_fd);
    return true;
}

bool PolicyEnforcer::ensure_nftables_table() {
    if (access("/usr/sbin/nft", X_OK) != 0) return false;

    const char* add_table[] = { "/usr/sbin/nft", "add", "table", "ip", "neuro_mesh", nullptr };
    fork_exec_wait("/usr/sbin/nft", add_table);

    const char* add_chain[] = {
        "/usr/sbin/nft", "add", "chain", "ip", "neuro_mesh", "INPUT",
        "{", "type", "filter", "hook", "input", "priority", "0", ";", "}", nullptr
    };
    return fork_exec_wait("/usr/sbin/nft", add_chain);
}

// ---------------------------------------------------------------------------
// Safe list
// ---------------------------------------------------------------------------

bool PolicyEnforcer::is_safe(const std::string& target_id) const {
    return m_safe_list.find(target_id) != m_safe_list.end();
}

void PolicyEnforcer::add_safe_node(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(m_mtx);
    m_safe_list.insert(node_id);
    std::cout << "[ENFORCER] Safe-listed node: " << node_id << std::endl;
}

// ---------------------------------------------------------------------------
// Peer IP mapping (thread-safe)
// ---------------------------------------------------------------------------

void PolicyEnforcer::register_peer_ip(const std::string& node_id, const std::string& ip) {
    if (node_id.empty() || !is_valid_ip(ip)) return;
    std::lock_guard<std::shared_mutex> lock(m_ip_map_mtx);
    m_peer_ip_map.insert_or_assign(node_id, ip);
}

std::string PolicyEnforcer::resolve_target(const std::string& target) const {
    if (is_valid_ip(target)) return target;

    std::shared_lock<std::shared_mutex> lock(m_ip_map_mtx);
    auto it = m_peer_ip_map.find(target);
    if (it != m_peer_ip_map.end()) return it->second;

    return {};
}

// ---------------------------------------------------------------------------
// Enforcement backends
// ---------------------------------------------------------------------------

bool PolicyEnforcer::apply_ebpf_drop(const std::string& ip) {
    if (!is_valid_ipv4(ip)) return false;

    const char* map_path = "/sys/fs/bpf/neuro_mesh/neuro_blocklist";
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) return false;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) { close(map_fd); return false; }
    uint32_t key = addr.s_addr;
    uint8_t value = 1;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    close(map_fd);
    return ret == 0;
}

bool PolicyEnforcer::remove_ebpf_drop(const std::string& ip) {
    if (!is_valid_ipv4(ip)) return false;
    const char* map_path = "/sys/fs/bpf/neuro_mesh/neuro_blocklist";
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) return false;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) { close(map_fd); return false; }
    uint32_t key = addr.s_addr;
    int ret = bpf_map_delete_elem(map_fd, &key);
    close(map_fd);
    return ret == 0;
}

bool PolicyEnforcer::apply_nftables_drop(const std::string& ip) {
    const char* args[] = {
        "/usr/sbin/nft",
        "add", "rule",
        "ip", "neuro_mesh", "INPUT",
        "ip", "saddr", ip.c_str(),
        "counter", "drop",
        nullptr
    };
    return fork_exec_wait("/usr/sbin/nft", args);
}

bool PolicyEnforcer::remove_nftables_drop(const std::string& ip) {
    const char* args[] = {
        "/usr/sbin/nft",
        "delete", "rule",
        "ip", "neuro_mesh", "INPUT",
        "ip", "saddr", ip.c_str(),
        "counter", "drop",
        nullptr
    };
    return fork_exec_wait("/usr/sbin/nft", args);
}

bool PolicyEnforcer::apply_iptables_drop(const std::string& ip) {
    const char* args[] = {
        "/usr/sbin/iptables",
        "-A", "INPUT",
        "-s", ip.c_str(),
        "-j", "DROP",
        nullptr
    };
    return fork_exec_wait("/usr/sbin/iptables", args);
}

bool PolicyEnforcer::remove_iptables_drop(const std::string& ip) {
    const char* args[] = {
        "/usr/sbin/iptables",
        "-D", "INPUT",
        "-s", ip.c_str(),
        "-j", "DROP",
        nullptr
    };
    return fork_exec_wait("/usr/sbin/iptables", args);
}

// ---------------------------------------------------------------------------
// Raw IP blocking (no node-ID resolution) — used by MitigationEngine
// ---------------------------------------------------------------------------

// D3FEND: D3-NTF (Network Traffic Filtering) — cascade through eBPF → nftables → iptables drop rules
bool PolicyEnforcer::block_ip_address(const std::string& ip) {
    if (!is_valid_ip(ip)) {
        std::cerr << "[ENFORCER] Invalid IP address: " << ip << std::endl;
        return false;
    }

    if (is_loopback(ip) || is_loopback_ipv6(ip)) {
        std::cerr << "[ENFORCER] REFUSED: " << ip
                  << " is loopback — will not block localhost." << std::endl;
        return false;
    }

    std::cout << "[ENFORCER] Applying network block for IP " << ip << "..." << std::endl;

    EnforcementBackend backends = available_backends();

    if ((backends & EnforcementBackend::EBPF) && apply_ebpf_drop(ip)) {
        std::cout << "[ENFORCER] IP " << ip
                  << " blocked via eBPF blocklist map." << std::endl;
        return true;
    }

    if ((backends & EnforcementBackend::NFTABLES) && apply_nftables_drop(ip)) {
        std::cout << "[ENFORCER] IP " << ip
                  << " blocked via nftables drop rule." << std::endl;
        return true;
    }

    if ((backends & EnforcementBackend::IPTABLES) && apply_iptables_drop(ip)) {
        std::cout << "[ENFORCER] IP " << ip
                  << " blocked via iptables drop rule." << std::endl;
        return true;
    }

    std::cerr << "[ENFORCER] CRITICAL: All enforcement backends failed for IP "
              << ip << ". Traffic NOT blocked." << std::endl;
    return false;
}

// ---------------------------------------------------------------------------
// Core isolation pipeline
// ---------------------------------------------------------------------------

bool PolicyEnforcer::isolate_target(const std::string& target) {
    std::lock_guard<std::mutex> lock(m_mtx);

    if (m_isolated_nodes.find(target) != m_isolated_nodes.end()) {
        return true;  // Already isolated
    }

    if (is_safe(target)) {
        std::cout << "[ENFORCER] REFUSED: " << target
                  << " is safe-listed. Isolation blocked." << std::endl;
        return false;
    }

    std::string resolved_ip = resolve_target(target);
    if (resolved_ip.empty()) {
        std::cerr << "[ENFORCER] Cannot resolve target '" << target
                  << "': not a valid IP and no peer mapping registered." << std::endl;
        return false;
    }

    if (is_loopback(resolved_ip)) {
        std::cerr << "[ENFORCER] REFUSED: " << resolved_ip
                  << " is a loopback address — will not isolate localhost." << std::endl;
        return false;
    }

    if (is_loopback_ipv6(resolved_ip)) {
        std::cerr << "[ENFORCER] REFUSED: " << resolved_ip
                  << " is an IPv6 loopback address — will not isolate localhost." << std::endl;
        return false;
    }

    std::cout << "[ENFORCER] Consensus reached. Resolved " << target
              << " → " << resolved_ip << ". Executing isolation..." << std::endl;

    EnforcementBackend backends = available_backends();
    bool any_success = false;

    if ((backends & EnforcementBackend::EBPF) && apply_ebpf_drop(resolved_ip)) {
        std::cout << "[ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from "
                  << resolved_ip << " [eBPF]" << std::endl;
        m_isolated_nodes.insert(target);
        any_success = true;
    }

    if (!any_success && (backends & EnforcementBackend::NFTABLES) && apply_nftables_drop(resolved_ip)) {
        std::cout << "[ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from "
                  << resolved_ip << " [nftables]" << std::endl;
        m_isolated_nodes.insert(target);
        any_success = true;
    }

    if (!any_success && (backends & EnforcementBackend::IPTABLES) && apply_iptables_drop(resolved_ip)) {
        std::cout << "[ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from "
                  << resolved_ip << " [iptables]" << std::endl;
        m_isolated_nodes.insert(target);
        any_success = true;
    }

    if (!any_success) {
        std::string diag;
        diag += (backends & EnforcementBackend::EBPF)     ? "eBPF: attempted,failed" : "eBPF: unavailable";
        diag += (backends & EnforcementBackend::NFTABLES) ? " | nftables: attempted,failed" : " | nftables: unavailable";
        diag += (backends & EnforcementBackend::IPTABLES) ? " | iptables: attempted,failed" : " | iptables: unavailable";

        std::cerr << "[ENFORCER] CRITICAL: All enforcement methods failed for "
                  << resolved_ip << ". Target NOT isolated. (" << diag << ")" << std::endl;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

void PolicyEnforcer::release_target(const std::string& target) {
    std::lock_guard<std::mutex> lock(m_mtx);

    if (m_isolated_nodes.erase(target) == 0) return;

    std::string resolved_ip = resolve_target(target);
    if (resolved_ip.empty()) return;

    remove_ebpf_drop(resolved_ip);
    remove_nftables_drop(resolved_ip);
    remove_iptables_drop(resolved_ip);

    std::cout << "[ENFORCER] Target released from isolation: " << target
              << " (" << resolved_ip << ")" << std::endl;
}

// ---------------------------------------------------------------------------
// Process Suspension
// ---------------------------------------------------------------------------

// D3FEND: D3-PT (Process Termination) — SIGSTOP halts compromised process for forensic triage
void PolicyEnforcer::suspend_process(uint32_t pid) {
    std::lock_guard<std::mutex> lock(m_mtx);
    if (m_suspended_pids.find(pid) != m_suspended_pids.end()) return;

    m_suspended_pids.insert(pid);
    std::cout << "[ENFORCER] Process " << pid << " suspended." << std::endl;

    if (kill(static_cast<pid_t>(pid), SIGSTOP) == 0) {
        std::cout << "[ENFORCER] SIGSTOP delivered to PID " << pid << std::endl;
    } else {
        std::cerr << "[ENFORCER] Failed to deliver SIGSTOP to PID " << pid << std::endl;
    }
}

void PolicyEnforcer::reset_enforcement() {
    std::lock_guard<std::mutex> lock(m_mtx);
    std::cout << "[ENFORCER] Eradicating " << m_suspended_pids.size() << " jailed processes." << std::endl;
    for (auto pid : m_suspended_pids) {
        kill(static_cast<pid_t>(pid), SIGCONT);
        kill(static_cast<pid_t>(pid), SIGTERM);
    }
    m_suspended_pids.clear();
}

} // namespace neuro_mesh
