#include "PolicyEnforcer.hpp"
#include <iostream>
#include <cstdlib>

namespace neuro_mesh {

PolicyEnforcer::PolicyEnforcer() {
    std::cout << "[INIT] PolicyEnforcer module loaded. Ready to enforce Layer 3 packet inspection." << std::endl;
}

PolicyEnforcer::~PolicyEnforcer() = default;

void PolicyEnforcer::isolate_target(const std::string& target_id) {
    std::lock_guard<std::mutex> lock(m_mtx);

    if (m_isolated_nodes.find(target_id) != m_isolated_nodes.end()) {
        return;
    }

    std::cout << "[ENFORCER] PolicyEnforcer activated. Isolating target: " << target_id << std::endl;

    // OS-Level Deep Packet Inspection via iptables string matching.
    // Packets containing the target node ID are dropped before reaching user-space.
    std::string cmd = "sudo iptables -A INPUT -p udp --dport 9999 -m string --algo bm --string \"|" + target_id + "|\" -j DROP";
    int result = std::system(cmd.c_str());

    if (result == 0) {
        m_isolated_nodes.insert(target_id);
        std::cout << "[ENFORCER] Target " << target_id << " successfully isolated at the OS level." << std::endl;
    } else {
        std::cerr << "[ERROR] Kernel execution failed. Target remains active." << std::endl;
    }
}

} // namespace neuro_mesh
