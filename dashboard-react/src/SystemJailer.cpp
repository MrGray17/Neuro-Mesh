#include "SystemJailer.hpp"
#include <iostream>
#include <cstdlib>

namespace neuro_mesh {

SystemJailer::SystemJailer() {
    std::cout << "[INIT] SystemJailer module loaded. Ready to enforce Layer 3 Deep Packet Inspection." << std::endl;
}

SystemJailer::~SystemJailer() = default;

void SystemJailer::isolate_target(const std::string& target_id) {
    std::lock_guard<std::mutex> lock(m_mtx);
    
    if (m_isolated_nodes.find(target_id) != m_isolated_nodes.end()) {
        return; 
    }

    std::cout << "[DEFENSE] SystemJailer activated. Neutralizing target: " << target_id << std::endl;
    
    // ARCHITECTURAL FIX: OS-Level Deep Packet Inspection
    // We command the Linux kernel to inspect incoming UDP traffic on port 9999.
    // If a packet contains the exact Sovereign Identity (e.g., "|NODE_5|"), it is destroyed before reaching user-space.
    std::string cmd = "sudo iptables -A INPUT -p udp --dport 9999 -m string --algo bm --string \"|" + target_id + "|\" -j DROP";
    int result = std::system(cmd.c_str());

    if (result == 0) {
        m_isolated_nodes.insert(target_id);
        std::cout << "[DEFENSE] Target " << target_id << " successfully isolated at the OS level." << std::endl;
    } else {
        std::cerr << "[FATAL] Kernel execution failed. Target remains active." << std::endl;
    }
}

} // namespace neuro_mesh
