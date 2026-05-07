#include "consensus/MeshNode.hpp"
#include "jailer/SystemJailer.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace neuro_mesh;

int main(int argc, char* argv[]) {
    // Usage: simulate_threat <target_ip_or_id> [evidence_json]
    //   target_ip_or_id  — IP address (e.g. 10.99.99.99) or logical node ID (e.g. NODE_3)
    //   evidence_json    — optional threat evidence (default: eBPF entropy anomaly)
    std::string target = (argc > 1) ? argv[1] : "10.99.99.99";
    std::string evidence = (argc > 2) ? argv[2]
        : R"({"sensor":"ebpf_entropy","value":0.98,"threshold":0.85})";

    SystemJailer jailer;

    std::string sim_id = "NODE_SIMULATOR";
    MeshNode node(sim_id, 5, &jailer, nullptr);
    node.start();

    std::cout << "[TEST] Booting " << sim_id << ". Waiting for mesh discovery (5s)..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::cout << "[TEST] Simulating CRITICAL eBPF Anomaly for target: " << target << std::endl;
    std::cout << "[TEST] Evidence: " << evidence << std::endl;

    // Inject the threat consensus — SystemJailer will resolve target to IP at EXECUTED
    node.initiate_threat_consensus(target, evidence);

    // Wait for consensus to propagate and enforcement to execute
    std::this_thread::sleep_for(std::chrono::seconds(10));

    node.stop();
    return 0;
}
