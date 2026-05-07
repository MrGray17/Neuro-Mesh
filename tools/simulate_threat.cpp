#include "consensus/MeshNode.hpp"
#include "jailer/SystemJailer.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

using namespace neuro_mesh;

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --target <node_id> [--event <type>] [--verdict <severity>]\n"
              << "  --target   Target node ID (required, e.g. ALPHA, 10.99.99.99)\n"
              << "  --event    Event type: lateral_movement | privilege_escalation | entropy_spike (default: lateral_movement)\n"
              << "  --verdict  Severity: THREAT | CRITICAL | ANOMALY (default: THREAT)\n"
              << "\nExample:\n"
              << "  " << prog << " --target ALPHA --event lateral_movement --verdict CRITICAL\n";
}

int main(int argc, char* argv[]) {
    std::string target;
    std::string event_type = "lateral_movement";
    std::string verdict = "THREAT";

    // Parse --key value pairs
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) {
            target = argv[++i];
        } else if (arg == "--event" && i + 1 < argc) {
            event_type = argv[++i];
        } else if (arg == "--verdict" && i + 1 < argc) {
            verdict = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] == '-' && arg[1] == '-') {
            std::cerr << "Unknown flag: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (target.empty()) {
        std::cerr << "Error: --target is required.\n";
        print_usage(argv[0]);
        return 1;
    }

    // Build the evidence JSON from parsed flags
    std::string evidence;
    if (event_type == "lateral_movement") {
        evidence = R"({"event":"lateral_movement","src_ip":")" + target
                 + R"(","pid":4201,"comm":"sshd","verdict":")" + verdict + R"("})";
    } else if (event_type == "privilege_escalation") {
        evidence = R"({"event":"privilege_escalation","uid":0,"comm":"bash")"
                   R"(,"parent_comm":"nginx","verdict":")" + verdict + R"("})";
    } else {
        evidence = R"({"sensor":"ebpf_entropy","value":0.98,"threshold":0.85,"verdict":")"
                 + verdict + R"("})";
    }

    SystemJailer jailer;

    std::string sim_id = "NODE_SIMULATOR";
    MeshNode node(sim_id, &jailer, nullptr);
    node.start();

    std::cout << "[SIMULATOR] Booting " << sim_id << ". Waiting for mesh discovery (5s)..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(5));

    std::cout << "[SIMULATOR] Injecting threat consensus:" << std::endl;
    std::cout << "  Target  : " << target << std::endl;
    std::cout << "  Event   : " << event_type << std::endl;
    std::cout << "  Verdict : " << verdict << std::endl;
    std::cout << "  Evidence: " << evidence << std::endl;

    node.initiate_threat_consensus(target, evidence);

    // Wait for consensus propagation and enforcement
    std::this_thread::sleep_for(std::chrono::seconds(10));

    node.stop();
    std::cout << "[SIMULATOR] Done." << std::endl;
    return 0;
}
