#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "jailer/SystemJailer.hpp"
#include "jailer/MitigationEngine.hpp"
#include "consensus/MeshNode.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include "common/UniqueFD.hpp"

using namespace neuro_mesh;

std::atomic<bool> global_running{true};

void signal_handler(int signum) {
    std::cout << "\n[SYS] Interrupt signal (" << signum << ") received. Initiating shutdown..." << std::endl;
    global_running = false;
}

// =============================================================================
// Mock threat generator — injects synthetic telemetry into the bridge every 2s
// =============================================================================

void mock_threat_loop(TelemetryBridge& bridge, const std::string& node_id) {
    int seq = 0;
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Build a realistic JSON telemetry payload.
        // Alternates between entropy spikes, lateral movement alerts,
        // and normal heartbeat entries.
        std::string json;
        switch (seq % 5) {
            case 0:
                json = R"({"seq":)" + std::to_string(seq)
                     + R"(,"node":")" + node_id
                     + R"(","event":"entropy_spike","sensor":"ebpf_entropy")"
                     + R"(,"value":0.97,"threshold":0.85,"verdict":"ANOMALY"})";
                break;
            case 1:
                json = R"({"seq":)" + std::to_string(seq)
                     + R"(,"node":")" + node_id
                     + R"(","event":"lateral_movement","src_ip":"10.99.99.99")"
                     + R"(,"pid":4201,"comm":"sshd","verdict":"THREAT"})";
                break;
            case 2:
                json = R"({"seq":)" + std::to_string(seq)
                     + R"(,"node":")" + node_id
                     + R"(","event":"heartbeat","cpu":0.12,"mem_mb":48)"
                     + R"(,"peers":3,"uptime_s":)" + std::to_string(seq * 2) + "}";
                break;
            case 3:
                json = R"({"seq":)" + std::to_string(seq)
                     + R"(,"node":")" + node_id
                     + R"(","event":"privilege_escalation","uid":0,"comm":"bash")"
                     + R"(,"parent_comm":"nginx","verdict":"CRITICAL"})";
                break;
            case 4:
                json = R"({"seq":)" + std::to_string(seq)
                     + R"(,"node":")" + node_id
                     + R"(","event":"pbft_round_complete")"
                     + R"(,"target":"10.99.99.99","quorum":4,"stage":"EXECUTED"})";
                break;
        }

        auto result = bridge.push_telemetry(json);
        if (result.is_err()) {
            std::cerr << "[MOCK] Bridge push failed: " << result.error() << std::endl;
        }
        ++seq;
    }
    std::cout << "[MOCK] Threat generator halted (" << seq << " payloads sent)." << std::endl;
}

// =============================================================================
// IPC listener — accepts commands from Python C2 server over Unix domain socket
// =============================================================================

void ipc_listener_loop(const std::string& node_id, SystemJailer& jailer) {
    std::string socket_path = "/tmp/neuro_mesh_" + node_id.substr(node_id.find('_') + 1) + ".sock";
    unlink(socket_path.c_str());

    UniqueFD server_fd{socket(AF_UNIX, SOCK_STREAM, 0)};
    if (!server_fd.valid()) {
        std::cerr << "[IPC] Failed to create Unix socket." << std::endl;
        return;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd.get(), (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[IPC] Failed to bind " << socket_path << std::endl;
        return;
    }

    if (listen(server_fd.get(), 1) < 0) {
        std::cerr << "[IPC] Failed to listen on " << socket_path << std::endl;
        return;
    }

    std::cout << "[IPC] Listening for C2 commands on " << socket_path << std::endl;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    while (global_running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd.get(), &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(server_fd.get() + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        int client_fd = accept(server_fd.get(), nullptr, nullptr);
        if (client_fd < 0) continue;

        char buf[256];
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            std::string cmd(buf);
            std::cout << "[IPC] Received command: " << cmd << std::endl;

            if (cmd == "CMD:ISOLATE") {
                std::cout << "[IPC] ISOLATE command acknowledged (requires consensus)." << std::endl;
            } else if (cmd == "CMD:VACCINATE") {
                jailer.eradicate_threats();
                std::cout << "[IPC] Vaccine applied." << std::endl;
            } else if (cmd == "CMD:SHUTDOWN") {
                global_running = false;
            }
        }
        close(client_fd);
    }

    unlink(socket_path.c_str());
}

// =============================================================================
// Entry point
// =============================================================================

int main(int argc, char* argv[]) {
    std::signal(SIGPIPE, SIG_IGN);   // survive broken pipe to dead child
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string node_id = "NODE_1";
    if (argc > 1) {
        node_id = argv[1];
    }

    std::cout << "[BOOT] Neuro-Mesh V9.0 Sovereign Node: " << node_id << std::endl;

    // ---- Stage 1: Defense mechanisms ----
    SystemJailer jailer;
    jailer.add_safe_node(node_id);

    MitigationEngine mitigation(&jailer);

    // ---- Stage 2: Telemetry bridge (privilege-separated child process) ----
    TelemetryBridge bridge({.websocket_port = 9000});
    auto spawn_result = bridge.spawn();
    if (spawn_result.is_err()) {
        std::cerr << "[BOOT] TelemetryBridge spawn failed: "
                  << spawn_result.error() << std::endl;
        std::cerr << "[BOOT] Continuing without bridge — WebSocket telemetry unavailable."
                  << std::endl;
    } else {
        std::cout << "[BOOT] TelemetryBridge child spawned (pid="
                  << bridge.child_pid() << "). WebSocket on :9000."
                  << std::endl;
    }

    // ---- Stage 3: Mock threat generator (synthetic telemetry) ----
    std::thread mock_thread;
    if (bridge.alive()) {
        mock_thread = std::thread(mock_threat_loop, std::ref(bridge), node_id);
        std::cout << "[BOOT] Mock threat generator started (2s interval)." << std::endl;
    }

    // ---- Stage 4: Consensus engine (5-node PBFT, tolerates f=1) ----
    MeshNode mesh(node_id, 5, &jailer, &mitigation);

    // ---- Stage 5: P2P listener ----
    mesh.start();

    // ---- Stage 6: IPC listener for C2 commands ----
    std::thread ipc_thread(ipc_listener_loop, node_id, std::ref(jailer));

    std::cout << "[BOOT] System fully operational. Awaiting P2P telemetry..." << std::endl;

    // ---- Main idle loop ----
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // ---- Graceful shutdown (reverse order of init) ----
    std::cout << "[SHUTDOWN] Stopping mock generator..." << std::endl;
    if (mock_thread.joinable()) mock_thread.join();

    std::cout << "[SHUTDOWN] Halting MeshNode..." << std::endl;
    mesh.stop();

    if (ipc_thread.joinable()) {
        global_running = false;  // belt-and-suspenders for IPC select() wake
        ipc_thread.join();
    }

    std::cout << "[SHUTDOWN] Stopping TelemetryBridge..." << std::endl;
    auto shutdown_result = bridge.shutdown();
    if (shutdown_result.is_err()) {
        std::cerr << "[SHUTDOWN] Bridge shutdown warning: "
                  << shutdown_result.error() << std::endl;
    }

    std::cout << "[SHUTDOWN] System terminated safely." << std::endl;
    return 0;
}
