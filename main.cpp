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
// Heartbeat loop — pushes node vitals to the TelemetryBridge every 2s
// =============================================================================

void heartbeat_loop(TelemetryBridge& bridge, MeshNode& mesh, const std::string& node_id) {
    int seq = 0;
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Build peer_list JSON array
        auto peer_ids = mesh.get_active_peer_ids();
        std::string peer_list_json = "[";
        for (size_t i = 0; i < peer_ids.size(); ++i) {
            if (i > 0) peer_list_json += ",";
            peer_list_json += "\"" + peer_ids[i] + "\"";
        }
        peer_list_json += "]";

        std::string json = "{\"seq\":" + std::to_string(seq)
                         + ",\"node\":\"" + node_id + "\""
                         + ",\"event\":\"heartbeat\""
                         + ",\"peers\":" + std::to_string(mesh.peer_count())
                         + ",\"peer_list\":" + peer_list_json
                         + ",\"cpu\":0.0,\"mem_mb\":0}";

        auto result = bridge.push_telemetry(json);
        if (result.is_err()) {
            std::cerr << "[HEARTBEAT] Bridge push failed: " << result.error() << std::endl;
        }
        ++seq;
    }
}

// =============================================================================
// IPC listener — accepts commands from Python C2 server over Unix domain socket
// =============================================================================

void ipc_listener_loop(const std::string& node_id, SystemJailer& jailer, MeshNode& mesh) {
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

            if (cmd.rfind("CMD:INJECT ", 0) == 0) {
                // Format: CMD:INJECT <target> <evidence_json>
                std::string payload = cmd.substr(strlen("CMD:INJECT "));
                size_t space = payload.find(' ');
                if (space != std::string::npos) {
                    std::string inject_target = payload.substr(0, space);
                    std::string evidence = payload.substr(space + 1);
                    std::cout << "[IPC] INJECT: initiating threat consensus against "
                              << inject_target << std::endl;
                    mesh.initiate_threat_consensus(inject_target, evidence);
                    const char* ack = "ACK:INJECT\n";
                    write(client_fd, ack, strlen(ack));
                }
            } else if (cmd == "CMD:ISOLATE") {
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

    // ---- Stage 3: Consensus engine (dynamic scaling, starts with n=1) ----
    MeshNode mesh(node_id, &jailer, &mitigation);

    // ---- Stage 4: Heartbeat (node vitals broadcast every 2s) ----
    std::thread heartbeat_thread;
    if (bridge.alive()) {
        heartbeat_thread = std::thread(heartbeat_loop, std::ref(bridge), std::ref(mesh), node_id);
        std::cout << "[BOOT] Heartbeat pulse started (2s interval)." << std::endl;
    }

    // ---- Stage 5: P2P listener ----
    mesh.start();

    // ---- Stage 6: IPC listener for C2 commands ----
    std::thread ipc_thread(ipc_listener_loop, node_id, std::ref(jailer), std::ref(mesh));

    std::cout << "[BOOT] System fully operational. Awaiting P2P telemetry..." << std::endl;

    // ---- Main idle loop ----
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // ---- Graceful shutdown (reverse order of init) ----
    std::cout << "[SHUTDOWN] Stopping heartbeat..." << std::endl;
    if (heartbeat_thread.joinable()) heartbeat_thread.join();

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
