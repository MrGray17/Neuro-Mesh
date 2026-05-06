#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "jailer/SystemJailer.hpp"
#include "consensus/MeshNode.hpp"
#include "common/UniqueFD.hpp"

using namespace neuro_mesh;

std::atomic<bool> global_running{true};

void signal_handler(int signum) {
    std::cout << "\n[SYS] Interrupt signal (" << signum << ") received. Initiating shutdown..." << std::endl;
    global_running = false;
}

// IPC listener: accepts commands from Python C2 server over Unix domain socket
void ipc_listener_loop(const std::string& node_id, SystemJailer& jailer) {
    std::string socket_path = "/tmp/neuro_mesh_" + node_id.substr(node_id.find('_') + 1) + ".sock";
    unlink(socket_path.c_str()); // Clean up stale socket

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
                // Isolation is triggered via PBFT consensus, not direct IPC
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

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string node_id = "NODE_1";
    if (argc > 1) {
        node_id = argv[1];
    }

    std::cout << "[BOOT] Neuro-Mesh V9.0 Sovereign Node: " << node_id << std::endl;

    // 1. Initialize defense mechanisms
    SystemJailer jailer;
    jailer.add_safe_node(node_id); // Zero-trust: never isolate self

    // 2. Initialize consensus engine (5 nodes, tolerates f=1 malicious)
    MeshNode mesh(node_id, 5, &jailer);

    // 3. Start the P2P listener
    mesh.start();

    // 4. Start IPC listener for C2 commands
    std::thread ipc_thread(ipc_listener_loop, node_id, std::ref(jailer));

    std::cout << "[BOOT] System fully operational. Awaiting P2P telemetry..." << std::endl;

    while (global_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[SHUTDOWN] Halting MeshNode..." << std::endl;
    mesh.stop();
    if (ipc_thread.joinable()) ipc_thread.join();
    std::cout << "[SHUTDOWN] System terminated safely." << std::endl;

    return 0;
}
