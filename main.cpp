#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>
#include <memory>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "enforcer/PolicyEnforcer.hpp"
#include "enforcer/MitigationEngine.hpp"
#include "consensus/MeshNode.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include "cell/InferenceEngine.hpp"
#include "cell/NodeAgent.hpp"
#include "common/UniqueFD.hpp"

using namespace neuro_mesh;

std::atomic<bool> global_running{true};

// Demo simulation mode: when set, heartbeat injects simulated telemetry for 10s.
// Set by IPC INJECT, consumed by heartbeat_loop.
std::atomic<int64_t> g_demo_until_us{0};

// Read container memory from cgroups (v2 or v1), falling back to sysinfo.
// sysinfo() reports host total RAM inside containers — cgroups give the true footprint.
static long cgroup_memory_mb() {
    // cgroup v2
    FILE* f = std::fopen("/sys/fs/cgroup/memory.current", "r");
    if (f) {
        long bytes = 0;
        if (std::fscanf(f, "%ld", &bytes) == 1) {
            std::fclose(f);
            return bytes / (1024 * 1024);
        }
        std::fclose(f);
    }
    // cgroup v1
    f = std::fopen("/sys/fs/cgroup/memory/memory.usage_in_bytes", "r");
    if (f) {
        long bytes = 0;
        if (std::fscanf(f, "%ld", &bytes) == 1) {
            std::fclose(f);
            return bytes / (1024 * 1024);
        }
        std::fclose(f);
    }
    // Fallback: host /proc/meminfo via sysinfo
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        return (info.totalram - info.freeram) / (1024 * 1024);
    }
    return 0;
}

// Read /proc/net/dev and compute a network activity score (0.0–1.0)
// based on the byte-rate delta between calls. Spikes during traffic floods.
static float network_entropy_score() {
    static uint64_t s_prev_bytes = 0;
    static auto    s_prev_time  = std::chrono::steady_clock::now();

    FILE* f = std::fopen("/proc/net/dev", "r");
    if (!f) return 0.0f;

    uint64_t total = 0;
    char line[256];
    // Skip the two header lines
    std::fgets(line, sizeof(line), f);
    std::fgets(line, sizeof(line), f);

    while (std::fgets(line, sizeof(line), f)) {
        char* colon = std::strchr(line, ':');
        if (!colon) continue;

        // Parse: bytes packets errs drop ... | bytes packets errs drop ...
        uint64_t rx_bytes = 0, tx_bytes = 0;
        int fields = std::sscanf(colon + 1,
            "%lu %*u %*u %*u %*u %*u %*u %*u %lu",
            &rx_bytes, &tx_bytes);
        if (fields >= 1) total += rx_bytes;
        if (fields >= 2) total += tx_bytes;
    }
    std::fclose(f);

    auto now = std::chrono::steady_clock::now();
    float dt = std::chrono::duration<float>(now - s_prev_time).count();
    if (dt < 0.5f) return 0.0f;  // first call or too soon

    float byte_rate = static_cast<float>(total - s_prev_bytes) / dt;
    s_prev_bytes = total;
    s_prev_time  = now;

    // Normalize: 5 MB/s → 0.5, 50 MB/s → 1.0 (logarithmic-ish clamping)
    constexpr float kMaxRate = 50.0f * 1024 * 1024;  // 50 MB/s = score 1.0
    return std::min(1.0f, byte_rate / kMaxRate);
}

// Convert raw ONNX IsolationForest decision score to a 0.0–1.0 entropy value.
// Score range: approx -0.2 (anomalous) to +0.2 (normal), threshold at -0.05.
static float onnx_to_entropy(float score) {
    constexpr float kThreshold = -0.05f;
    constexpr float kMinScore = -0.2f;
    if (score >= kThreshold) return 0.0f;
    float t = (kThreshold - score) / (kThreshold - kMinScore);
    return std::min(1.0f, t);
}

void signal_handler(int signum) {
    std::cout << "\n[SYS] Interrupt signal (" << signum << ") received. Initiating shutdown..." << std::endl;
    global_running = false;
}

// =============================================================================
// Heartbeat loop — pushes node vitals to the TelemetryBridge every 2s
// =============================================================================

void heartbeat_loop(TelemetryBridge& bridge, MeshNode& mesh,
                    ai::InferenceEngine& inference, core::NodeAgent* ebpf,
                    const std::string& node_id) {
    int seq = 0;
    pid_t my_pid = getpid();  // filter eBPF events from our own traffic
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

        // Real CPU load (1-min average, normalized to 0.0–1.0 by core count)
        double loads[1] = {0.0};
        double cpu = 0.0;
        if (getloadavg(loads, 1) != -1) {
            long nproc = sysconf(_SC_NPROCESSORS_ONLN);
            if (nproc > 0)
                cpu = loads[0] / static_cast<double>(nproc);
            else
                cpu = loads[0];
        }

        // Real RAM usage in MB (cgroup-aware for containers)
        long mem_mb = cgroup_memory_mb();

        // ---- eBPF sensor: drain ring buffer, run ONNX inference on kernel events ----
        if (ebpf && ebpf->is_operational()) {
            auto events = ebpf->poll_events();
            if (events.empty()) {
                // No new kernel events — decay the anomaly score toward normal.
                // Prevents sticky CRITICAL state after anomalous traffic ceases.
                inference.decay(0.3f);
            } else {
                for (const auto& ev : events) {
                    // Skip events from our own PID (telemetry, P2P discovery)
                    if (static_cast<pid_t>(ev.pid) == my_pid) continue;
                    inference.analyze(std::string(ev.comm), std::string(ev.payload));
                }
            }
        }

        float onnx_score   = inference.last_score();
        float onnx_entropy = onnx_to_entropy(onnx_score);
        float net_score    = network_entropy_score();
        float entropy = std::max(onnx_entropy, net_score);

        // Threat determined by blended entropy, not sticky ONNX score alone.
        // ONNX anomalies feed into entropy via onnx_to_entropy().
        const char* threat;
        if (entropy > 0.65f)      threat = "CRITICAL";
        else if (entropy > 0.6f)  threat = "ALERT";
        else                      threat = "NONE";

        // Decentralized enforcement: self-initiate PBFT consensus on sustained anomaly.
        // 30s cooldown prevents spamming rounds every heartbeat.
        if (entropy > 0.65f && mesh.peer_count() > 1) {
            static int64_t s_last_consensus_us = 0;
            static bool s_first = true;
            auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            // 30-second grace period on first call (prevents startup self-isolation)
            if (s_first) { s_last_consensus_us = now_us; s_first = false; }
            if (now_us - s_last_consensus_us > 30'000'000) {
                s_last_consensus_us = now_us;
                std::string evidence = "{\"entropy\":" + std::to_string(entropy)
                                     + ",\"node\":\"" + node_id + "\""
                                     + ",\"source\":\"self_detected\"}";
                std::cout << "[DECENTRALIZED] Self-initiating PBFT consensus (entropy="
                          << entropy << ")" << std::endl;
                mesh.initiate_consensus(node_id, evidence);
            }
        }

        // Demo simulation mode: override vitals for 10s after an IPC alert
        if (g_demo_until_us.load(std::memory_order_relaxed) > 0) {
            auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (now_us < g_demo_until_us.load(std::memory_order_relaxed)) {
                cpu = 85.5;
                entropy = 0.98f;
                threat = "CRITICAL";
                static int demo_seq = 0;
                if (demo_seq++ % 5 == 0) {
                    std::cout << "[DEMO] Injecting demo telemetry (cpu=" << cpu
                              << ", entropy=" << entropy << ", threat=" << threat << ")" << std::endl;
                }
            } else {
                g_demo_until_us.store(0, std::memory_order_relaxed);
            }
        }

        // Map current threat posture to MITRE ATT&CK technique IDs
        std::string mitre_tags;
        if (strcmp(threat, "CRITICAL") == 0 || strcmp(threat, "ALERT") == 0) {
            // High-entropy lateral movement or C2-like traffic detected
            mitre_tags = "\"mitre_attack\":[\"T1021\",\"T1571\",\"T1059\"]";
        } else if (entropy > 0.6f) {
            mitre_tags = "\"mitre_attack\":[\"T1571\"]";
        } else {
            mitre_tags = "\"mitre_attack\":[]";
        }

        std::string json = "{\"seq\":" + std::to_string(seq)
                         + ",\"node\":\"" + node_id + "\""
                         + ",\"event\":\"heartbeat\""
                         + ",\"peers\":" + std::to_string(mesh.peer_count())
                         + ",\"peer_list\":" + peer_list_json
                         + ",\"cpu\":" + std::to_string(cpu)
                         + ",\"mem_mb\":" + std::to_string(mem_mb)
                         + ",\"entropy\":" + std::to_string(entropy)
                         + ",\"threat\":\"" + threat + "\""
                         + "," + mitre_tags + "}";

        // Gossip telemetry to all peers — each node aggregates the full mesh view.
        // The dashboard can connect to ANY node and see the entire network.
        mesh.gossip_telemetry(json);

        ++seq;
    }
}

// =============================================================================
// IPC listener — accepts commands from Python C2 server over Unix domain socket
// =============================================================================

void ipc_listener_loop(const std::string& node_id, PolicyEnforcer& jailer, MeshNode& mesh, TelemetryBridge& bridge) {
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

    std::cout << "[IPC] Listening for commands on " << socket_path << std::endl;

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
                    std::cout << "[IPC] INJECT: initiating consensus against "
                              << inject_target << std::endl;
                    mesh.initiate_consensus(inject_target, evidence);

                    // Broadcast synthetic telemetry for the target so the
                    // dashboard marks it red regardless of which node's
                    // bridge it's connected to.
                    std::string fake_tel =
                        "{\"event\":\"heartbeat\","
                        "\"node\":\"" + inject_target + "\","
                        "\"threat\":\"CRITICAL\","
                        "\"status\":\"FLAGGED\","
                        "\"entropy\":0.98,"
                        "\"cpu\":85.5,"
                        "\"mem_mb\":512,"
                        "\"peers\":" + std::to_string(mesh.peer_count()) + ","
                        "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\"]}";
                    bridge.push_telemetry(fake_tel);
                    // Gossip to all peers so every node's bridge sees it
                    mesh.gossip_event_json(fake_tel);

                    const char* ack = "ACK:INJECT\n";
                    write(client_fd, ack, strlen(ack));
                }
            } else if (cmd.rfind("CMD:ISOLATE ", 0) == 0) {
                // Format: CMD:ISOLATE <target> <evidence_json>
                std::string payload = cmd.substr(strlen("CMD:ISOLATE "));
                size_t space = payload.find(' ');
                if (space != std::string::npos) {
                    std::string isolate_target = payload.substr(0, space);
                    std::string evidence = payload.substr(space + 1);
                    std::cout << "[IPC] ISOLATE: initiating PBFT consensus against "
                              << isolate_target << std::endl;
                    mesh.initiate_consensus(isolate_target, evidence);

                    // Broadcast synthetic telemetry for the target
                    std::string fake_tel =
                        "{\"event\":\"heartbeat\","
                        "\"node\":\"" + isolate_target + "\","
                        "\"threat\":\"CRITICAL\","
                        "\"status\":\"FLAGGED\","
                        "\"entropy\":0.98,"
                        "\"cpu\":85.5,"
                        "\"mem_mb\":512,"
                        "\"peers\":" + std::to_string(mesh.peer_count()) + ","
                        "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\"]}";
                    bridge.push_telemetry(fake_tel);
                    mesh.gossip_event_json(fake_tel);

                    const char* ack = "ACK:ISOLATE\n";
                    write(client_fd, ack, strlen(ack));
                }
            } else if (cmd == "CMD:RESET") {
                jailer.reset_enforcement();
                std::cout << "[IPC] Enforcement reset." << std::endl;
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

    std::cout << "[BOOT] Neuro-Mesh V9.0 Node: " << node_id << std::endl;

    // ---- Stage 1: Defense mechanisms ----
    PolicyEnforcer jailer;
    jailer.add_safe_node(node_id);

    MitigationEngine mitigation(&jailer);

    // ---- Stage 2: Telemetry bridge (privilege-separated child process) ----
    // Each node gets a unique WebSocket port to avoid host-network conflicts.
    // wsbridge uses port 9001, so nodes use 9000 + offset to stay clear.
    int ws_port = 9000;
    if (node_id == "BRAVO")      ws_port = 9010;
    else if (node_id == "CHARLIE") ws_port = 9020;
    else if (node_id == "DELTA")  ws_port = 9030;
    else if (node_id == "ECHO")   ws_port = 9040;
    TelemetryBridge bridge({.websocket_port = static_cast<uint16_t>(ws_port)});
    auto spawn_result = bridge.spawn();
    if (spawn_result.is_err()) {
        std::cerr << "[BOOT] TelemetryBridge spawn failed: "
                  << spawn_result.error() << std::endl;
        std::cerr << "[BOOT] Continuing without bridge — WebSocket telemetry unavailable."
                  << std::endl;
    } else {
        std::cout << "[BOOT] TelemetryBridge child spawned (pid="
                  << bridge.child_pid() << "). WebSocket on :" << ws_port << "."
                  << std::endl;
    }

    // ---- Stage 3: Consensus engine (dynamic scaling, starts with n=1) ----
    MeshNode mesh(node_id, &jailer, &mitigation, &bridge);

    // ---- Stage 4: ML inference engine (ONNX Isolation Forest) ----
    std::unique_ptr<ai::InferenceEngine> inference;
    try {
        inference = std::make_unique<ai::InferenceEngine>("/app/isolation_forest.onnx", -0.05f);
        std::cout << "[BOOT] ONNX InferenceEngine: "
                  << (inference->is_operational() ? "OPERATIONAL" : "DEGRADED")
                  << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[BOOT] InferenceEngine failed to load: " << e.what() << std::endl;
        std::cerr << "[BOOT] Continuing without ML inference — using fallback." << std::endl;
    }

    // ---- Stage 4.5: eBPF sensor (kernel tracepoints → ONNX inference) ----
    std::unique_ptr<core::NodeAgent> ebpf;
    auto ebpf_result = core::NodeAgent::create(node_id);
    if (ebpf_result.error.empty()) {
        ebpf = std::move(ebpf_result.agent);
        std::cout << "[BOOT] eBPF sensor: OPERATIONAL (execve/sendto/connect probes)" << std::endl;
    } else {
        std::cerr << "[BOOT] eBPF sensor failed: " << ebpf_result.error
                  << " — continuing with /proc/net/dev entropy only." << std::endl;
    }

    // ---- Stage 5: Heartbeat (node vitals broadcast every 2s) ----
    std::thread heartbeat_thread;
    if (bridge.alive() && inference) {
        heartbeat_thread = std::thread(heartbeat_loop, std::ref(bridge), std::ref(mesh),
                                       std::ref(*inference), ebpf.get(), node_id);
        std::cout << "[BOOT] Heartbeat pulse started (2s interval)." << std::endl;
    }

    // ---- Stage 6: P2P listener ----
    mesh.start();

    // ---- Stage 7: IPC listener for C2 commands ----
    std::thread ipc_thread(ipc_listener_loop, node_id, std::ref(jailer), std::ref(mesh), std::ref(bridge));

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
