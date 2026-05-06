#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <unistd.h>
#include "common/UniqueFD.hpp"
#include "common/Result.hpp"

namespace neuro_mesh {

struct TelemetryBridgeConfig {
    uint16_t websocket_port = 9000;
    std::string chroot_path = "/var/empty";
    uid_t sandbox_uid = 65534;   // nobody
    gid_t sandbox_gid = 65534;   // nogroup
    std::string log_path = "/tmp/telemetry_bridge.log";
};

// Air-gapped telemetry bridge with privilege-separated architecture.
//
// Parent (root)     — retains write-end of O_CLOEXEC pipe, pushes JSON.
// Child  (sandbox)  — reads JSON from pipe, broadcasts via uWebSockets
//                     to topic/telemetry subscribers under full sandbox:
//                     chroot, nobody uid/gid, no-new-privs, seccomp-bpf.
//
// Usage from SystemJailer or main thread:
//   TelemetryBridge bridge({.websocket_port = 9000});
//   bridge.spawn();
//   bridge.push_telemetry(R"({"event":"anomaly","score":0.97})");
class TelemetryBridge {
public:
    explicit TelemetryBridge(TelemetryBridgeConfig config);
    ~TelemetryBridge();

    TelemetryBridge(const TelemetryBridge&) = delete;
    TelemetryBridge& operator=(const TelemetryBridge&) = delete;
    TelemetryBridge(TelemetryBridge&&) = delete;
    TelemetryBridge& operator=(TelemetryBridge&&) = delete;

    // Fork child, apply sandbox, start WebSocket server in child.
    // Returns Ok once parent-side pipe is set up and child is running.
    [[nodiscard]] Result<void> spawn();

    // Push a single JSON line into the bridge.
    // Data flows: parent -> pipe -> child -> WebSocket broadcast.
    // Thread-safe. Returns Err if write fails (child crashed).
    [[nodiscard]] Result<void> push_telemetry(std::string_view json);

    // Terminate child process, reap it, close the pipe.
    [[nodiscard]] Result<void> shutdown();

    [[nodiscard]] pid_t child_pid() const noexcept { return m_child_pid; }
    [[nodiscard]] bool alive() const noexcept;

private:
    TelemetryBridgeConfig m_config;
    UniqueFD             m_write_fd;
    pid_t                m_child_pid = -1;

    // ---- child-side (runs in forked process, never returns) ----
    [[noreturn]] static void child_main(int read_fd, const TelemetryBridgeConfig& cfg);

    // Sandbox stages — each must succeed before proceeding
    static void apply_no_new_privs();
    static void apply_fs_isolation(const TelemetryBridgeConfig& cfg);
    static void apply_uid_drop(const TelemetryBridgeConfig& cfg);
    static void apply_seccomp_filter(int pipe_read_fd);

    // WebSocket event loop in sandboxed child
    [[noreturn]] static void run_event_loop(int pipe_read_fd, uint16_t port);
};

} // namespace neuro_mesh
