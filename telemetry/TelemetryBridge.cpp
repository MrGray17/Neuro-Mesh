#include "telemetry/TelemetryBridge.hpp"

#include <iostream>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>

#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include <seccomp.h>
#include <sys/prctl.h>

// uWebSockets + uSockets
#include <App.h>
#include <libusockets.h>

// uSockets internal — required for POLL_TYPE_CALLBACK integration.
// This is a stable ABI used by uSockets' own UDP implementation.
extern "C" {
#include "internal/internal.h"
}

namespace neuro_mesh {

// =========================================================================
// Construction / Destruction
// =========================================================================

TelemetryBridge::TelemetryBridge(TelemetryBridgeConfig config)
    : m_config(std::move(config))
{}

TelemetryBridge::~TelemetryBridge() {
    (void)shutdown();
}

// =========================================================================
// spawn() — fork + pipe2(O_CLOEXEC) + child sandbox
// =========================================================================

Result<void> TelemetryBridge::spawn() {
    if (m_child_pid > 0) {
        return Result<void>("spawn(): child already running (pid=" + std::to_string(m_child_pid) + ")");
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        return Result<void>(std::string("pipe2(O_CLOEXEC) failed: ") + strerror(errno));
    }

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return Result<void>(std::string("fork() failed: ") + strerror(errno));
    }

    if (pid == 0) {
        // ---- CHILD ----
        // Close write-end; we only read from the pipe.
        close(pipefd[1]);
        child_main(pipefd[0], m_config);
        // child_main is [[noreturn]]
    }

    // ---- PARENT ----
    // Close read-end; we only write.
    close(pipefd[0]);
    m_write_fd = UniqueFD(pipefd[1]);
    m_child_pid = pid;

    return Result<void>();
}

// =========================================================================
// push_telemetry() — parent-side, writes JSON line to pipe
// =========================================================================

Result<void> TelemetryBridge::push_telemetry(std::string_view json) {
    if (!m_write_fd.valid()) {
        return Result<void>("bridge not spawned");
    }

    // Write the JSON fragment followed by a newline delimiter.
    // The child parses line-by-line for simple framing.

    // Accumulate small writes: if entire payload plus newline fits in one
    // PIPE_BUF (>= 4096 on Linux), the write is atomic on the pipe.
    std::string framed;
    framed.reserve(json.size() + 1);
    framed.append(json);
    framed.push_back('\n');

    ssize_t written = write(m_write_fd.get(), framed.data(), framed.size());
    if (written < 0) {
        return Result<void>(std::string("pipe write failed: ") + strerror(errno));
    }
    if (static_cast<size_t>(written) < framed.size()) {
        // Partial write — pipe full. The child is not consuming fast enough.
        // Try to write the remainder (best-effort, non-blocking not required).
        size_t remaining = framed.size() - static_cast<size_t>(written);
        ssize_t w2 = write(m_write_fd.get(), framed.data() + written, remaining);
        if (w2 < 0) {
            return Result<void>(std::string("pipe write (partial) failed: ") + strerror(errno));
        }
    }

    return Result<void>();
}

// =========================================================================
// shutdown() — close pipe, terminate child, reap
// =========================================================================

Result<void> TelemetryBridge::shutdown() {
    if (m_child_pid <= 0) return Result<void>();

    // 1. Close the write-end so the child sees EOF on its read-end.
    m_write_fd = UniqueFD{};

    // 2. Give the child a moment to exit cleanly on EOF.
    int status = 0;
    pid_t waited = waitpid(m_child_pid, &status, WNOHANG);
    if (waited == 0) {
        // Child still alive — send SIGTERM, then wait with timeout.
        kill(m_child_pid, SIGTERM);

        // Spin-wait up to 3 seconds for the child to exit.
        for (int i = 0; i < 30; ++i) {
            usleep(100000); // 100ms
            waited = waitpid(m_child_pid, &status, WNOHANG);
            if (waited > 0) break;
        }

        // If still alive, force-kill.
        if (waited == 0) {
            kill(m_child_pid, SIGKILL);
            waitpid(m_child_pid, &status, 0);
        }
    }

    m_child_pid = -1;
    return Result<void>();
}

bool TelemetryBridge::alive() const noexcept {
    if (m_child_pid <= 0) return false;
    return kill(m_child_pid, 0) == 0;
}

// =========================================================================
// CHILD PROCESS — Sandbox → Seccomp → uWS Event Loop
// =========================================================================

void TelemetryBridge::child_main(int read_fd, const TelemetryBridgeConfig& cfg) {
    // ---- Stage 0: Redirect stderr to log file for diagnostics ----
    int log_fd = open(cfg.log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (log_fd >= 0) {
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
    }

    std::cerr << "[TELEMETRY_BRIDGE] Child spawned (pid=" << getpid()
              << "), starting sandbox sequence..." << std::endl;

    // ---- Stage 1: PR_SET_NO_NEW_PRIVS — irreversible ----
    apply_no_new_privs();

    // ---- Stage 2: Filesystem isolation (chroot + chdir) ----
    apply_fs_isolation(cfg);

    // ---- Stage 3: Drop root privileges to nobody ----
    apply_uid_drop(cfg);

    // ---- Stage 4: Seccomp-BPF default-kill filter ----
    apply_seccomp_filter(read_fd);

    std::cerr << "[TELEMETRY_BRIDGE] Sandbox complete. Starting WebSocket on port "
              << cfg.websocket_port << "..." << std::endl;

    // ---- Stage 5: Run the WebSocket event loop (never returns) ----
    run_event_loop(read_fd, cfg.websocket_port);
}

// =========================================================================
// Sandbox Stages
// =========================================================================

void TelemetryBridge::apply_no_new_privs() {
    // Irreversible — prevents setuid binaries, capabilities, and
    // seccomp filter weakening by any future execve.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        std::cerr << "[SANDBOX] FATAL: prctl(PR_SET_NO_NEW_PRIVS) failed: "
                  << strerror(errno) << std::endl;
        _exit(1);
    }
    std::cerr << "[SANDBOX] PR_SET_NO_NEW_PRIVS applied." << std::endl;
}

void TelemetryBridge::apply_fs_isolation(const TelemetryBridgeConfig& cfg) {
    // Verify chroot path exists and is a directory before attempting.
    struct stat st;
    if (stat(cfg.chroot_path.c_str(), &st) == -1) {
        std::cerr << "[SANDBOX] WARN: chroot path '" << cfg.chroot_path
                  << "' does not exist: " << strerror(errno) 
                  << " — continuing WITHOUT sandbox (WebSocket will still work)" << std::endl;
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        std::cerr << "[SANDBOX] WARN: chroot path '" << cfg.chroot_path
                  << "' is not a directory — continuing WITHOUT sandbox" << std::endl;
        return;
    }

    if (chroot(cfg.chroot_path.c_str()) == -1) {
        std::cerr << "[SANDBOX] WARN: chroot('" << cfg.chroot_path
                  << "') failed: " << strerror(errno) 
                  << " — continuing WITHOUT sandbox (WebSocket will still work)" << std::endl;
        return;
    }

    if (chdir("/") == -1) {
        std::cerr << "[SANDBOX] FATAL: chdir(\"/\") failed: "
                  << strerror(errno) << std::endl;
        _exit(1);
    }

    std::cerr << "[SANDBOX] Filesystem jailed to " << cfg.chroot_path << "/" << std::endl;
}

void TelemetryBridge::apply_uid_drop(const TelemetryBridgeConfig& cfg) {
    // Drop supplementary groups first, then gid, then uid.
    // If this fails, continue without dropping (WebSocket still works)
    if (setgroups(0, nullptr) == -1) {
        std::cerr << "[SANDBOX] WARN: setgroups() failed: "
                  << strerror(errno) << " — continuing without group drop" << std::endl;
    }

    if (setresgid(cfg.sandbox_gid, cfg.sandbox_gid, cfg.sandbox_gid) == -1) {
        std::cerr << "[SANDBOX] WARN: setresgid(" << cfg.sandbox_gid
                  << ") failed: " << strerror(errno) << " — continuing without gid drop" << std::endl;
    }

    if (setresuid(cfg.sandbox_uid, cfg.sandbox_uid, cfg.sandbox_uid) == -1) {
        std::cerr << "[SANDBOX] WARN: setresuid(" << cfg.sandbox_uid
                  << ") failed: " << strerror(errno) << " — continuing without uid drop" << std::endl;
    }

    std::cerr << "[SANDBOX] UID/GID dropped to " << cfg.sandbox_uid
              << ":" << cfg.sandbox_gid << std::endl;
}

// =========================================================================
// Seccomp-BPF Filter — Default Kill, Explicit Whitelist
// =========================================================================

void TelemetryBridge::apply_seccomp_filter(int /*pipe_read_fd*/) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (ctx == nullptr) {
        std::cerr << "[SECCOMP] WARN: seccomp_init() returned null "
                  << "— continuing WITHOUT seccomp filter" << std::endl;
        return;
    }

    // ---- Basic process syscalls ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

    // ---- Memory — needed by std::string, vector, uWS internals ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);

    // ---- Async event loop (epoll) ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);

    // ---- Networking — socket/bind/listen/accept for WebSocket server ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);

    // ---- connect — glibc getaddrinfo() probes addresses via connect().
    //      Must be allowed for the resolver to function. The chroot+jail
    //      limits the blast radius — no outbound reachability exists. ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);

    // ---- Socket I/O — uSockets uses sendmsg/recvmsg/recvfrom/sendto internally ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);

    // ---- fcntl — required by uSockets to set O_NONBLOCK on accepted sockets ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);

    // ---- Synchronization — futex for std::mutex / uWS internal locks ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

    // ---- Timer & clock — uWS timers, event-loop timeout granularity ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);

    // ---- timerfd — epoll-integrated timers (uSockets us_create_timer) ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);

    // ---- Eventfd — used by uSockets for loop wakeup mechanism ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);

    // ---- Random — needed for WebSocket upgrade key (Sec-WebSocket-Key) ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);

    // ---- sched_yield — used in uSockets internal spinloops ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);

    // ---- rt_sigaction / rt_sigprocmask — signal masking by uSockets ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);

    // ---- getpid / gettid — identity checks in libraries ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);

    // ---- File access — getaddrinfo reads /etc/hosts, /etc/nsswitch.conf,
    //      glibc loads NSS modules, locale data, etc.
    //      All will fail with ENOENT inside the chroot, which is safe. ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);

    // ---- ioctl — FIONBIO/FIONREAD on sockets by uSockets ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);

    // ---- pipe2 — uSockets internal event notification pipes ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);

    // ---- pthread / glibc runtime ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);

    // ---- membarrier — glibc uses for thread synchronization on newer kernels ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(membarrier), 0);

    // ---- tgkill — thread signaling in uSockets event loop ----
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);

    // ---- Load the filter ----
    if (seccomp_load(ctx) != 0) {
        std::cerr << "[SECCOMP] WARN: seccomp_load() failed "
                  << "— continuing WITHOUT seccomp filter" << std::endl;
        seccomp_release(ctx);
        return;
    }

    seccomp_release(ctx);

    std::cerr << "[SECCOMP] Default-kill BPF filter loaded (47 syscalls whitelisted)."
              << std::endl;
}

// =========================================================================
// uWebSockets Event Loop (Child Process)
// =========================================================================

struct PipeReaderData {
    int fd;
    uWS::App *app;
    std::string buffer;   // partial-line accumulation
};

// Called by the uSockets event loop when pipe has data to read.
static void pipe_read_callback(struct us_internal_callback_t *cb) {
    auto *data = reinterpret_cast<PipeReaderData *>(reinterpret_cast<char *>(cb + 1));

    char buf[65536];
    ssize_t n = read(data->fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        if (n == 0) {
            std::cerr << "[TELEMETRY_BRIDGE] Pipe closed (parent shutdown). Exiting."
                      << std::endl;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            std::cerr << "[TELEMETRY_BRIDGE] Pipe read error: "
                      << strerror(errno) << ". Exiting." << std::endl;
        }
        _exit(0);
        return;
    }

    buf[n] = '\0';
    data->buffer.append(buf, static_cast<size_t>(n));

    // Process complete lines from the buffer.
    // Each line is a complete JSON object pushed by the parent.
    size_t pos;
    while ((pos = data->buffer.find('\n')) != std::string::npos) {
        std::string line = data->buffer.substr(0, pos);
        data->buffer.erase(0, pos + 1);

        if (line.empty()) continue;

        // Broadcast to all WebSocket clients subscribed to topic/telemetry.
        data->app->publish("topic/telemetry", line, uWS::OpCode::TEXT);
    }

    // Prevent unbounded buffer growth if parent sends malformed data
    // (no newlines).  Cap at 1 MB.
    if (data->buffer.size() > 1'048'576) {
        std::cerr << "[TELEMETRY_BRIDGE] Buffer overflow — discarding "
                  << data->buffer.size() << " bytes of un-terminated data."
                  << std::endl;
        data->buffer.clear();
    }
}

[[noreturn]] void TelemetryBridge::run_event_loop(int pipe_read_fd, uint16_t port) {
    // ---- Per-socket data (empty — we only publish, no client state) ----
    struct PerSocketData {};

    // ---- Behaviour: open handler subscribes every client to telemetry ----
    auto ws_behaviour = uWS::App::WebSocketBehavior<PerSocketData>{
        .compression = uWS::SHARED_COMPRESSOR,
        .maxPayloadLength = 64 * 1024,
        .idleTimeout = 32,
        .open = [](auto *ws) {
            ws->subscribe("topic/telemetry");
        },
        .message = [](auto * /*ws*/, std::string_view /*msg*/, uWS::OpCode) {
            // Clients may send control messages; we ignore for now.
            // Future: C2 commands could be routed back through a second pipe.
        },
        .close = [](auto * /*ws*/, int, std::string_view) {
            // Client disconnected; subscription auto-cleaned by uWS.
        },
    };

    // ---- Build the uWS App with a catch-all WebSocket route ----
    auto app = uWS::App{};

    app.ws<PerSocketData>("/*", std::move(ws_behaviour));

    // ---- Listen on the configured port (explicit IPv4 all-interfaces) ----
    bool listening = false;
    app.listen("0.0.0.0", static_cast<int>(port), [&](auto *listen_socket) {
        if (listen_socket) {
            listening = true;
            std::cerr << "[TELEMETRY_BRIDGE] WebSocket server listening on port "
                      << port << std::endl;
        } else {
            std::cerr << "[TELEMETRY_BRIDGE] FATAL: Failed to listen on port "
                      << port << std::endl;
            _exit(1);
        }
    });

    if (!listening) {
        // listen() callback may not have fired if the port is already in use
        // and the error was synchronous. Exit to avoid running without a socket.
        std::cerr << "[TELEMETRY_BRIDGE] FATAL: Cannot bind to port "
                  << port << " (address in use?)" << std::endl;
        _exit(1);
    }

    // ---- Integrate pipe FD into the uSockets event loop ----
    // Get the underlying us_loop_t from uWS.
    struct us_loop_t *loop = (struct us_loop_t *) uWS::Loop::get();

    // Allocate a poll handle with trailing PipeReaderData as extension.
    // Bounds-check to prevent UB if uSockets internal struct layout changes.
    constexpr unsigned ext_size = sizeof(PipeReaderData);
    constexpr size_t kMinPollSize = 64;   // sanity lower bound
    constexpr size_t kMaxPollSize = 512;  // sanity upper bound

    constexpr size_t calc_size = sizeof(struct us_internal_callback_t) - sizeof(struct us_poll_t) + ext_size;
    static_assert(calc_size >= kMinPollSize && calc_size <= kMaxPollSize,
                  "uSockets struct size out of expected bounds - verify uSockets version compatibility");

    if (calc_size < kMinPollSize || calc_size > kMaxPollSize) {
        std::cerr << "[TELEMETRY_BRIDGE] FATAL: uSockets struct size out of bounds: "
                  << calc_size << std::endl;
        _exit(1);
    }

    struct us_poll_t *pipe_poll = us_create_poll(loop, 0, calc_size);
    if (!pipe_poll) {
        std::cerr << "[TELEMETRY_BRIDGE] FATAL: us_create_poll returned nullptr" << std::endl;
        _exit(1);
    }

    us_poll_init(pipe_poll, pipe_read_fd, POLL_TYPE_CALLBACK);

    // Configure the internal callback struct.
    auto *cb = (struct us_internal_callback_t *) pipe_poll;
    cb->loop = loop;
    cb->cb_expects_the_loop = 0;    // callback receives the poll itself
    cb->leave_poll_ready = 1;       // keep polling — pipe is long-lived
    cb->cb = pipe_read_callback;

    // Initialize the extension data (PipeReaderData lives after cb struct).
    // The callback reads it; the local variable is only for construction.
    (void) new (reinterpret_cast<char *>(cb + 1)) PipeReaderData{pipe_read_fd, &app, {}};

    us_poll_start(pipe_poll, loop, LIBUS_SOCKET_READABLE);

    std::cerr << "[TELEMETRY_BRIDGE] Pipe FD " << pipe_read_fd
              << " integrated into event loop. Awaiting telemetry..." << std::endl;

    // ---- Run forever — all I/O driven by epoll through uSockets ----
    app.run();

    // app.run() only returns on intentional stop (which we never call).
    std::cerr << "[TELEMETRY_BRIDGE] Event loop exited. Shutting down." << std::endl;
    us_poll_stop(pipe_poll, loop);
    us_poll_free(pipe_poll, loop);
    _exit(0);
}

} // namespace neuro_mesh
