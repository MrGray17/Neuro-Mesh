# ADR-0005: TelemetryBridge Sandbox Architecture

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Neuro-Mesh architecture team  

## Context

The TelemetryBridge runs a uWebSockets server that broadcasts telemetry to dashboard clients via WebSocket. The WebSocket server process must never have access to the parent process's memory, filesystem, network stack, or privilege escalation vectors.

## Decision

Use a privilege-separated architecture with a fork+exec sandbox:

1. **Parent (root)**: Retains write-end of an `O_CLOEXEC` pipe. Pushes JSON telemetry lines via `write()`. Never touches network I/O.
2. **Child (sandbox)**: Runs under:
   - `chroot("/var/empty")` — filesystem isolation
   - `setuid(nobody)` / `setgid(nogroup)` — privilege drop
   - `prctl(PR_SET_NO_NEW_PRIVS, 1)` — prevent privilege re-escalation
   - `seccomp-bpf(56 whitelisted syscalls)` — syscall filtering
3. **Communication**: Unidirectional pipe (parent → child), atomic writes at `PIPE_BUF` (4096 bytes).
4. **NEURO_UNSAFE_NO_SANDBOX=1**: Bypasses all sandbox stages for development.

## Alternatives Considered

- **In-process WebSocket server**: uWebSockets runs in the main agent thread. Rejected — a WebSocket exploit gives attacker full agent privileges.
- **Standalone daemon**: Separate systemd service. Rejected — lifecycle coupling with agent process is needed (agent starts → bridge starts; agent stops → bridge stops).
- **TCP socket IPC instead of pipe**: Bidirectional but adds attack surface (exposed port). Rejected — unidirectional pipe is simpler and safer.

## Consequences

- **Positive**: WebSocket compromise is contained — attacker gets a `nobody` process in an empty chroot with 56 syscalls.
- **Positive**: Sandbox degrades gracefully — `NEURO_UNSAFE_NO_SANDBOX=1` for development.
- **Negative**: Seccomp profile must be updated when uWebSockets dependencies change; new syscalls break the sandbox.
- **Negative**: Pipe can fill up (EAGAIN) if child crashes; message is dropped but parent continues.
