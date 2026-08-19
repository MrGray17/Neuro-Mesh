# Runtime hardening status

This document records the invariants that the hardened runtime is expected to preserve. It is intentionally narrower than the project roadmap: these are merge-blocking properties of the currently shipped security path.

## Trust-boundary invariants

- Discovery uses a cross-host wall-clock timestamp and accepts only the signed V3 packet format that binds the node ID, transport ports, TLS fingerprint, and TLS certificate material.
- Telemetry gossip is accepted only from registered peers with a valid signature. Legacy unsigned telemetry fails closed.
- TLS clients and servers both present certificates. Inbound and outbound peer identity is bound to the verified certificate common name and the expected peer identity, rather than an ephemeral TCP source port.
- TelemetryBridge sandbox setup fails closed if seccomp cannot be installed, and the bridge/proxy bind to loopback by default.
- Security sensing, anomaly evaluation, consensus initiation, and mitigation do not depend on the optional browser telemetry bridge being alive.
- The privileged agent does not link the red-team AttackSimulator implementation.

## Consensus/liveness invariants

- View-change timeout checks real non-terminal consensus rounds instead of relying only on a synthetic lookup key.
- Advancing the view refreshes active-round view/timing state so one monitor pass cannot repeatedly advance the same stalled state.
- Dynamic membership is still research-grade and is not claimed to implement formally verified BFT reconfiguration.

## Verification gate

Before this hardening branch is merged, the current head must pass the full GitHub Actions matrix: GCC/Clang builds, unit tests, sanitizer tests, Docker five-node integration with actual PBFT execution evidence, fuzzing, static analysis, security scanning, Python lint/formatting, ShellCheck, and Hadolint.

Passing CI demonstrates the tested repository configurations only; it is not a claim of formal verification or production readiness on arbitrary multi-host deployments.
