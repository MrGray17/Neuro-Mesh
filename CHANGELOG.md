# Changelog

All notable changes to Neuro-Mesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security
- Fix `connect_tls_to_peer` FD return value capture — TLS peer connections now functional
- Fix `std::stoi` crash on malformed beacon input — wrapped in try/catch
- Fix private key storage — encrypted on disk with `chmod 0600`
- Fix integer overflow in `MitigationEngine::extract_int` — saturation arithmetic
- Fix JSON injection in `AuditLogger` — all fields properly escaped
- Fix `AuditLogger::initialize()` call — now invoked in `main.cpp`
- Fix TelemetryBridge uid drop — process exits on failure instead of continuing as root
- Remove unused `set_nonblocking` and `generate_id` functions

### Build System
- Add `-Wpedantic -Wshadow -Werror` to default build flags
- Add `DEBUG=1` build mode (no optimization, full symbols)
- Add `SANITIZE=1` build mode (ASan + UBSan)
- Add `THREAD=1` build mode (ThreadSanitizer)
- Add `COVERAGE=1` build mode (gcov instrumentation)
- Add `make test` target — runs all unit tests
- Add `make install PREFIX=<path>` target
- Add `make lint` target — runs clang-tidy
- Add `make check-deps` — validates toolchain at build start
- Suppress third-party header warnings via `-isystem`
- Parallel build support (`make -j$(nproc)`)

### CI/CD
- Multi-job CI pipeline: build matrix, Docker, static analysis, security audit
- Build matrix: clang/gcc × release/debug/sanitize
- Python linting with ruff
- Shell script linting with shellcheck
- Dockerfile linting with hadolint
- Security audit: banned function detection, semgrep, secret scanning

### Code Quality
- Replace `assert()` with exception-throwing `ASSERT` macro in all test files
- Fix unused variable warnings in test_crypto, test_pbft, test_enforcer, test_meshnode, test_inference
- Add `.clang-format` configuration (Google style)
- Add `.clang-tidy` configuration (bugprone, modernize, performance, readability)
- Add `.pre-commit-config.yaml` with comprehensive hooks

### Documentation
- Add `SECURITY.md` — vulnerability disclosure policy, threat model, known limitations
- Add `CONTRIBUTING.md` — development setup, code style, PR process
- Add `CHANGELOG.md` — this file

## [Previous]

### V9.0 Build System
- Professional build system with eBPF skeleton generation
- Multi-stage Docker build
- GitHub Actions CI pipeline

### V8.0 Cryptographic Foundation
- Ed25519 identity with TOFU key pinning
- X.509 certificate generation
- HSM backend support (SoftHSM, PKCS11)

### V7.0 PBFT Consensus
- Full PBFT state machine (PRE_PREPARE → PREPARE → COMMIT → EXECUTED)
- Signature binding prevents cross-stage replay
- Equivocation detection
- Trust scoring

### V6.0 eBPF Sensors
- Kernel-level tracepoints: exec, sendto, sendmsg, sendmmsg, connect
- Ring buffer telemetry to userspace
- Shannon entropy analysis

### V5.0 Policy Enforcement
- iptables/nftables/eBPF cascade
- Process suspension (SIGSTOP)
- Safe list protection

### V4.0 Telemetry Bridge
- Privilege-separated WebSocket server
- Seccomp-BPF sandbox
- chroot + uid drop

### V3.0 P2P Mesh
- UDP peer discovery
- TCP PEX (Peer Exchange)
- TLS transport with mTLS

### V2.0 Inference Engine
- ONNX Runtime integration
- IsolationForest anomaly detection
- Entropy score decay

### V1.0 Initial Release
- Basic node architecture
- IPC command interface
- Event injection
