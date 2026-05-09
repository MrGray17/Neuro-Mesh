# Neuro-Mesh

**Distributed Adaptive Security Mesh** — C++20 nodes with kernel-level eBPF intrusion detection, Ed25519-signed PBFT Byzantine fault-tolerant consensus over UDP, and multi-backend network isolation enforcement.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://hub.docker.com/)

---

## Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
  - [Native Build](#native-build)
  - [Docker Compose](#docker-compose)
- [How It Works](#how-it-works)
  - [PBFT Consensus](#pbft-consensus)
  - [Enforcement Backends](#enforcement-backends)
  - [State Persistence](#state-persistence)
- [Project Structure](#project-structure)
- [Threat Simulation](#threat-simulation)
- [Benchmarking](#benchmarking)
- [IPC Protocol](#ipc-protocol)
- [Security Properties](#security-properties)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Neuro-Mesh Console                             │
│    Canvas force graph · entropy spectrogram · SVG arc gauges     │
│             live event feed · WebSocket telemetry                  │
└───────────────────────────┬──────────────────────────────────────┘
                            │ WebSocket :9000
┌───────────────────────────▼──────────────────────────────────────┐
│                  PYTHON CONTROL PLANE                              │
│   control_server.py (WS :9002)  ·  ws_proxy.py (:9001→:9002)     │
│   anomaly_classifier.py       ·  web_server.py (static)          │
└───────────────────────────┬──────────────────────────────────────┘
                            │ UDP telemetry :9998 + IPC sockets
┌───────────────────────────▼──────────────────────────────────────┐
│                       C++20 Mesh Nodes                              │
│                                                                    │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐     │
│  │   NodeAgent   │──▶│InferenceEngine│──▶│    MeshNode       │     │
│  │  (eBPF poll)  │   │  (entropy)    │   │ (PBFT consensus)  │     │
│  └──────────────┘   └───────────────┘   └────────┬───────────┘     │
│                                                   │                │
│                    ┌──────────────────────────────┘                │
│                    ▼                                               │
│  ┌─────────────────────────────────────────────┐                  │
│  │            MitigationEngine                  │                  │
│  │  process termination · network enforcement   │                  │
│  └─────────────────────┬───────────────────────┘                  │
│                        │                                           │
│         eBPF  │  nftables  │  iptables                             │
└────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
eBPF kernel probe (kernel/sensor.bpf.c)
  → NodeAgent drains ring buffer, queues events
    → InferenceEngine: entropy-based anomaly scoring
      → MeshNode: UDP broadcast PBFT (PRE_PREPARE → PREPARE → COMMIT → EXECUTED)
        → MitigationEngine: process termination + iptables isolation
          → StateJournal: append-only JSON persistence
            → TelemetryBridge: WebSocket push to dashboard
```

---

## Quick Start

### Prerequisites

| Dependency | Purpose |
|------------|---------|
| clang / llvm 18+ | C++20 compilation, eBPF backend |
| libbpf, libelf, zlib | eBPF program loading |
| libssl (OpenSSL 3.x) | Ed25519 key operations |
| libseccomp | TelemetryBridge syscall sandboxing |
| bpftool | eBPF skeleton header generation |
| nftables / iptables | Network isolation enforcement |
| Python 3.12+ | Control plane services |
| Node.js 18+ | Dashboard (optional) |

### Native Build

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get install clang llvm make libbpf-dev libelf-dev libssl-dev \
                     libseccomp-dev linux-headers-generic bpftool git zlib1g-dev

# Build everything
make clean && make
```

Produces:

| Binary | Purpose |
|--------|---------|
| `bin/neuro_agent` | Mesh node — eBPF sensor + PBFT consensus + enforcement |
| `bin/inject_event` | Event injector — triggers PBFT consensus for testing |
| `bin/test_crypto` | Ed25519 unit tests |

### Run a Node

```bash
./bin/neuro_agent NODE_1
```

### Launch a Multi-Node Mesh

```bash
# 5-node tmux grid
./mesh_dashboard.sh

# Python-managed mesh
python3 orchestration/mesh_manager.py

# Full demo (control plane + 3 agents + console dashboard)
./start_demo.sh
```

### Docker Compose

```bash
# Build and launch 5-node mesh (ALPHA, BRAVO, CHARLIE, DELTA, ECHO) + control plane + dashboard
docker compose up -d

# Verify mesh formed (should show 5 nodes)
docker compose ps
docker logs neuro_alpha

# Open dashboard
open http://localhost:8080

# Inject a single-node compromise (10s demo telemetry)
docker exec neuro_charlie /app/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL

# Run full-mesh traffic flood (triggers eBPF entropy on all nodes)
docker exec neuro_charlie python3 /app/traffic_generator.py --target 127.0.0.1 --duration 15 --threads 8

# Tear down
docker compose down
```

Each C++ node container runs with `privileged: true` and `network_mode: host` for eBPF/XDP map access and UDP broadcast discovery.

---

## How It Works

### PBFT Consensus

Each node runs a Practical Byzantine Fault Tolerance state machine over UDP broadcast (`255.255.255.255:9999`). The protocol has four stages:

| Stage | Trigger | Action |
|-------|---------|--------|
| `PRE_PREPARE` | Anomaly detected | Initiator proposes consensus target + evidence |
| `PREPARE` | PRE_PREPARE received | Nodes acknowledge and broadcast their vote |
| `COMMIT` | Quorum PREPARE votes | Nodes confirm readiness to execute |
| `EXECUTED` | Quorum COMMIT votes | MitigationEngine enforces isolation |

**Quorum formula:** `(2n + 2) / 3` — equivalent to `2f + 1` with `f = ⌊(n-1)/3⌋`.

Every message carries an Ed25519 signature binding `(stage | target | evidence)`, preventing cross-stage replay attacks. Self-votes are verified through the same cryptographic path as external votes — zero-trust by construction.

### Enforcement Backends

PolicyEnforcer probes backends at startup and selects the best available:

| Priority | Backend | Mechanism |
|----------|---------|-----------|
| 1 (fastest) | eBPF | `BPF_MAP_TYPE_HASH` blocklist at `/sys/fs/bpf/neuro_mesh/` |
| 2 | nftables | Dedicated `ip neuro_mesh INPUT` table with filter hook |
| 3 (fallback) | iptables | `iptables -A INPUT -s <ip> -j DROP` via `fork()`+`execv()` |

MitigationEngine extends enforcement with process termination (seccomp-whitelisted 46 syscalls) and IPTABLES network isolation, executed in detached threads to avoid blocking the P2P listener.

### State Persistence

`StateJournal` (header-only, `common/StateJournal.hpp`) provides append-only JSON journaling:

```json
{"seq":1,"ts":1715123456789,"stage":"COMMIT","target":"ALPHA","evidence":{...},"hash":"a1b2c3d4"}
{"seq":2,"ts":1715123456810,"stage":"EXECUTED","target":"ALPHA","evidence":{...},"hash":"a1b2c3d4"}
```

- **Thread-safe:** `std::mutex` for writes, `std::atomic<uint64_t>` for sequence numbers
- **Crash recovery:** Constructor replays existing journal, recovering the last sequence number
- **Per-node isolation:** Each node writes to `journal_{ID}.log`
- **Write pattern:** `open(O_APPEND) → write → fsync → close` — no long-lived file descriptors

---

## Project Structure

| Directory | Purpose | Key Files |
|-----------|---------|-----------|
| `kernel/` | eBPF probes | `sensor.bpf.c` (ring buffer), `neuro_bpf.c` (XDP filter), `sensor.skel.h` (generated) |
| `cell/` | Node intelligence | `NodeAgent.hpp/.cpp`, `InferenceEngine.hpp/.cpp` |
| `consensus/` | P2P mesh + PBFT | `MeshNode.hpp/.cpp` (UDP mesh), `PBFT.hpp` (header-only BFT) |
| `crypto/` | Ed25519 identity | `CryptoCore.hpp/.cpp` (OpenSSL EVP keygen/sign/verify) |
| `enforcer/` | Policy enforcement | `PolicyEnforcer.hpp/.cpp`, `MitigationEngine.hpp/.cpp` |
| `telemetry/` | Structured logging | `AuditLogger.hpp/.cpp` (UDP JSON), `TelemetryBridge.hpp/.cpp` (uWebSockets) |
| `common/` | Shared utilities | `StateJournal.hpp`, `UniqueFD.hpp`, `Result.hpp`, `Base64.hpp` |
| `orchestration/` | Python control plane | `control_server.py`, `anomaly_classifier.py`, `bridge_api.py`, `mesh_manager.py` |
| `tools/` | Test & benchmark | `inject_event.cpp`, `test_crypto.cpp`, `traffic_generator.py`, `benchmark_mesh.py` |
| `dashboard/` | Console dashboard | Zero-dependency HTML/CSS/JS with Canvas + WebSocket |
| `web/` | Static assets | `mesh_status.json` (POSIX-locked multi-writer sink) |

---

## Event Injection & Traffic Generation

### Single-node injection (IPC)

```bash
# Make a single node report CRITICAL telemetry for 10 seconds
./bin/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL

# Or via docker exec
docker exec neuro_charlie /app/inject_event --node CHARLIE --target ALPHA --event lateral_movement --verdict THREAT
```

| Flag | Description |
|------|-------------|
| `--node` | Local daemon to command via IPC (required) |
| `--target` | Target node ID for PBFT consensus (required) |
| `--event` | `lateral_movement` \| `privilege_escalation` \| `entropy_spike` (default: `lateral_movement`) |
| `--verdict` | `THREAT` \| `CRITICAL` \| `ANOMALY` (default: `THREAT`) |
| `--tag` | Unique identifier for benchmark iteration |

The injector sends `CMD:INJECT` over the node's Unix domain socket (`/tmp/neuro_mesh_{id}.sock`). The receiving node overrides its telemetry (CPU 85%, entropy 0.98) for 10 seconds and initiates a PBFT consensus round against the target.

### Full-mesh traffic flood

```bash
# Multi-threaded UDP flood + TCP port scan — triggers eBPF entropy on all nodes
python3 tools/traffic_generator.py --target 127.0.0.1 --duration 15 --threads 8

# Inside a container
docker exec neuro_charlie python3 /app/traffic_generator.py --target 127.0.0.1 --duration 15 --threads 8
```

| Flag | Description |
|------|-------------|
| `--target` | Target IP address (required) |
| `--duration` | Attack duration in seconds (default: 15) |
| `--threads` | Worker threads — higher = more entropy (default: 3) |
| `--udp-ratio` | Fraction of threads doing UDP flood (default: 0.6) |

Uses `network_mode: host` — all nodes share `/proc/net/dev`, so a flood to `127.0.0.1` triggers entropy on the entire mesh. Use `inject_event` for single-node targeting.

---

## Benchmarking

```bash
python3 tools/benchmark_mesh.py --runs 3 --output markdown
```

Zero-dependency Python script using only stdlib. Measures:

| Metric | Description | Source |
|--------|-------------|--------|
| **A: Latency** | Injection → EXECUTED journal entry (ms) | Journal polling at 100ms intervals |
| **B: Resources** | CPU ticks (utime+stime) and RSS memory delta | `/proc/1/stat` via `docker exec` |

Output formats: `markdown` (tables) or `json` (structured).

---

## IPC Protocol

Control plane commands are delivered over Unix domain sockets at `/tmp/neuro_mesh_{id}.sock`:

| Command | Action |
|---------|--------|
| `CMD:INJECT` | Injects synthetic CRITICAL telemetry for 10s + initiates PBFT consensus against target |
| `CMD:ISOLATE` | Initiates PBFT consensus against target + injects synthetic telemetry for 10s |
| `CMD:RESET` | Resets enforcement state for all suspended processes and removes blocklist entries |
| `CMD:SHUTDOWN` | Graceful node shutdown |

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Zero shell injection** | `fork()`+`execv()` with `argv` entries, no `system()` or `popen()` |
| **Binary-safe cryptography** | `std::string::data()`/`size()` — no null-byte truncation |
| **Cross-stage replay prevention** | Signatures bind `(stage + target + evidence)` together |
| **Self-isolation prevention** | `add_safe_node()` prevents nodes isolating themselves |
| **Loopback protection** | Refuses to isolate `127.0.0.0/8` addresses |
| **Bounded memory** | PBFT rounds evicted after 120s inactivity; eBPF ring buffer drained in tight loop |
| **Atomic telemetry** | `flock()`-protected multi-writer JSON sink |
| **RAII resource management** | `UniqueFD` wraps all raw socket descriptors |
| **seccomp sandbox** | TelemetryBridge child process restricted to 46 syscalls |
| **Crash recovery** | StateJournal replays existing journal on boot, recovers sequence counter |

---

## MITRE D3FEND Counter-Measures

Neuro-Mesh implements the following D3FEND defensive techniques:

| D3FEND ID | Technique | Implementation | Location |
|-----------|-----------|----------------|----------|
| **D3-PT** | Process Termination | SIGSTOP/SIGKILL delivery to anomalous processes via `PolicyEnforcer::suspend_process()` and `MitigationEngine::terminate_process()` | `enforcer/PolicyEnforcer.cpp:423`, `enforcer/MitigationEngine.cpp:124` |
| **D3-NTF** | Network Traffic Filtering | Multi-backend IP blocklist cascade: eBPF `BPF_MAP_TYPE_HASH` → nftables chain → iptables DROP rules | `enforcer/PolicyEnforcer.cpp:296`, `kernel/sensor.bpf.c:29` |
| **D3-IPI** | Identity Protection & Integrity | Ed25519 signatures bind every PBFT message to `(stage + target + evidence)` — prevents cross-stage replay and peer spoofing | `crypto/CryptoCore.hpp:19`, `consensus/MeshNode.cpp:668` |
| **D3-SEA** | System Event Analysis | eBPF tracepoints on `sys_enter_execve`, `sys_enter_sendto`, `sys_enter_connect` feed ring buffer → ONNX Isolation Forest entropy scoring | `kernel/sensor.bpf.c:56`, `cell/InferenceEngine.hpp` |
| **D3-PM** | Process Monitoring | `NodeAgent::telemetry_loop()` drains eBPF ring buffer continuously, queues events for ML inference, and streams telemetry via UDP to control plane | `cell/NodeAgent.cpp:44` |
| **D3-IRA** | Incident Response Automation | PBFT consensus reaches EXECUTED stage → `MitigationEngine::execute_response()` dispatches process termination and network isolation in detached threads | `enforcer/MitigationEngine.cpp:184`, `consensus/MeshNode.cpp:641` |

---

## NIST Cybersecurity Framework (CSF) Mapping

Neuro-Mesh coverage across the NIST CSF 5-function model:

| CSF Function | Neuro-Mesh Capability | Evidence |
|--------------|----------------------|----------|
| **IDENTIFY** (ID) | Peer discovery via UDP broadcast; `register_peer_ip()` maps node IDs to IPs; `StateJournal` replays crash history on boot; `/proc/net/dev` byte-rate baselining | `consensus/MeshNode.cpp`, `enforcer/PolicyEnforcer.cpp:197`, `common/StateJournal.hpp` |
| **PROTECT** (PR) | Ed25519-signed PBFT messages prevent vote spoofing; `add_safe_node()` prevents self-isolation; `PolicyEnforcer::validate_pid()` refuses to kill PID 1 or self; seccomp sandbox restricts TelemetryBridge to 46 syscalls; `fork()`+`execv()` eliminates shell injection | `crypto/CryptoCore.hpp`, `enforcer/PolicyEnforcer.cpp:187`, `enforcer/MitigationEngine.cpp:86`, `telemetry/TelemetryBridge.cpp` |
| **DETECT** (DE) | 3 eBPF tracepoints (execve, sendto, connect) capture kernel events; ONNX Isolation Forest scores payload entropy; `/proc/net/dev` byte-rate deltas detect traffic floods; `network_entropy_score()` provides fallback detection; rule-based classifier flags CPU>85% or RAM>14GB | `kernel/sensor.bpf.c`, `cell/InferenceEngine.hpp`, `main.cpp:30`, `orchestration/anomaly_classifier.py` |
| **RESPOND** (RS) | PBFT BFT consensus (PRE_PREPARE→PREPARE→COMMIT→EXECUTED) coordinates multi-node verdicts; `MitigationEngine::execute_response()` dispatches process termination and IP blocking; `PolicyEnforcer::isolate_target()` enforces network isolation through 3-backend cascade; IPC socket accepts CMD:ISOLATE for external trigger | `consensus/PBFT.hpp`, `enforcer/MitigationEngine.cpp:184`, `enforcer/PolicyEnforcer.cpp:339`, `main.cpp:163` |
| **RECOVER** (RC) | `CMD:RESET` releases all suspended processes and removes blocklist entries; `PolicyEnforcer::release_target()` removes eBPF/nftables/iptables rules; `StateJournal` append-only log provides full audit trail for post-incident forensics; `AuditLogger` streams structured JSON telemetry for external SIEM ingestion | `enforcer/PolicyEnforcer.cpp:402`, `enforcer/PolicyEnforcer.cpp:436`, `common/StateJournal.hpp`, `telemetry/AuditLogger.hpp` |

---

## License

MIT — see [LICENSE](LICENSE) for details.
