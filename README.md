# Neuro-Mesh

**Distributed Zero-Trust Security Mesh** — sovereign C++20 nodes with kernel-level eBPF intrusion detection, Ed25519-signed PBFT Byzantine fault-tolerant consensus over UDP, and multi-backend network isolation enforcement.

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
│                     FUI SOVEREIGN DASHBOARD                       │
│    Canvas force graph · entropy spectrogram · SVG arc gauges     │
│             live kill feed · WebSocket telemetry                  │
└───────────────────────────┬──────────────────────────────────────┘
                            │ WebSocket :9000
┌───────────────────────────▼──────────────────────────────────────┐
│                  PYTHON CONTROL PLANE                              │
│   c2_server.py (WebSocket hub)  ·  bridge_api.py (REST)           │
│   brain_ai.py (anomaly classifier)  ·  web_server.py (static)     │
└───────────────────────────┬──────────────────────────────────────┘
                            │ IPC (Unix domain sockets)
┌───────────────────────────▼──────────────────────────────────────┐
│                    C++20 SOVEREIGN NODES                           │
│                                                                    │
│  ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐     │
│  │ SovereignCell │──▶│InferenceEngine│──▶│    MeshNode       │     │
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
  → SovereignCell drains ring buffer, queues events
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
| `bin/neuro_agent` | Sovereign node — eBPF sensor + PBFT consensus + enforcement |
| `bin/simulate_threat` | Threat injector — triggers PBFT consensus for testing |
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

# Full demo (C2 + 3 agents + FUI dashboard)
./start_demo.sh
```

### Docker Compose

```bash
# Build and launch 3-node mesh (ALPHA, BRAVO, CHARLIE)
docker-compose up -d

# Verify
docker-compose ps
docker logs neuro_alpha

# Inject a threat
docker run --rm --network=host \
  --entrypoint /app/simulate_threat neuro_mesh:titan \
  --target ALPHA --event lateral_movement --verdict THREAT

# Run benchmark suite
python3 tools/benchmark_mesh.py --runs 3

# Tear down
docker-compose down
```

Each container runs with `privileged: true` and `network_mode: host` for eBPF/XDP map access and UDP broadcast discovery.

---

## How It Works

### PBFT Consensus

Each node runs a Practical Byzantine Fault Tolerance state machine over UDP broadcast (`255.255.255.255:9999`). The protocol has four stages:

| Stage | Trigger | Action |
|-------|---------|--------|
| `PRE_PREPARE` | Anomaly detected | Initiator proposes threat target + evidence |
| `PREPARE` | PRE_PREPARE received | Nodes acknowledge and broadcast their vote |
| `COMMIT` | Quorum PREPARE votes | Nodes confirm readiness to execute |
| `EXECUTED` | Quorum COMMIT votes | MitigationEngine enforces isolation |

**Quorum formula:** `(2n + 2) / 3` — equivalent to `2f + 1` with `f = ⌊(n-1)/3⌋`.

Every message carries an Ed25519 signature binding `(stage | target | evidence)`, preventing cross-stage replay attacks. Self-votes are verified through the same cryptographic path as external votes — zero-trust by construction.

### Enforcement Backends

SystemJailer probes backends at startup and selects the best available:

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
| `cell/` | Sovereign intelligence | `SovereignCell.hpp/.cpp`, `InferenceEngine.hpp/.cpp` |
| `consensus/` | P2P mesh + PBFT | `MeshNode.hpp/.cpp` (UDP mesh), `PBFT.hpp` (header-only BFT) |
| `crypto/` | Ed25519 identity | `CryptoCore.hpp/.cpp` (OpenSSL EVP keygen/sign/verify) |
| `jailer/` | Enforcement | `SystemJailer.hpp/.cpp`, `MitigationEngine.hpp/.cpp` |
| `telemetry/` | Structured logging | `AuditLogger.hpp/.cpp` (UDP JSON), `TelemetryBridge.hpp/.cpp` (uWebSockets) |
| `common/` | Shared utilities | `StateJournal.hpp`, `UniqueFD.hpp`, `Result.hpp`, `Base64.hpp` |
| `orchestration/` | Python control plane | `c2_server.py`, `brain_ai.py`, `bridge_api.py`, `mesh_manager.py` |
| `tools/` | Test & benchmark | `simulate_threat.cpp`, `test_crypto.cpp`, `benchmark_mesh.py` |
| `dashboard-fui/` | FUI SOC dashboard | Zero-dependency HTML/CSS/JS with Canvas + WebSocket |
| `web/` | Static assets | `mesh_status.json` (POSIX-locked multi-writer sink) |

---

## Threat Simulation

```bash
# Basic injection
./bin/simulate_threat --target ALPHA --event lateral_movement --verdict THREAT

# With unique tag (prevents PBFT round collision in benchmarks)
./bin/simulate_threat --target ALPHA --event privilege_escalation --verdict CRITICAL --tag run1

# Available flags
--target    Target node ID (required)
--event     lateral_movement | privilege_escalation | entropy_spike
--verdict   THREAT | CRITICAL | ANOMALY
--tag       Unique identifier for benchmark iteration
```

The simulator runs as a temporary peer (`NODE_SIMULATOR`), generates an ephemeral Ed25519 identity, participates in mesh discovery, and injects a PBFT consensus round before exiting.

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

C2 commands are delivered over Unix domain sockets at `/tmp/neuro_mesh_{id}.sock`:

| Command | Action |
|---------|--------|
| `CMD:ISOLATE` | Acknowledged (isolation requires PBFT consensus) |
| `CMD:VACCINATE` | Eradicates all jailed processes |
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

## License

MIT — see [LICENSE](LICENSE) for details.
