# Neuro-Mesh

A distributed P2P security mesh where sovereign C++ nodes use kernel-level eBPF sensors to detect anomalies, run an Ed25519-signed PBFT consensus protocol over UDP broadcast, and execute zero-trust network isolation against compromised peers through a multi-backend enforcement cascade.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      REACT SOC DASHBOARD                        │
│   KPI cards · topology graph · agent table · event timeline     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ WebSocket / HTTP
┌──────────────────────────▼──────────────────────────────────────┐
│                 PYTHON CONTROL PLANE                             │
│  c2_server.py (WebSocket hub)  ·  bridge_api.py (REST)          │
│  brain_ai.py (anomaly classifier)  ·  web_server.py (static)    │
└──────────────────────────┬──────────────────────────────────────┘
                           │ IPC (Unix domain sockets)
┌──────────────────────────▼──────────────────────────────────────┐
│                   C++ SOVEREIGN NODES                            │
│                                                                  │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────┐     │
│  │ SovereignCell│──▶│InferenceEngine│──▶│    MeshNode       │     │
│  │ (eBPF poll) │   │ (entropy)     │   │ (PBFT consensus)  │     │
│  └─────────────┘   └──────────────┘   └─────────┬─────────┘     │
│                                                  │               │
│                                          ┌───────▼────────┐     │
│                                          │  SystemJailer   │     │
│                                          │ (enforcement)   │     │
│                                          └───────┬────────┘     │
│                                                  │               │
│                              eBPF  │  nftables  │  iptables      │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
eBPF kernel probe (sensor.bpf.c)
  → SovereignCell polls ring buffer, feeds InferenceEngine
    → InferenceEngine: entropy-based anomaly detection
      → MeshNode: UDP broadcast PBFT (PRE_PREPARE → PREPARE → COMMIT → EXECUTED)
        → SystemJailer: eBPF blocklist → nftables → iptables cascade
          → AuditLogger: UDP JSON telemetry to C2
```

## Directory Map

| Directory | Purpose |
|-----------|---------|
| `kernel/` | eBPF C probes — `sensor.bpf.c` (ring buffer telemetry), `neuro_bpf.c` (XDP packet filter) |
| `cell/` | Sovereign intelligence — `SovereignCell` (eBPF poll + event queue), `InferenceEngine` (entropy anomaly scoring) |
| `consensus/` | P2P mesh + PBFT — `MeshNode` (UDP broadcast mesh), `PBFT.hpp` (header-only BFT state machine) |
| `crypto/` | Ed25519 identity — key generation, signing, verification via OpenSSL EVP |
| `jailer/` | Enforcement — `SystemJailer` with eBPF + nftables + iptables backends, process imprisonment |
| `telemetry/` | Structured logging — `AuditLogger` (UDP JSON), `TelemetryExporter` (POSIX-locked file writes) |
| `common/` | Shared utilities — `UniqueFD` (RAII file descriptor), `Result<T,E>`, `Base64` |
| `orchestration/` | Python control plane — C2 server, brain AI, bridge API, web server, mesh manager, neuroctl |
| `tools/` | Test utilities — `simulate_threat` (PBFT injection), `test_crypto` (Ed25519 unit tests) |
| `dashboard-react/` | React SOC dashboard — KPI cards, topology graph, agent table, event logs, time-series charts |
| `web/` | Static assets and `mesh_status.json` (POSIX-locked multi-writer telemetry sink) |

## Quick Start

### Prerequisites

```bash
# System dependencies (Ubuntu/Debian)
sudo apt-get install clang make libssl-dev libelf-dev libbpf-dev bpftool \
                     nftables iptables python3 python3-pip nodejs npm

# Python dependencies
pip install -r requirements.txt

# React dashboard dependencies
cd dashboard-react && npm install
```

### Build

```bash
make clean && make
```

This produces:
- `bin/neuro_agent` — the sovereign node binary
- `bin/simulate_threat` — threat injection utility for testing
- `bin/test_crypto` — Ed25519 crypto unit tests

### Run a single node

```bash
./bin/neuro_agent NODE_1
```

### Launch a multi-node mesh

```bash
# 5-node tmux grid
./mesh_dashboard.sh

# 5-node Python-managed mesh
python3 orchestration/mesh_manager.py
```

### Full demo stack

```bash
# Launches C2 server + 3 agents + React dashboard
./start_demo.sh
```

### Stress test (PBFT → Enforcement)

```bash
sudo bash final_stress_test.sh
```

Six-phase validation: boot → mesh discovery → threat injection → PBFT verification → enforcement verification → live firewall rule display.

## How It Works

### PBFT Consensus

Each node runs a Practical Byzantine Fault Tolerance state machine over UDP broadcast to `255.255.255.255:9999`. The protocol has four stages:

1. **PRE_PREPARE** — A node detecting an anomaly initiates consensus
2. **PREPARE** — Nodes acknowledge the proposal
3. **COMMIT** — Nodes confirm they've seen sufficient prepares
4. **EXECUTED** — Quorum reached, enforcement triggers

Quorum is `(2f + 1) / 3` where `f` is the number of tolerated faulty nodes. Every message carries an Ed25519 signature binding `(stage + target + evidence)` together, preventing cross-stage replay and message forgery.

### Enforcement Backends

SystemJailer tries three backends in priority order:

| Priority | Backend | Mechanism |
|----------|---------|-----------|
| 1 (fastest) | eBPF | `BPF_MAP_TYPE_HASH` blocklist pinned at `/sys/fs/bpf/neuro_mesh/neuro_blocklist` |
| 2 | nftables | Dedicated `ip neuro_mesh INPUT` table with filter hook |
| 3 (fallback) | iptables | Traditional `iptables -A INPUT -s <ip> -j DROP` |

Backend availability is probed once per process via a function-local static variable — immune to instance-level memory corruption.

### Safe List

`SystemJailer::add_safe_node()` prevents a node from ever isolating itself or critical infrastructure, even if PBFT consensus demands it. Each node safe-lists itself at startup.

### Identity

Each node generates an Ed25519 keypair on boot. The public key is PEM-encoded and broadcast via ANNOUNCE messages. All PBFT votes are signed with the private key and verified against the sender's registered public key.

## Threat Simulation

```bash
# Default target (10.99.99.99)
./bin/simulate_threat

# Custom target with evidence
./bin/simulate_threat 192.168.1.100 '{"sensor":"ebpf_entropy","value":0.98,"threat":"lateral_movement"}'
```

The simulator acts as a peer node, initiates PBFT consensus with evidence data, and participates in all four consensus stages.

## IPC Protocol

C2 commands are delivered over Unix domain sockets at `/tmp/neuro_mesh_{id}.sock`:

| Command | Action |
|---------|--------|
| `CMD:ISOLATE` | Acknowledged (isolation requires PBFT consensus) |
| `CMD:VACCINATE` | Eradicates all jailed processes |
| `CMD:SHUTDOWN` | Graceful node shutdown |

## Security Properties

- **Fork+exec isolation** — SystemJailer calls iptables/nftables via `fork()` + `execv()` with arguments as separate `argv` entries, eliminating shell injection vectors
- **Binary-safe crypto** — `CryptoCore` uses `data.data()`/`data.size()` instead of `c_str()`, preventing null-byte truncation in signatures
- **RAII file descriptors** — `UniqueFD` wraps raw socket FDs; `AuditLogger` uses it for the static telemetry socket
- **Continuous eBPF drain** — Ring buffer polled in a tight loop before analysis, preventing kernel-side event loss
- **POSIX file locking** — `TelemetryExporter` uses `flock()` to prevent corrupted JSON when multiple processes write to `mesh_status.json`
- **Loopback protection** — SystemJailer refuses to isolate 127.0.0.0/8 addresses
- **Round timeout** — `PBFTConsensus` evicts consensus rounds after 120s of inactivity, preventing unbounded memory growth
