# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build everything (eBPF skeleton + neuro_agent + inject_event + test_crypto)
make clean && make

# Run a single node
./bin/neuro_agent NODE_1

# Launch 5-node mesh in a tmux grid
./mesh_dashboard.sh

# Launch 5 nodes via Python process manager
python3 orchestration/mesh_manager.py

# Docker Compose (decentralized — no control plane needed)
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml build --no-cache
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml up -d
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml down

# Dashboard
open http://localhost:8080

# Event injection
docker exec neuro_charlie /app/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL

# Traffic flood
docker exec neuro_charlie python3 /app/traffic_generator.py --target 127.0.0.1 --duration 15 --threads 8

# Individual services (optional / legacy)
python3 orchestration/control_server.py        # Legacy: centralized aggregator
python3 orchestration/anomaly_classifier.py
python3 orchestration/ws_proxy.py              # Stateless WS proxy
```

## Architecture

Neuro-Mesh is a decentralized P2P security mesh. C++20 nodes use eBPF to detect kernel-level anomalies, run a PBFT consensus protocol over UDP to verify events, then execute network isolation against compromised peers. Nodes gossip telemetry directly to each other — no central control plane. Any node can serve the dashboard.

### Data Flow

```
eBPF kernel probe (kernel/sensor.bpf.c)
  → NodeAgent (cell/) polls ring buffer, feeds InferenceEngine
    → InferenceEngine (cell/) entropy analysis
      → MeshNode (consensus/) UDP broadcast PBFT voting
        → PBFTConsensus (consensus/PBFT.hpp) multi-hop state machine
          → PolicyEnforcer (enforcer/) iptables isolation
            → Telemetry gossip (TELEMETRY|node_id|json) to all peers
              → Each peer's TelemetryBridge broadcasts full mesh view via WebSocket
```

### Directory Map

| Directory | Purpose | Files |
|-----------|---------|-------|
| `kernel/` | eBPF probes | `sensor.bpf.c`, `neuro_bpf.c` (XDP filter), `vmlinux.h`, `sensor.skel.h` (generated) |
| `cell/` | Node intelligence | `NodeAgent.hpp/.cpp` (agent core), `InferenceEngine.hpp/.cpp` (entropy anomaly detection) |
| `consensus/` | P2P + PBFT + gossip | `MeshNode.hpp/.cpp` (UDP mesh, telemetry gossip), `PBFT.hpp` (header-only BFT state machine) |
| `crypto/` | Ed25519 identity | `CryptoCore.hpp/.cpp` (keygen, sign, verify via OpenSSL EVP) |
| `enforcer/` | Policy enforcement | `PolicyEnforcer.hpp/.cpp` (iptables + eBPF blocklist + process suspension), `MitigationEngine.hpp/.cpp` |
| `telemetry/` | Structured logging + WS bridge | `TelemetryBridge.hpp/.cpp` (uWebSockets sandboxed child process), `AuditLogger.hpp/.cpp` (UDP JSON), `TelemetryExporter.hpp` |
| `orchestration/` | Python tools (optional) | `control_server.py` (legacy aggregator), `anomaly_classifier.py`, `ws_proxy.py` (stateless WS proxy), `mesh_manager.py` |
| `tools/` | Test/sim utilities | `inject_event.cpp`, `test_crypto.cpp`, `traffic_generator.py`, `benchmark_mesh.py` |
| `dashboard/` | Vanilla JS dashboard | Zero-dependency HTML/CSS/JS with Canvas + WebSocket |
| `main.cpp` | Entry point | Initializes PolicyEnforcer + MeshNode + InferenceEngine, runs heartbeat with telemetry gossip |
| `common/` | Shared utilities | `UniqueFD.hpp` (RAII file descriptor), `Result.hpp` (Result<T,E> error propagation) |
| `_archive_old/` | Archived experiments | 46 old files (monolithic client, ML models, standalone HTML dashboard, etc.) |

### Key Design Decisions

- **PBFT over UDP broadcast to 127.0.0.1:9999** — All nodes run on localhost; discovery is implicit via broadcast. Each node announces its Ed25519 public key on startup.
- **Signature binding** — PBFT signatures bind `(stage + target + evidence)` together, preventing cross-stage replay attacks where a PRE_PREPARE signature could be re-used as a COMMIT.
- **Safe list** — `PolicyEnforcer::add_safe_node()` prevents a node from ever isolating itself or critical infrastructure, even if PBFT consensus demands it.
- **Zero-trust self-vote** — In `MeshNode::broadcast_pbft_stage()`, self-votes are verified through the same `verify_message()` path as external votes before advancing state.
- **Timeout-based cleanup** — `PBFTConsensus` evicts consensus rounds after 120s of inactivity, preventing unbounded memory growth.
- **fork+exec iptables** — PolicyEnforcer uses `fork()` + `execv()` to call iptables with arguments as separate `argv` entries, eliminating shell injection vectors.
- **Ed25519 signatures** on every PBFT message prevent spoofed votes.
- **Binary-safe crypto** — `CryptoCore` uses `data.data()`/`data.size()` instead of `c_str()`, preventing null-byte truncation in signatures.
- **RAII file descriptors** — `UniqueFD` wraps raw socket FDs; `AuditLogger` uses it for the static telemetry socket.
- **Continuous eBPF drain** — `NodeAgent::telemetry_loop()` drains the ring buffer in a tight `while(ring_buffer__poll()>0)` loop before analysis, preventing kernel-side event loss.
- **IPC socket** — `main.cpp` creates a Unix domain socket at `/tmp/neuro_mesh_{id}.sock` for command delivery (INJECT, ISOLATE, RESET, SHUTDOWN).
- **POSIX file locking** in `TelemetryExporter` prevents corrupted JSON when multiple processes write to `web/mesh_status.json`.
- **`-I.` in CXXFLAGS** — All includes are project-root-relative (e.g., `#include "crypto/CryptoCore.hpp"`).
- **eBPF skeleton** is auto-generated by `bpftool gen skeleton` during `make`, placed at `kernel/sensor.skel.h`.
- **Telemetry gossip** — Each node unicasts its telemetry JSON to all known peers on the discovery port (UDP 9998). Peers push received telemetry to their local TelemetryBridge. Dashboard connects to ANY node and sees the full mesh.
- **Unique WebSocket ports** — Each node binds a different TelemetryBridge port (ALPHA=9000, BRAVO=9001, CHARLIE=9002, DELTA=9003, ECHO=9004) to avoid host-network conflicts.
- **Stateless wsbridge** — `ws_proxy.py` tries all 5 node backends with failover. It's a network bridge for Docker/WSL2 (the browser can't reach host-network ports directly). In real deployments, the browser connects directly to node IPs.
