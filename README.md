<div align="center">

```
 ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗       ███╗   ███╗███████╗███████╗██╗  ██╗
 ████╗  ██║██╔════╝██║   ██║██╔══██╗██╔═══██╗      ████╗ ████║██╔════╝██╔════╝██║  ██║
 ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║   ██║█████╗██╔████╔██║█████╗  ███████╗███████║
 ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║╚════╝██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
 ██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝      ██║ ╚═╝ ██║███████╗███████║██║  ██║
 ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝       ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
```

### **Decentralized P2P Security Fabric · C++20 · eBPF · PBFT · mTLS · Zero-Trust**

**No master. No control plane. No single point of failure.**

Every node runs kernel probes, votes on threats via BFT consensus, and enforces
network isolation — peer-to-peer, cryptographic, autonomous.

<br/>

[![C++20](https://img.shields.io/badge/C%2B%2B-20-%2300599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![eBPF](https://img.shields.io/badge/eBPF-kernel--native-%23ebc334?style=for-the-badge&logo=linux&logoColor=black)](https://ebpf.io/)
[![PBFT](https://img.shields.io/badge/consensus-PBFT-%23934fff?style=for-the-badge&logo=blockchaindotcom&logoColor=white)](https://en.wikipedia.org/wiki/Byzantine_fault)
[![Ed25519](https://img.shields.io/badge/crypto-Ed25519-%23000000?style=for-the-badge&logo=letsencrypt&logoColor=white)](https://ed25519.cr.yp.to/)
[![Docker](https://img.shields.io/badge/docker--ready-%232496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/MrGray17/Neuro-Mesh/ci.yml?style=for-the-badge&label=CI)](https://github.com/MrGray17/Neuro-Mesh/actions)

[**Quick Start**](#-quick-start) · [**Demo**](#-30-second-demo) · [**Architecture**](#-architecture) · [**Threat Model**](#-threat-model) · [**Performance**](#-performance) · [**ADRs**](#-architecture-decisions)

<br/>

<img src="docs/architecture.svg" alt="Neuro-Mesh Architecture" width="92%"/>

</div>

---

## What Is Neuro-Mesh?

Neuro-Mesh is a **production-grade decentralized security fabric** written in modern C++20.
Each node:

1. **Observes** kernel events via eBPF ring buffer (sub-microsecond overhead)
2. **Infers** anomalies with entropy analysis + ONNX isolation forest
3. **Votes** on threats via **Practical Byzantine Fault Tolerance** over UDP
4. **Enforces** network isolation with `nftables` / `iptables` / eBPF blocklist
5. **Gossips** state peer-to-peer — no coordinator, no aggregator, no telemetry lake

When a consensus round reaches a **Final Quorum** (≥ 2f+1 of N=5 nodes agree), the
target node's traffic is dropped at the INPUT chain on every honest peer.
**The malicious node sees its own packets disappear at the network edge, in
real time, with cryptographic proof.**

```
eBPF kernel probe (kernel/sensor.bpf.c)
  → NodeAgent (cell/) drains ring buffer, feeds InferenceEngine
    → InferenceEngine (cell/) entropy + ONNX isolation forest
      → MeshNode (consensus/) UDP broadcast PBFT voting
        → PBFTConsensus (consensus/PBFT.hpp) multi-hop state machine
          → PolicyEnforcer (enforcer/) nftables DROP at INPUT chain
            → Telemetry gossip (TELEMETRY|node_id|json) to all peers
              → Each peer's TelemetryBridge broadcasts full mesh view via WebSocket
                → Dashboard (dashboard/) renders live mesh in any browser
```

---

## 30-Second Demo

```bash
# Build everything (eBPF skeleton + agent + tools)
make clean && make

# Launch 5-node mesh in isolated Linux network namespaces
sudo ./tools/setup_demo_net.sh
python3 orchestration/mesh_manager.py &

# Wait for mesh formation (~30s)
sleep 30

# Inject a CRITICAL entropy spike at CHARLIE targeting ALPHA
./bin/inject_event --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL

# In <5s, all 4 honest peers apply nftables DROP for ALPHA's IP:
#   [ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2
#   [nftables] chain INPUT: ip saddr 192.168.50.2 counter packets 76 drop

# Verify the isolation is effective:
sudo ip netns exec BRAVO ping -c2 -W1 192.168.50.2   # 100% loss
sudo ip netns exec BRAVO ping -c2 -W1 192.168.50.6   # 0% loss (mesh intact)
```

```text
$ ./bin/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL
[SIM] Sent:     CMD:INJECT ALPHA {"sensor":"ebpf_entropy","value":0.98,"threshold":0.85,"verdict":"CRITICAL"}
[SIM] Response: ACK:INJECT
[SIM] Done.

$ tail -f /tmp/agent_*.log | grep "Final Quorum|Zero-Trust|Drop"
ALPHA   : [CRITICAL] PBFT Final Quorum Reached! Target ALPHA — executing MitigationEngine response.
BRAVO   : [ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2 [nftables]
CHARLIE : [ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2 [nftables]
DELTA   : [ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2 [nftables]
ECHO    : [ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2 [nftables]
```

Open `http://localhost:8080` in any browser to watch the mesh react in real time.

---

## Quick Start

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt install clang-18 libbpf-dev libelf-dev zlib1g-dev \
  libssl-dev bpftool nlohmann-json3-dev \
  libonnxruntime-dev libseccomp-dev nftables iproute2
```

| Dependency           | Purpose                                          |
|----------------------|--------------------------------------------------|
| clang/LLVM 18+       | C++20 compiler + eBPF backend                    |
| libbpf, libelf, zlib | eBPF loader and BPF object handling              |
| OpenSSL 3.x          | Ed25519 signatures + TLS 1.3 mTLS                |
| bpftool              | eBPF skeleton generation                         |
| nlohmann-json3-dev   | JSON parsing for evidence and telemetry          |
| libseccomp-dev       | Process sandboxing (seccomp BPF)                 |
| libonnxruntime-dev   | Anomaly detection via ONNX inference             |
| nftables / iproute2  | Network isolation enforcement                    |
| Docker (optional)    | Containerized multi-node mesh                    |

### Docker Requirements

The Docker Compose stack requires a **Linux host** with:

- `/sys/kernel/debug` and `/lib/modules/$(uname -r)` mounted into agent containers (compose handles this).
- The following capabilities granted to each agent container: `SYS_ADMIN`, `BPF`, `NET_ADMIN`, `PERFMON` (compose handles this).
- Free host ports: `8080` (dashboard), `9000-9040` (agent WebSocket), `9001` (wsbridge).
- A kernel that exposes the probed kprobes (`execve`, `sendto`, `connect`) — any modern 5.x/6.x kernel works.

Docker Desktop on macOS/Windows is **not supported** because the agents need the host kernel's eBPF subsystem. Use a Linux VM or bare-metal Linux instead.

### Build

```bash
make clean && make           # build the node + eBPF skeleton
make tools                   # build all CLI tools + test binaries
```

Binaries land in `bin/`:
- `neuro_agent` — the node daemon
- `inject_event` — threat injection via IPC socket
- `attack_injector` — adversarial UDP flood simulator
- `register_attacker` — keypair generation + TOFU enrollment
- `test_crypto` — Ed25519 / TLS / sandbox regression suite

### Run a Single Node

```bash
./bin/neuro_agent ALPHA
```

### Launch a 5-Node Mesh

```bash
# Background processes with sandboxing
for node in ALPHA BRAVO CHARLIE DELTA ECHO; do
    ./bin/neuro_agent $node > /tmp/agent_$node.log 2>&1 &
done

# Or via tmux grid
./mesh_dashboard.sh

# Or Python process manager
python3 orchestration/mesh_manager.py

# Or Docker Compose (decentralized — no control plane needed)
docker compose -f docker-compose.yml build --no-cache
docker compose -f docker-compose.yml up -d
```

### Live Dashboard

```bash
# Vanilla JS dashboard — zero dependencies, real-time WebSocket
python3 -m http.server 8080 --directory dashboard/
open http://localhost:8080
```

Each node binds a unique WebSocket port (ALPHA=9000, BRAVO=9010, …, ECHO=9040).
Any node's port serves the **full mesh view** via gossip-based telemetry.

### Inject a Threat

```bash
docker exec neuro_charlie /app/inject_event \
  --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL

# Generate load to trigger the anomaly detector
docker exec neuro_charlie python3 /app/traffic_generator.py \
  --target 127.0.0.1 --duration 15 --threads 8
```

---

## Architecture

### Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          KERNEL SPACE  (eBPF)                             │
│  ┌──────────────┐    ┌─────────────────┐    ┌──────────────────────┐    │
│  │ trace_sendto │───►│ telemetry_ringbuf│───►│  /sys/fs/bpf/neuro_* │    │
│  │  (kprobe)    │    │  (lock-free)     │    │   (XDP blocklist)    │    │
│  └──────────────┘    └─────────────────┘    └──────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
                                    │ ring buffer poll
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          USER SPACE  (C++20)                              │
│                                                                          │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────────┐  │
│  │ NodeAgent   │───►│ InferenceEngine  │───►│  MeshNode              │  │
│  │  (cell/)    │    │  entropy + ONNX  │    │  (consensus/)          │  │
│  └─────────────┘    └──────────────────┘    └────────┬───────────────┘  │
│                                                       │ PBFT vote UDP    │
│                                                       ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  PBFTConsensus  (consensus/PBFT.hpp)  multi-hop state machine      │ │
│  │   IDLE → PREPARE → COMMIT → EXECUTED                                │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                       │                  │
│                                                       ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  PolicyEnforcer  (enforcer/)                                         │ │
│  │   nftables / iptables / eBPF blocklist / process suspension         │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                       │                  │
│                                                       ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  TelemetryBridge  (telemetry/)  sandboxed child process             │ │
│  │   chroot / seccomp-bpf / setresuid(nobody)                          │ │
│  │   WebSocket → dashboard                                              │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

### Directory Map

| Directory      | Purpose                          | Highlights                                                        |
|----------------|----------------------------------|-------------------------------------------------------------------|
| `kernel/`      | eBPF probes                      | `sensor.bpf.c` (ringbuf kprobe), `neuro_bpf.c` (XDP filter)       |
| `cell/`        | Node intelligence                | `NodeAgent` (ring buffer drain), `InferenceEngine` (entropy + ONNX) |
| `consensus/`   | P2P + PBFT + gossip              | `MeshNode` (UDP mesh), `PBFT.hpp` (header-only state machine)     |
| `crypto/`      | Ed25519 identity + mTLS          | `CryptoCore` (OpenSSL EVP), `KeyManager` (persistent keystore)    |
| `enforcer/`    | Policy enforcement               | `PolicyEnforcer` (nftables/iptables), `MitigationEngine`         |
| `telemetry/`   | Structured logging + WS bridge   | `TelemetryBridge` (sandboxed uWebSockets), `AuditLogger` (UDP)    |
| `orchestration/` | Python tools (optional)        | `mesh_manager.py`, `ws_proxy.py` (stateless WS bridge)            |
| `tools/`       | Test/sim utilities               | `inject_event`, `attack_injector`, `traffic_generator`           |
| `dashboard/`   | Vanilla JS dashboard             | Zero-dependency HTML/CSS/JS with Canvas + WebSocket               |
| `common/`      | Shared utilities                 | `UniqueFD` (RAII fd), `Result<T,E>` (error propagation)            |
| `docs/adr/`    | Architecture Decision Records    | 5 ADRs covering PBFT, crypto, sandbox, TOFU, telemetry            |

### Key Design Decisions

- **PBFT over UDP broadcast to 127.0.0.1:9999** — all nodes run on localhost; discovery is implicit. Each node announces its Ed25519 public key on startup.
- **Signature binding** — PBFT signatures bind `(stage + target + evidence)`, preventing cross-stage replay attacks where a PRE_PREPARE signature could be re-used as a COMMIT.
- **Safe list** — `PolicyEnforcer::add_safe_node()` prevents a node from ever isolating itself or critical infrastructure, even if PBFT consensus demands it.
- **Zero-trust self-vote** — In `MeshNode::broadcast_pbft_stage()`, self-votes are verified through the same `verify_message()` path as external votes before advancing state.
- **Timeout-based cleanup** — `PBFTConsensus` evicts consensus rounds after 120s of inactivity, preventing unbounded memory growth.
- **`fork()+execv()` for iptables** — `PolicyEnforcer` uses `fork()` + `execv()` to call iptables with arguments as separate `argv` entries, eliminating shell injection vectors.
- **Ed25519 signatures** on every PBFT message prevent spoofed votes.
- **Binary-safe crypto** — `CryptoCore` uses `data.data()` / `data.size()` instead of `c_str()`, preventing null-byte truncation in signatures.
- **RAII file descriptors** — `UniqueFD` wraps raw socket FDs; `AuditLogger` uses it for the static telemetry socket.
- **Continuous eBPF drain** — `NodeAgent::telemetry_loop()` drains the ring buffer in a tight `while(ring_buffer__poll()>0)` loop, preventing kernel-side event loss.
- **IPC socket** — `main.cpp` creates a Unix domain socket at `/tmp/neuro_mesh_{id}.sock` for command delivery (INJECT, ISOLATE, RESET, SHUTDOWN) with shared-secret token auth.
- **V3 discovery with cert PEM** — Each beacon broadcasts the full TLS cert PEM (signed by Ed25519 identity key), enabling peers to add the cert to OpenSSL's trust store and verify mTLS handshakes. The fingerprint is no longer just a comparison string — it's the key to a cryptographic cert pin.
- **Telemetry gossip** — Each node unicasts its telemetry JSON to all known peers on the discovery port. Peers push received telemetry to their local TelemetryBridge. **The dashboard connects to ANY node and sees the full mesh.**
- **Unique WebSocket ports** — Each node binds a different TelemetryBridge port (ALPHA=9000, BRAVO=9010, …, ECHO=9040, override via `NEURO_WS_PORT`) to avoid host-network conflicts.
- **Seccomp-BPF default-kill** — TelemetryBridge child is locked down to a 65-syscall whitelist. Any unknown syscall kills the child immediately (defense in depth on top of chroot + setresuid).

---

## Threat Model

Neuro-Mesh is designed to survive the following adversary profiles:

| Adversary                     | Assumption                                               | Defense                                                   |
|-------------------------------|----------------------------------------------------------|-----------------------------------------------------------|
| **Passive eavesdropper**      | Can sniff all UDP/TCP traffic                            | Ed25519 signatures on every PBFT message; mTLS 1.3 on TCP |
| **Active MITM**               | Can intercept, replay, or modify packets in flight       | Signature binding (stage+target+evidence) blocks replay   |
| **Byzantine node (≤ f=1)**    | Up to 1 of 5 nodes may be malicious or compromised        | PBFT requires 2f+1=3 honest votes to commit              |
| **Byzantine node (≤ f=1) voting inconsistently** | Same node votes PREPARE but not COMMIT    | PBFT state machine enforces per-stage vote counts        |
| **Self-isolation attempt**    | Compromised node tries to isolate itself or the cluster  | `PolicyEnforcer::add_safe_node()` safe-list               |
| **Cert spoofing**             | Attacker mints a cert claiming to be a legitimate peer   | Cert PEM signed by Ed25519 identity key, fingerprint pin  |
| **Shell injection via iptables args** | Malicious verdict payload injects shell metachars | `fork()+execv()` with argv as `vector<string>`           |
| **Null-byte truncation**      | Attacker crafts signature with `\0` to truncate payload  | `data.data()/data.size()` (binary-safe)                    |
| **DoS via fork-bomb**         | Anomaly storm causes thousands of forks                  | `fork_exec_wait` rate-limited + seccomp-BPF in bridge     |
| **Stale consensus**           | Old rounds accumulate, OOM the node                      | 120s timeout eviction in `PBFTConsensus`                  |
| **eBPF event loss**           | Ring buffer overruns under load                          | Tight `while(ring_buffer__poll()>0)` drain loop           |
| **Sandbox escape**            | TelemetryBridge child tries `execve("/bin/sh")`          | seccomp-BPF default-kill + chroot + setresuid(nobody)     |

### Out of Scope

- **Sybil attacks on identity provisioning** — a PKI / RA layer is orthogonal to the mesh; we assume one Ed25519 keypair per real peer.
- **Hardware-level side channels** (Spectre, Rowhammer).
- **A node that can forge signatures from the keypair** — assumes secure key storage.

### Safety Properties

- **Agreement** — No two honest nodes commit different decisions for the same `(view, target)`.
- **Validity** — A decision is committed only if at least one honest node proposed it.
- **Termination** — A consensus round either reaches quorum or evicts via timeout.
- **Safe-list invariant** — `add_safe_node()` can never be removed via PBFT.
- **No self-isolation** — A node's own pubkey is always in the safe-list at startup.

---

## Performance

Measured on Linux 6.8, Intel Xeon E5-2680v4, 5-node mesh in network namespaces.

| Operation                              | Latency     | Throughput        |
|----------------------------------------|-------------|-------------------|
| eBPF kprobe → ring buffer              | < 1 µs      | 1.2M events/sec   |
| Ring buffer → InferenceEngine          | 8 µs        | 125K events/sec   |
| Ed25519 sign (single vote)             | 47 µs       | 21K sigs/sec      |
| Ed25519 verify (single vote)           | 138 µs      | 7.2K verifies/sec |
| PBFT round-trip (PREPARE → COMMIT)     | 3.2 ms      | 312 rounds/sec    |
| Full consensus → nftables DROP applied | 47 ms p50, 89 ms p99 | —        |
| mTLS handshake (TLS 1.3, X25519)       | 1.1 ms      | 900 handshakes/sec |
| Telemetry gossip (per peer/heartbeat)  | 0.4 ms      | 2.5K msg/sec      |

See [`docs/benchmarks/`](docs/benchmarks/) for the full methodology, including flame graphs, syscall traces, and nftables rule hit rates.

### Resource Footprint

| Resource | Per Node (idle) | Per Node (under 1K events/sec) |
|----------|-----------------|---------------------------------|
| RSS      | 12 MB           | 28 MB                           |
| CPU      | 0.4%            | 4.8%                            |
| FDs      | 9               | 11 (ringbuf + epoll)            |
| Threads  | 4               | 4 (agent, mesh, bridge, IPC)    |
| Net      | 8 KB/s          | 120 KB/s                        |

---

## Security Architecture

### Cryptographic Primitives

| Purpose              | Algorithm       | Library         | Key Size |
|----------------------|-----------------|-----------------|----------|
| Node identity        | Ed25519         | OpenSSL EVP     | 256-bit  |
| PBFT message signing | Ed25519         | OpenSSL EVP     | 256-bit  |
| Transport (mTLS)     | TLS 1.3         | OpenSSL 3.x     | —        |
| Key exchange (TLS)   | X25519 / P-256  | OpenSSL 3.x     | 256-bit  |
| Certificate          | X.509v3 self-signed | OpenSSL     | RSA-2048 / Ed25519 |
| Random                | `/dev/urandom` + `RDRAND` | Linux   | 256-bit  |

### Key Persistence

Every node's Ed25519 keypair is persisted in `~/.neuro_mesh/keys/{node_id}.key` with `0600` permissions. The key is reused across restarts to preserve the cryptographic identity. If the file is missing, a fresh keypair is generated and persisted on first use.

### Trust-on-First-Use (TOFU)

1. **Discovery**: each node broadcasts a beacon containing `id`, `pubkey_b64`, `tls_fpr`, `cert_pem_b64`, `signature`.
2. **Verification**: receivers verify the signature using `pubkey_b64` against the binding `(id | tcp | tls | ts | tls_fpr | cert_pem)`.
3. **Cert pinning**: the V3 format includes the full X.509 cert PEM, signed by the Ed25519 identity key. After dual-path confirmation, the cert is added to OpenSSL's trust store via `SSL_CTX_get_cert_store() + X509_STORE_add_cert()`.
4. **Subsequent handshakes**: mTLS uses the pinned cert. A different cert with the same identity key fails verification.

### PBFT State Machine

```
       (proposer)
           │
           ▼
   ┌───────────────┐
   │  IDLE         │  ← on stage 0 timeout: evict
   └───────┬───────┘
           │ broadcast PREPARE (signed)
           ▼
   ┌───────────────┐
   │  PREPARED     │  ← on ≥2f+1 PREPARE: advance
   └───────┬───────┘
           │ broadcast COMMIT (signed)
           ▼
   ┌───────────────┐
   │  COMMITTED    │  ← on ≥2f+1 COMMIT: execute
   └───────┬───────┘
           │ call PolicyEnforcer
           ▼
   ┌───────────────┐
   │  EXECUTED     │  ← gossip EXECUTED to peers
   └───────────────┘
```

Each stage's signature binds `(stage || target || evidence_hash)`. **A PREPARE signature cannot be replayed as a COMMIT** because the `stage` field changes.

### Process Sandboxing

The TelemetryBridge child process is sandboxed with three layers:

1. **chroot** — `chroot("/var/empty")` removes filesystem access.
2. **setresuid/setresgid** — drops to `nobody:nogroup` (uid 65534).
3. **seccomp-BPF default-kill** — whitelist of 65 syscalls; any other syscall kills the process.

Parent liveness is monitored via **passive EOF detection** on a pipe: when the parent closes the pipe (process exit), the child's `read()` returns 0 and the child exits cleanly. This avoids the `kill(getppid(), 0)` false-positive under `nobody` (would return `EPERM` when probing the root parent).

---

## Architecture Decision Records

All major design decisions are documented as ADRs in [`docs/adr/`](docs/adr/):

- [**ADR-001**](docs/adr/0001-pbft-consensus-over-udp.md) — Why PBFT over UDP broadcast
- [**ADR-002**](docs/adr/0002-ed25519-signature-binding-cross-stage-replay.md) — Why Ed25519 with stage-binding signatures
- [**ADR-003**](docs/adr/0003-fork-exec-iptables-over-system.md) — Why `fork()+execv()` over `system()`
- [**ADR-004**](docs/adr/0004-dual-path-tofu-trust-model.md) — Why dual-path TOFU with signed cert PEM in V3 discovery
- [**ADR-005**](docs/adr/0005-telemetrybridge-sandbox-architecture.md) — Why chroot + seccomp-BPF + setresuid for the bridge

---

## Testing

```bash
# Crypto regression suite
./bin/test_crypto

# Full E2E netns demo
sudo ./tools/setup_demo_net.sh
python3 orchestration/mesh_manager.py
./bin/inject_event --node CHARLIE --target ALPHA --event entropy_spike --verdict CRITICAL

# Mesh-level benchmark
python3 tools/benchmark_mesh.py --nodes 5 --duration 60

# Attack simulation
./bin/attack_injector --target ALPHA --duration 30 --threads 16
```

---

## Project Structure

```
neuro_mesh/
├── main.cpp                       # Entry point
├── Makefile                       # Build orchestration (clang++, bpftool)
├── docker-compose.yml             # 5-node decentralized mesh
├── mesh_dashboard.sh              # tmux grid launcher
├── README.md                      # This file
├── LICENSE                        # MIT
│
├── kernel/                        # eBPF probes
│   ├── sensor.bpf.c               # kprobe + ringbuf producer
│   ├── neuro_bpf.c                # XDP filter
│   └── sensor.skel.h              # Generated by bpftool gen skeleton
│
├── cell/                          # Node intelligence
│   ├── NodeAgent.{hpp,cpp}        # ring buffer drain, sensor control
│   └── InferenceEngine.{hpp,cpp}  # entropy analysis + ONNX scoring
│
├── consensus/                     # P2P + PBFT
│   ├── MeshNode.{hpp,cpp}         # UDP mesh, telemetry gossip
│   └── PBFT.hpp                   # header-only BFT state machine
│
├── crypto/                        # Ed25519 + TLS
│   ├── CryptoCore.{hpp,cpp}       # keygen, sign, verify (OpenSSL EVP)
│   └── KeyManager.{hpp,cpp}       # persistent keystore
│
├── net/                           # Transport
│   ├── TransportLayer.{hpp,cpp}   # mTLS 1.3, cert pinning, TOFU
│   └── TLSContext.{hpp,cpp}       # OpenSSL SSL_CTX wrapper
│
├── enforcer/                      # Policy enforcement
│   ├── PolicyEnforcer.{hpp,cpp}   # nftables / iptables / eBPF blocklist
│   └── MitigationEngine.{hpp,cpp} # process suspension, audit
│
├── telemetry/                     # Observability
│   ├── TelemetryBridge.{hpp,cpp}  # sandboxed WebSocket server
│   ├── AuditLogger.{hpp,cpp}      # UDP JSON logs
│   └── TelemetryExporter.hpp      # POSIX-locked JSON status export
│
├── common/                        # Shared utilities
│   ├── UniqueFD.hpp               # RAII file descriptor
│   └── Result.hpp                 # Result<T,E> error propagation
│
├── orchestration/                 # Python orchestration (optional)
│   ├── mesh_manager.py            # Process manager
│   ├── ws_proxy.py                # Stateless WS bridge (Docker/WSL2)
│   ├── control_server.py          # Legacy aggregator
│   └── anomaly_classifier.py      # ML inference (legacy)
│
├── tools/                         # Test/sim utilities
│   ├── inject_event.cpp           # Threat injection via IPC
│   ├── attack_injector.cpp        # Adversarial flood simulator
│   ├── test_crypto.cpp            # Crypto regression suite
│   ├── traffic_generator.py       # Load generator
│   ├── benchmark_mesh.py          # Mesh-level benchmark
│   └── setup_demo_net.sh          # netns topology
│
├── dashboard/                     # Vanilla JS dashboard
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   └── dashboard_raw.html         # Single-file export
│
├── docs/                          # Documentation
│   ├── adr/                       # Architecture Decision Records (5)
│   ├── benchmarks/                # Performance methodology
│   └── architecture.svg           # Architecture diagram
│
└── _archive_old/                  # Archived experiments (46 files)
    └── (monolithic client, ML models, standalone HTML, etc.)
```

---

## Development

### Coding Standards

- **C++20** — `clang++ -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror`
- **All includes project-root-relative** — e.g. `#include "crypto/CryptoCore.hpp"` (uses `-I.` in CXXFLAGS)
- **No `c_str()` for binary data** — use `data.data()` / `data.size()` for signature payloads
- **No raw `fork()+system()`** — use `fork()+execv()` with `vector<string>` argv
- **RAII for FDs** — wrap in `UniqueFD`
- **No `kill(getppid(), 0)` liveness checks under unprivileged UIDs** — returns `EPERM` falsely; use pipe EOF instead
- **All PBFT signatures bind `(stage + target + evidence)`** — never sign an isolated field
- **All public APIs are `const`-correct**

### Adding a New PBFT Stage

1. Add the stage name to `consensus/PBFT.hpp` enum.
2. Update `MeshNode::broadcast_pbft_stage()` to include the new stage in the signature payload.
3. Update `PBFTConsensus::verify_message()` to check the signature.
4. Add a test in `tools/test_crypto.cpp` for the new signature shape.
5. Update the relevant ADR.

### Adding a New Enforcer Backend

1. Implement the backend as a class with `apply()` / `revoke()` methods.
2. Register it in `PolicyEnforcer::init_backends()`.
3. Add a unit test that verifies the backend applies the rule idempotently.
4. Add a cleanup hook in the agent's shutdown path.

---

## Contributing

Contributions are welcome! Please:

1. **Open an issue first** for major changes (PBFT state machine, crypto, eBPF probes).
2. **Match the existing code style** — `clang-format` config is in the repo root.
3. **All new code must build with `-Werror`** — no warnings, no exceptions.
4. **Add a test** for any new behavior.
5. **Update the relevant ADR** if you change a design decision.

### Reporting Security Issues

**Please do not file public issues for security vulnerabilities.** Open a [GitHub Security Advisory](https://github.com/MrGray17/Neuro-Mesh/security/advisories/new) privately.

---

## License

[MIT](LICENSE) — Copyright (c) 2024 Neuro-Mesh Contributors

---

## Acknowledgments

- **eBPF / libbpf** — kernel-native observability without kmods
- **OpenSSL** — the bedrock of crypto on Linux
- **PBFT** — Castro & Liskov, 1999 — the original BFT state machine
- **uWebSockets** — single-header WebSocket server
- **nftables** — modern netfilter replacement
- **The Linux kernel community** — for making all of this possible

---

<div align="center">

**Built for environments where the network is the threat and the perimeter is a lie.**

If you're deploying this in production, talk to us — we want to hear about it.

⭐ **Star this repo** if Neuro-Mesh saved you from a 3am incident.

</div>
