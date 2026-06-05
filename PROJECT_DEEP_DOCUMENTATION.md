# Neuro-Mesh — Deep Technical Documentation

> **Status:** Authoritative technical reference.
> **Audience:** Senior engineers, security auditors, architects, maintainers, contributors.
> **Source of truth:** Derived from the source code in this repository. Every claim is traceable to a file and (where possible) a line. Where the code is ambiguous, the ambiguity is marked `[ASSUMPTION]` or `[NOT YET VERIFIED]`.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Executive Summary](#2-executive-summary)
3. [Architecture Overview](#3-architecture-overview)
4. [System Components](#4-system-components)
5. [Runtime Lifecycle](#5-runtime-lifecycle)
6. [Consensus System Deep Dive](#6-consensus-system-deep-dive)
7. [Security Architecture](#7-security-architecture)
8. [Networking Architecture](#8-networking-architecture)
9. [Enforcement Engine](#9-enforcement-engine)
10. [Telemetry & Monitoring](#10-telemetry--monitoring)
11. [Data Flow Analysis](#11-data-flow-analysis)
12. [State Management](#12-state-management)
13. [Failure Handling](#13-failure-handling)
14. [Configuration System](#14-configuration-system)
15. [Build System](#15-build-system)
16. [Deployment Guide](#16-deployment-guide)
17. [Operational Guide](#17-operational-guide)
18. [Security Review Notes](#18-security-review-notes)
19. [Contributor Guide](#19-contributor-guide)
20. [File & Directory Reference](#20-file--directory-reference)
21. [Glossary](#21-glossary)

---

## 1. Project Overview

### 1.1 Project Purpose

Neuro-Mesh is a **decentralized peer-to-peer security mesh** for detecting and isolating compromised workloads in real time. The system runs multiple `neuro_agent` processes (nodes) on a network, each equipped with an eBPF kernel sensor. When any node detects an anomaly, the entire mesh runs a **PBFT (Practical Byzantine Fault Tolerance) consensus round** to agree on whether to isolate the suspected peer. Consensus decisions are propagated to every node, which then applies network-level isolation (eBPF XDP drop, nftables, iptables).

The system's defining property is that **no central authority is required**: any node can be the dashboard host, any node can be the proposer, and the mesh tolerates `f` Byzantine failures with `n = 3f + 1` nodes (BFT safety property of standard PBFT).

### 1.2 Problem Being Solved

Traditional intrusion-detection systems suffer from one of two failure modes:

- **Centralized detection** — a single SOC/IDS is a single point of failure and a single target for adversaries. Detection latency is also bounded by the network round trip to the central collector.
- **Local-only detection** — each host decides unilaterally, which means a single compromised host can be isolated by a single malicious peer (a "griefing" attack), or a single compromised host can be ignored because no peer agrees with the verdict.

Neuro-Mesh attempts to solve this by combining local kernel-level detection (eBPF) with a Byzantine-tolerant agreement protocol (PBFT), then enforcing the agreement through kernel-level networking primitives (XDP/nftables/iptables) on every node that participated in the consensus.

### 1.3 Design Goals

| Goal | Mechanism |
|------|-----------|
| **Sub-second detection-to-isolation** | eBPF ring buffer + heartbeat-driven consensus |
| **Byzantine tolerance** | PBFT over UDP broadcast, Ed25519 signatures, quorum intersection guard |
| **Zero single point of failure** | No central coordinator; gossip-based telemetry; any node hosts the dashboard |
| **Defense in depth** | Multiple enforcement backends (XDP → nftables → iptables); sandboxed telemetry bridge; kernel-bypass-resistant auth |
| **Cryptographic accountability** | Every PBFT vote is signed; every ban is recorded in a Merkle proof chain |
| **Privilege separation** | Telemetry WebSocket bridge runs in chroot + seccomp + dropped-UID child process |
| **Recoverable from transient failure** | `StateJournal` write-ahead log, `cleanup_stale_rounds` with TTL, dual-path TOFU |
| **Testable** | Unit tests, integration tests, fuzz harnesses (`make fuzz`), stress tests |

### 1.4 Non-Goals

- **Not a SIEM** — Neuro-Mesh does not store long-term event history beyond a per-process ring buffer and a per-process journal. Integration with a SIEM is left to operators.
- **Not a host firewall** — the eBPF XDP dropper is for *mesh-internal* traffic between nodes, not for arbitrary ingress.
- **Not a replacement for OS hardening** — the system assumes the host kernel is trusted; it does not defend against kernel-level rootkits.
- **Not a public/internet-scale network** — the default deployment is 5 nodes on `127.0.0.1` (localhost) or a trusted LAN. Cross-internet deployment requires additional transport hardening not present in the mainline.
- **Not a generic blockchain** — there is no mining, no token, no global ledger. The `ProofChain` is a per-process Merkle log, not a global one.

### 1.5 Major Capabilities

1. **eBPF kernel telemetry** — four kprobes (`execve`, `sendto`, `sendmsg`, `connect`) and one XDP dropper (`sensor.bpf.c:43-65, 103-191`).
2. **ONNX anomaly detection** — `cell/InferenceEngine` runs an Isolation Forest model exported to ONNX; entropy-spike threshold 0.65.
3. **PBFT consensus** — 6 stages (`IDLE, PRE_PREPARE, PREPARE, COMMIT, EXECUTED, BAN_PEER`), 4-round TTL 120 s, view-change timeout 130 s, rate limit 5/s, signed every message.
4. **Three-backend enforcement cascade** — eBPF XDP map → nftables chain → iptables REJECT. Each backend is probed at startup and used in priority order (`enforcer/PolicyEnforcer.cpp:538-580`).
5. **Gossip-based telemetry** — every node unicasts a JSON telemetry blob to all known peers; the dashboard connects to any node and sees the full mesh view (`main.cpp:215-242`).
6. **WebSocket dashboard** — vanilla-JS single-page UI in `dashboard/index.html`, served by the TelemetryBridge on a per-node port (ALPHA=9000, BRAVO=9010, …, ECHO=9040; `main.cpp:537-546`).
7. **Sandboxed bridge** — TelemetryBridge child runs in chroot `/var/empty`, dropped to UID/GID `nobody/nogroup`, `PR_SET_NO_NEW_PRIVS`, and a default-deny seccomp filter with ~56 explicitly-allowed syscalls (`telemetry/TelemetryBridge.cpp:180-310`).
8. **ProofChain audit log** — Merkle-chained append-only log of consensus decisions, exported to a JSON file with POSIX file locking (`crypto/ProofChain.hpp`, `telemetry/TelemetryExporter.hpp`).
9. **IPC command interface** — Unix domain socket at `/tmp/neuro_mesh_<NODE_ID>.sock`, guarded by a per-boot shared-secret token (`NEURO_IPC_TOKEN`), per-UID rate limit (10/s), peer-credential check (`main.cpp:247-330`).
10. **Attack simulation tooling** — `tools/attack_injector`, `tools/register_attacker`, and `attacks/AttackSimulator` for adversarial tests (UDP flood, equivocation).

---

## 2. Executive Summary

Neuro-Mesh is a **five-node PBFT-secured eBPF intrusion response mesh** designed to run on a single host or a small trusted cluster. Each node boots with a unique Ed25519 identity, a TLS 1.3 self-signed certificate, and an eBPF skeleton that hooks the kernel's `execve`, `sendto`, `sendmsg`, and `connect` syscalls. Detected anomalies are scored by an ONNX Isolation Forest model and, when the blended entropy score crosses 0.65, the node self-initiates a PBFT round that proposes isolation of a suspect peer.

The PBFT implementation follows the standard four-stage flow — `PRE_PREPARE → PREPARE → COMMIT → EXECUTED` — with a fifth stage `BAN_PEER` for permanent exclusion. Every stage transition is signed; every message is rate-limited; every commit is verified by a **quorum-intersection guard** that ensures the PREPARE voter set and the COMMIT voter set overlap by at least a quorum (`consensus/PBFT.hpp:546-573`). This guard, in its current location at the `COMMIT → EXECUTED` transition, is the single most important safety property in the code base.

When a round reaches `EXECUTED`, every node locally applies a three-backend enforcement cascade: (1) update the eBPF XDP blocklist map, (2) insert an nftables `drop` rule, (3) fall back to an iptables `REJECT` rule. The order is intentional — eBPF is the fastest, iptables is the most portable. Each backend is independently probed at startup and independently applied; an attacker must therefore defeat all three to maintain connectivity with a banned peer.

Telemetry is gossiped on a heartbeat (every 2 s by default). Each node unicasts a JSON snapshot of its local state to all known peers; each receiving node forwards the union to its own TelemetryBridge. The dashboard connects via WebSocket to **any** node and sees the same union, which is what makes the system operationally redundant.

The TelemetryBridge itself is a **privilege-separated child process**: it is forked from the main agent, chrooted into `/var/empty`, dropped to UID/GID `nobody/nogroup`, given `PR_SET_NO_NEW_PRIVS`, and then constrained by a default-deny seccomp filter that whitelists only the ~56 syscalls uWebSockets/uSockets actually need. A compromise of the WebSocket layer does not yield kernel access, does not yield access to the parent's address space, and cannot reach the BPF maps.

The system's **principal failure mode** is partition: with `n=1` (no peers discovered), a node cannot initiate a cross-node ban and will log `[DEFENSE] Self-vote consensus blocked — no peers online`. With `n=5`, the mesh tolerates 1 Byzantine node (the standard BFT bound). The mesh **will not** self-isolate even if consensus demands it, because the local node ID is always in the safe-list — a critical invariant established in `main.cpp:518` (`jailer.add_safe_node(node_id)`) and re-checked at every enforcement call in `enforcer/PolicyEnforcer.cpp:238-269`.

For executives: Neuro-Mesh is a **locality-of-detection** system. It assumes the kernel is trustworthy, the operator is non-adversarial, and the network is at most semi-trusted. Within those assumptions, it provides a verifiable, cryptographically-attested intrusion-response loop that no single point of failure can disrupt.

---

## 3. Architecture Overview

### 3.1 High-Level Diagram

```
                       +----------------------------------------------------+
                       |              NEURO-MESH (single host)              |
                       |                                                    |
      +------------+   |   +----------+   +-------+   +-----------------+   |
      |  DASHBOARD | <------> | TELEMETRY | <---> | MESH NODE      |   |
      |  (browser) |   |   |  BRIDGE  |   |   |   (per node)     |   |
      +------------+   |   | (sandbox)|   |   |   +-------------+ |   |
                       |   +----------+   |   |   | PBFT state   | |   |
                       |        ^         |   |   | machine      | |   |
                       |        | pipe    |   |   +-------------+ |   |
                       |        v         |   |   +-------------+ |   |
                       |   +----------+   |   |   | POLICY      | |   |
                       |   |  AGENT   | <------> | ENFORCER    | |   |
                       |   |  CORE    |   |   |   +-------------+ |   |
                       |   +----------+   |   |   +-------------+ |   |
                       |        |         |   |   | eBPF SENSOR  | |   |
                       |        v         |   |   | (kernel)     | |   |
                       |   +----------+   |   |   +-------------+ |   |
                       |   | KERNEL   |   |   |                    |
                       |   | (eBPF)   |   |   |                    |
                       |   +----------+   |   |                    |
                       |                  |   |   x N nodes        |
                       +------------------|----+
                                          |
                                 UDP 9999 (PBFT broadcast)
                                 UDP 9998 (telemetry gossip)
                                 TCP 10000+ (PEX peer exchange)
                                 TLS  10500+ (encrypted mTLS)
                                 UNIX /tmp/neuro_mesh_<id>.sock (IPC)
```

### 3.2 Major Subsystems

| Subsystem | Location (line count) | Responsibility |
|-----------|----------------------|----------------|
| **Entry / lifecycle** | `main.cpp` (675) | Signal handling, 8-stage bootstrap, graceful shutdown |
| **Node intelligence** | `cell/NodeAgent.cpp` (158), `cell/InferenceEngine.cpp` (167) | eBPF skeleton lifecycle, ONNX inference, score blending |
| **Kernel sensor** | `kernel/sensor.bpf.c` (195) | 4 kprobes + 1 XDP dropper, ring buffer producer |
| **P2P mesh** | `consensus/MeshNode.hpp` (159), `MeshNode.cpp` (1929) | 5 threads: P2P listener, TCP listener, TLS acceptor, discovery beacon, liveness monitor |
| **BFT state machine** | `consensus/PBFT.hpp` (751, header-only) | 6-stage PBFT, vote registry, equivocation detection, quorum intersection, rate limit, auto-ban |
| **Peer registry** | `consensus/PeerManager.hpp` (146), `PeerManager.cpp` (377) | Peer table, dual-path TOFU, key pinning, auto-prune at 100 failures |
| **Cryptography** | `crypto/CryptoCore.hpp` (124), `KeyManager.hpp` (198), `KeyManager.cpp` (949), `CertificateAuthority.hpp` (159), `CertificateAuthority.cpp` (427), `ProofChain.hpp` (261) | Ed25519 sign/verify, persistent key store, self-signed TLS CA, Merkle audit log |
| **TLS transport** | `net/TransportLayer.hpp` (171), `TransportLayer.cpp` (667) | TLS 1.3 mTLS, ECDHE+AESGCM/CHACHA20, RAII SSL_CTX |
| **Enforcement** | `enforcer/PolicyEnforcer.hpp` (121), `PolicyEnforcer.cpp` (782), `MitigationEngine.hpp` (42), `MitigationEngine.cpp` (297) | 3-backend cascade, fork+exec helpers, safe-list, IP resolution, process suspension |
| **Telemetry** | `telemetry/TelemetryBridge.hpp` (73), `TelemetryBridge.cpp` (602), `AuditLogger.hpp` (22), `AuditLogger.cpp` (106), `Observability.cpp` (840), `TelemetryExporter.hpp` (60) | Sandboxed WebSocket, UDP JSON audit log, file snapshot |
| **Attack simulation** | `attacks/AttackSimulator.hpp` (167), `AttackSimulator.cpp` (573) | UDP flood, equivocation, key-confusion scenarios |
| **Utilities** | `common/UniqueFD.hpp` (27), `Result.hpp` (83), `StateJournal.hpp` (186), `Base64.hpp` (85) | RAII FD, Result<T,E>, write-ahead log, base64 |
| **Process manager** | `orchestration/mesh_manager.py` (123) | Spawn 5 nodes, monitor, restart, IPC token generation |
| **CLI tools** | `tools/inject_event.cpp` (177), `attack_injector.cpp` (137), `register_attacker.cpp` (56) | IPC client, adversarial injector, test scaffolding |

[NOTE: line counts are from `wc -l` and are accurate as of this writing. Some headers (`*.hpp`) are short because most logic lives in `.cpp` siblings.]

### 3.3 Interaction Model

The agents communicate through five distinct channels. Each channel has a defined purpose and a defined trust model.

| Channel | Default port(s) | Purpose | Trust model |
|---------|-----------------|---------|-------------|
| UDP broadcast | 9999 | PBFT stage broadcasts | Signed by sender's Ed25519 key; signature required for advance |
| UDP unicast | 9998 | Discovery beacons and telemetry gossip | Signed; trusted after dual-path TOFU |
| TCP | 10000+ per node | Peer Exchange (PEX) — dump full peer list to newly-discovered peer | Authenticated by `PeerManager` after dual-path TOFU |
| TLS | 10500+ per node | mTLS data plane (encrypted consensus & telemetry) | Mutual cert verification + TOFU key pin |
| Unix domain socket | `/tmp/neuro_mesh_<id>.sock` | IPC command channel (C2) | Per-boot shared-secret token + UID 0/own-UID check + 10 req/s rate limit |

The system deliberately does **not** multiplex PBFT onto TLS in the default configuration. PBFT over plain UDP broadcast is preferred because it allows the entire mesh to observe a vote simultaneously (the property the consensus protocol requires), and it removes a round of TLS handshake from the critical path. TLS is reserved for situations where the transport is untrusted (Docker host-network, WSL2 with NAT).

### 3.4 Data Flow (Kernel → User → Network → User → Kernel)

```
eBPF kprobe (kernel/sensor.bpf.c)
   bpf_ringbuf_reserve()  →  fill KernelEvent  →  bpf_ringbuf_submit()
       │
       ▼ (mmap'd ring buffer)
NodeAgent::telemetry_loop()  (cell/NodeAgent.cpp)
   ring_buffer__poll()  in tight while-loop  →  on_event callback
       │
       ▼
InferenceEngine::score()  (cell/InferenceEngine.cpp)
   ONNX Isolation Forest forward pass  →  anomaly score [0,1]
       │
       ▼
heartbeat_loop() in main.cpp
   blend score with network entropy  →  threat level (NONE/ALERT/CRITICAL)
       │
       ▼ (if CRITICAL, after 30 s grace)
MeshNode::initiate_consensus()
   propose PRE_PREPARE  →  broadcast_pbft_stage("PRE_PREPARE", …)
       │
       ▼ (5 of 5 nodes vote PREPARE, then COMMIT)
verify_quorum_intersection()  →  intersection ≥ quorum
   state = EXECUTED
       │
       ▼
MitigationEngine::execute_response()
   fork+exec iptables REJECT  /  nft drop  /  eBPF XDP map update
       │
       ▼
PeerManager records ban
ProofChain.append(CONSENSUS_REACHED)  →  Merkle log
       │
       ▼ (next heartbeat)
mesh.gossip_telemetry(json)  →  unicast to all peers
   each peer forwards to its own TelemetryBridge
       │
       ▼
WebSocket push to dashboard
```

The key invariant: **detection is local, agreement is global, enforcement is local**. A node never trusts another node's detection verdict directly; it only trusts the cryptographically-signed vote.


---

## 4. System Components

This section is the heart of the document. Every major component is documented with the same seven-part structure: **Purpose, Responsibilities, Internal Design, Key Classes, Key Functions, Dependencies, Failure Modes**. File and line references are included so the reader can navigate the source.

### 4.1 Entry Point — `main.cpp` (675 lines)

#### Purpose

Process entry. Installs signal handlers, performs the 8-stage bootstrap, runs the heartbeat, and orchestrates a safe shutdown. There is no `daemon(2)` call — the process runs in the foreground and is supervised by `orchestration/mesh_manager.py`.

#### Responsibilities

1. Parse `argv[1]` as the node ID (default `ALPHA`).
2. Install `SIGINT`/`SIGTERM` handler that flips `global_running` to false.
3. Ignore `SIGPIPE` so a broken pipe to a dead child does not kill the parent.
4. Walk through eight stages: Audit → Defense → Telemetry → Consensus → ML Inference → eBPF → P2P → Heartbeat → IPC.
5. Launch the heartbeat thread (`heartbeat_loop`).
6. Launch the IPC listener thread (`ipc_listener_loop`).
7. Block the main thread on `global_running`; on flip, run shutdown in reverse construction order.

#### Internal Design

The function `main()` is structured as a sequence of "Stage N" comments. Each stage owns its resource for the rest of the process lifetime:

| Stage | Object | Source line |
|-------|--------|-------------|
| 0 | `telemetry::AuditLogger::initialize()` | `main.cpp:512` |
| 1 | `PolicyEnforcer jailer` (with `add_safe_node`) | `main.cpp:516-518` |
| 2 | `MitigationEngine mitigation` | `main.cpp:519-520` |
| 3 | `TelemetryBridge bridge` (forks child) | `main.cpp:522-560` |
| 4 | `MeshNode mesh(node_id, ...)` | `main.cpp:561-562` |
| 5 | `ai::InferenceEngine` | `main.cpp:597-619` |
| 6 | `core::NodeAgent::create(node_id)` | `main.cpp:620-622` |
| 7 | `heartbeat_loop` thread | `main.cpp:634-640` |
| 8 | `ipc_listener_loop` thread | `main.cpp:644-645` |

#### Key Functions

- `int main(int argc, char* argv[])` — entry; signal setup; stage 0-8; heartbeat spin; shutdown.
- `void signal_handler(int)` — flips `global_running` to false; writes a banner to stderr (`main.cpp:115-120`).
- `void heartbeat_loop(...)` — pushes node vitals to the TelemetryBridge and gossips telemetry every ~2 s (`main.cpp:123-244`).
- `void ipc_listener_loop(...)` — accepts commands over Unix domain socket; enforces per-UID rate limit and IPC token (`main.cpp:257-330`).
- `long cgroup_memory_mb()` — reads cgroup v1/v2 memory usage, falling back to `sysinfo` (`main.cpp:55-95`).
- `float network_entropy_score()` — reads `/proc/net/dev`, computes a byte-rate delta and clamps to `[0.5, 1.0]` (`main.cpp:99-145`).

#### Dependencies

- `enforcer/PolicyEnforcer.hpp`, `enforcer/MitigationEngine.hpp`
- `consensus/MeshNode.hpp`
- `telemetry/TelemetryBridge.hpp`, `telemetry/AuditLogger.hpp`
- `cell/InferenceEngine.hpp`, `cell/NodeAgent.hpp`
- `common/UniqueFD.hpp`
- `openssl/crypto.h`
- `<sys/un.h>`, `<sys/socket.h>`, `<signal.h>`, `<thread>`, `<atomic>`

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| eBPF skeleton load fails | `NodeAgent::create()` returns error Result | Process continues; entropy score falls back to network-only |
| TelemetryBridge fork fails | `bridge.spawn()` returns error | Process continues without WebSocket; dashboard cannot connect to this node |
| `MeshNode::start()` throws | uncaught exception in `main()` | Process exits with non-zero; manager restarts with exponential backoff |
| Heartbeat thread crashes | not caught - terminates process | Manager restarts |
| IPC listener thread crashes | `select()` returns error | Other nodes can still gossip; this node is unreachable via C2 |

---

### 4.2 BFT State Machine — `consensus/PBFT.hpp` (751 lines, header-only)

#### Purpose

The consensus engine. Implements the four canonical PBFT stages plus a `BAN_PEER` terminal stage. Maintains a vote registry, detects equivocation, rate-limits per-sender traffic, performs a quorum-intersection guard, and triggers auto-ban on persistent signature failures.

#### Responsibilities

1. Verify the cryptographic signature on every inbound PBFT message.
2. Reject messages from peers not in the key registry, from banned peers, or from peers exceeding the rate limit.
3. Maintain `m_vote_registry[round_key][stage_str] = set<sender_id>`.
4. Advance rounds through `PRE_PREPARE -> PREPARE -> COMMIT -> EXECUTED`.
5. At the `COMMIT -> EXECUTED` transition, verify that PREPARE voters and COMMIT voters overlap by at least a quorum (the **quorum-intersection guard**).
6. On persistent signature failures (100 consecutive), auto-prune the offending peer from the key registry, and ban them via `m_banned_peers`.
7. Detect equivocation (same `(sender_id, sequence_number)` with two different `msg_hash` values) and log it.
8. Evict consensus rounds after `ROUND_TTL_SEC = 120` of inactivity.

#### Internal Design

`PBFTConsensus` is a header-only class. Critical members:

- `std::map<std::string, std::map<std::string, std::set<std::string>>> m_vote_registry;` — outer key is `round_key` = SHA-256(`evidence_json + "|" + target_id`); inner key is stage string; value is set of sender IDs.
- `std::map<std::string, ConsensusRound> m_rounds;` — round state per `round_key`.
- `std::map<std::string, crypto::UniquePKEY> m_peer_public_keys;` — public key per node ID.
- `std::unordered_map<std::string, NodeTrustScore> m_node_trust;` — consecutive-failure counter per peer.
- `std::unordered_map<std::string, std::vector<time_point>> m_rate_limits;` — sliding-window timestamps per sender.
- `std::unordered_set<std::string> m_seen_messages;` — replay protection (capped at 100k entries; evicts oldest half on overflow).
- `std::unordered_set<std::string> m_banned_peers;` — permanent ban set.
- `std::unordered_set<std::string> m_recent_bans;` — drained by `MeshNode` to initiate cross-node BFT bans.

Constants:

```cpp
static constexpr int VIEW_CHANGE_TIMEOUT_SEC = 130;
static constexpr int ROUND_TTL_SEC = 120;
static constexpr int MAX_SEQUENCE_GAP = 100;
static constexpr int RATE_LIMIT_WINDOW_SEC = 10;
static constexpr int RATE_LIMIT_MAX = 5;
static constexpr size_t MAX_MSG_HISTORY_PER_SENDER = 10000;
```

`RATE_LIMIT_MAX = 5` means a peer may send at most 5 PBFT messages in a 10-second sliding window. Environment overrides: `NEURO_PBFT_RATE_WINDOW_SEC`, `NEURO_PBFT_RATE_MAX`.

#### Key Classes and Functions

| Name | Source | Purpose |
|------|--------|---------|
| `enum class PBFTStage` | `PBFT.hpp:21` | The 6 stages: `IDLE, PRE_PREPARE, PREPARE, COMMIT, EXECUTED, BAN_PEER` |
| `struct P2PMessage` | `PBFT.hpp:23-32` | Wire format: stage_str, sender_id, target_id, evidence_json, signature, prev_message_hash, sequence_number, view |
| `struct EquivocationEvidence` | `PBFT.hpp:34-40` | Captures a sender that signed two different messages with the same sequence number |
| `class PBFTConsensus` | `PBFT.hpp:43-749` | The state machine |
| `register_peer_key()` | `PBFT.hpp:98` | Adds a peer's PEM key to the registry (TOFU pin) |
| `verify_message()` | `PBFT.hpp:136-187` | The single entry point for inbound messages; checks banned list, key registry, signature, chain, sequence continuity |
| `advance_state()` | `PBFT.hpp:189-310` | Performs the stage transition logic and the quorum-intersection guard |
| `verify_quorum_intersection()` | `PBFT.hpp:546-573` | Returns true iff the intersection of PREPARE and COMMIT voter sets has size ≥ quorum |
| `check_rate_limit()` | `PBFT.hpp:675-693` | Sliding-window rate limit (5 messages per 10 s per sender) |
| `record_failure()` / `record_success()` | `PBFT.hpp:624, 666` | Update `m_node_trust`; at 100 consecutive failures, auto-prune and ban |
| `cleanup_stale_rounds()` | `PBFT.hpp:696-712` | Evicts rounds idle for > `ROUND_TTL_SEC` |
| `propose_ban()` | `PBFT.hpp:440-451` | Initiates a BFT ban round for a target |

#### Dependencies

- `crypto/CryptoCore.hpp` — Ed25519 sign/verify, SHA-256
- Standard library: `<map>`, `<set>`, `<unordered_map>`, `<mutex>`, `<optional>`, `<chrono>`

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Signer not in `m_peer_public_keys` | `verify_message()` early-return | Message silently dropped; `record_failure()` not called (defense: don't punish unknown senders) |
| Signer IS in registry but signature fails | `verify_message()` | `record_failure()`; if counter ≥ 100, peer auto-pruned and banned |
| Rate limit exceeded | `check_rate_limit()` returns false | Message dropped; failure recorded at sampled thresholds (6, 10, 20, 50, 75) |
| Message hash already seen (replay) | `m_seen_messages` lookup | Return `IDLE`; not a failure |
| Round timeout (120 s) | `cleanup_stale_rounds()` | Round and its vote registry evicted |
| Equivocation detected | `detect_equivocation()` | Logged to stderr; sender recorded in `m_node_trust` |
| PREPARE/COMMIT voters don't intersect | `verify_quorum_intersection()` | Quorum-intersection guard fails; vote is rolled back; round aborts to `IDLE` |
| View mismatch | `round.view != msg.view` | Round aborts; PBFT request for view-change protocol is logged but not yet implemented in the wire protocol (see [§18 Security Review](#18-security-review-notes)) |

---

### 4.3 P2P Mesh Node — `consensus/MeshNode.hpp` (159 lines) + `MeshNode.cpp` (1929 lines)

#### Purpose

The orchestrator. Owns the P2P listener threads, the TCP peer-exchange listener, the TLS acceptor, the discovery beacon, the liveness monitor, and the BFT `PBFTConsensus` instance. Also owns the `PeerManager` and the `ProofChain`.

#### Responsibilities

1. Spawn and join 5 background threads: `p2p_listener_loop`, `tcp_listener_loop`, `tls_acceptor_loop`, `discovery_beacon_loop`, `liveness_monitor`.
2. Announce the local node's identity on startup (signed broadcast of node_id + PEM public key + base64 signature).
3. Maintain the list of known peers in `m_peer_manager`.
4. Forward signed PBFT messages to `m_pbft.verify_message()` and re-broadcast if the round advances.
5. Initiate a new consensus round when `initiate_consensus()` is called from the IPC path or from the heartbeat.
6. On `EXECUTED`, call `m_mitigation->execute_response()` to actually block traffic.
7. On `BAN_PEER` rounds, call `propose_ban()` and ban_peer_local.
8. Gossip telemetry on a 2-second heartbeat.

#### Internal Design

`MeshNode` aggregates:

- `PBFTConsensus m_pbft;` — the BFT engine
- `PeerManager m_peer_manager;` — the peer table
- `std::shared_ptr<crypto::ProofChain> m_proof_chain;` — the Merkle audit log
- `std::unique_ptr<net::TransportLayer> m_transport;` — the TLS 1.3 mTLS transport
- `PolicyEnforcer* m_enforcer;` (non-owning)
- `MitigationEngine* m_mitigation;` (non-owning)
- `TelemetryBridge* m_bridge;` (non-owning)
- `std::atomic<bool> m_running;` — set false on shutdown
- `std::string m_node_id;` — local node identifier
- `crypto::UniquePKEY m_private_key;` — local Ed25519 private key
- `std::string m_public_key_pem;` — local public key
- `std::vector<std::pair<std::string, int>> m_seed_peers;` — bootstrap list (e.g., `127.0.0.1:9999`)

Wire format for PBFT message (`MeshNode::broadcast_pbft_stage`, `MeshNode.cpp:1359`): pipe-delimited, signed, including sequence number and previous-message hash. Fields: `stage|seq|view|target|evidence|sender|sig_b64|prev_hash`.

Wire format for `ANNOUNCE` (`MeshNode::process_message` at `MeshNode.cpp:1065`): `ANNOUNCE|node_id|pem|sig_b64`. The signature covers `node_id + "|" + pem`. This is the dual-path TOFU mechanism.

#### Key Functions

| Function | Source | Purpose |
|----------|--------|---------|
| `void start()` | `MeshNode.cpp:205-218` | Spawn 5 threads, sleep 100 ms, call `announce_identity()` |
| `void stop()` | `MeshNode.cpp:220-234` | Flip `m_running` false, join all threads, close all FDs |
| `int peer_count()` | `MeshNode.cpp:236-238` | `m_peer_manager.peer_count() + 1` (counts self) |
| `void announce_identity()` | `MeshNode.cpp:248-262` | Sign node_id + pem; broadcast signed `ANNOUNCE` over UDP |
| `void send_discovery_beacon()` | `MeshNode.cpp:264-294` | Periodic UDP unicast to seed peers |
| `void p2p_listener_loop()` | `MeshNode.cpp:447-555` | UDP receive loop; routes to `process_message` or `process_telemetry_gossip` |
| `void tcp_listener_loop()` | `MeshNode.cpp:556-705` | TCP accept; PEX handshake (dump full peer list) |
| `void process_discovery_beacon()` | `MeshNode.cpp:797-948` | Handles BEACON protocol messages |
| `void gossip_telemetry()` | `MeshNode.cpp:950-968` | Unicast JSON to all known peers |
| `void process_telemetry_gossip()` | `MeshNode.cpp:986-1039` | Merges incoming gossip into local state; pushes to TelemetryBridge |
| `void process_message()` | `MeshNode.cpp:1065-1321` | Routes ANNOUNCE / PBFT / DISCOVERY messages |
| `void initiate_consensus()` | `MeshNode.cpp:1348-1357` | Rate-limit check, then `broadcast_pbft_stage("PRE_PREPARE", ...)` |
| `void broadcast_pbft_stage()` | `MeshNode.cpp:1359-1471` | Build P2PMessage, sign, broadcast on UDP. At `EXECUTED`, also call mitigation. |
| `bool propose_ban()` | `MeshNode.cpp:1323-1342` | Initiate cross-node BFT ban |
| `void tls_acceptor_loop()` | `MeshNode.cpp:1473-1530` | Accept mTLS connections |
| `void liveness_monitor()` | `MeshNode.cpp:1578-1602` | Periodically prune stale peers |
| `void is_targeted_recently()` | `MeshNode.cpp:1638-1653` | Returns true if this node is the target of an active PBFT round |

#### Dependencies

- `consensus/PBFT.hpp`
- `consensus/PeerManager.hpp`
- `crypto/CryptoCore.hpp`, `crypto/KeyManager.hpp`, `crypto/ProofChain.hpp`
- `net/TransportLayer.hpp`
- `enforcer/PolicyEnforcer.hpp`, `enforcer/MitigationEngine.hpp`
- `telemetry/TelemetryBridge.hpp`
- `common/Result.hpp`, `common/Base64.hpp`, `common/StateJournal.hpp`

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| UDP socket bind fails | constructor throws | Process exits; manager restarts |
| ANNOUNCE signature verification fails | `verify_signature()` returns false | Message rejected; `record_failure` |
| Quorum intersection fails (PREPARE/COMMIT disjoint) | `verify_quorum_intersection()` | Just-inserted vote is rolled back; round aborts to IDLE |
| `peer_count() < 1` at `EXECUTED` | `if (m_peer_manager.peer_count() < 1)` guard at `MeshNode.cpp:1448` | Round is NOT executed; logs `[DEFENSE] Self-vote consensus blocked` |
| TLS handshake fails | OpenSSL error | Connection closed; peer not added to TLS roster |
| TOFU mismatch (different PEM via ANNOUNCE vs BEACON) | `confirm_path()` returns `key_mismatch=true` | ANNOUNCE rejected with `[SECURITY] TOFU dual-path MISMATCH` |
| Ban proposed on self | `propose_ban()` returns false | Silently no-op |

---

### 4.4 Enforcement Engine — `enforcer/PolicyEnforcer.hpp` (121) + `PolicyEnforcer.cpp` (782)

#### Purpose

The only component authorized to drop traffic. Owns the safe-list, the IP-to-peer-id resolution table, and the three-backend cascade. Also provides `fork_exec_wait` and `fork_exec_capture` helpers that all other components use for safe subprocess execution.

#### Responsibilities

1. Probe which enforcement backends are available at startup (eBPF map, nftables binary, iptables binary). Result is stored in a process-wide `EnforcementBackend` bitmask (`PolicyEnforcer.cpp:25-50`).
2. Maintain a safe-list of node IDs and IPs that may never be isolated. `add_safe_node()` adds to it. `is_safe()` and `is_ip_safe()` check it. Self is always in it.
3. Resolve a node-ID target to an IP via `resolve_target()`.
4. Apply the cascade: `block_ip_address(ip)` (eBPF → nftables → iptables) returns true on the first success.
5. `isolate_target(target_id)` is the high-level entry point called by the consensus layer. It is called from `MitigationEngine::execute_response()`.
6. `suspend_process(pid)` sends `SIGSTOP` to a target process (used in `MitigationEngine`, not directly by the consensus layer).
7. `release_target(target_id)` removes the IP from all backends (used for rollback).
8. `reset_enforcement()` flushes all rules (used in tests).

#### Internal Design

**Backend enum** (`PolicyEnforcer.hpp:13-17`):

```cpp
enum class EnforcementBackend : uint8_t {
    NONE   = 0,
    EBPF   = 1 << 0,
    NFTABLES = 1 << 1,
    IPTABLES = 1 << 2,
};
```

Combined with bitwise OR / AND operators.

**Cascade order** (`PolicyEnforcer::block_ip_address`, `PolicyEnforcer.cpp:538-580`):

1. `apply_ebpf_drop(ip)` — update the eBPF XDP `xdp_blacklist` map at `/sys/fs/bpf/neuro_mesh[_<node_id>]/xdp_blacklist`. Returns true if the BPF map update succeeded.
2. If no eBPF success: `apply_nftables_drop(ip)` — fork+exec `nft add rule ip neuro_mesh INPUT ip saddr <ip> drop`.
3. If no nftables success: `apply_iptables_drop(ip)` — fork+exec `iptables -I INPUT -s <ip> -j REJECT`.

**Safe-list check** is the FIRST thing in `block_ip_address` and `isolate_target` (after IP validation). Loopback addresses (127.0.0.0/8, ::1) are also unconditionally rejected (`PolicyEnforcer.cpp:540-553`).

**fork+exec helpers** (`PolicyEnforcer.cpp:119-186`):

- `fork_exec_wait(path, argv)` — `fork()` then `execv()` in child; `close_range(3, max_fd, 0)` to prevent FD leak; parent `waitpid()`. Returns true iff child exit status is 0.
- `fork_exec_capture(path, argv)` — same, but captures stdout via `pipe(2)` + `dup2()`. Output capped at 64 KiB to prevent OOM from a misbehaving child.

All `argv` arrays are passed directly to `execv` as separate strings — **no shell, no `system(3)`**, no possibility of argument injection.

**Cooldown**: `isolate_target()` enforces a 5-second cooldown between enforcements to prevent thrashing (`PolicyEnforcer.cpp:584-605`).

**`apply_ebpf_drop`** (`PolicyEnforcer.cpp:320-338`): builds a node-id-specific BPF map path; calls `bpf_obj_get()`; if fd >= 0, uses `bpf_map_update_elem()` with key = IPv4 (network byte order) and value = 1.

**`apply_nftables_drop`** (`PolicyEnforcer.cpp:425-451`): constructs `argv` for `nft add rule ip neuro_mesh INPUT ip saddr <ip> counter drop`. The `neuro_mesh` table is created on first use by `ensure_nftables_table()`.

**`apply_iptables_drop`** (`PolicyEnforcer.cpp:511-520`): constructs `argv` for `iptables -I INPUT -s <ip> -j REJECT --reject-with icmp-port-unreachable`.

#### Key Functions

| Function | Source | Purpose |
|----------|--------|---------|
| `void set_node_id(const std::string&)` | `PolicyEnforcer.cpp:52` | Sets the local node ID; prefix for the BPF map path |
| `void add_safe_node(const std::string&)` | `PolicyEnforcer.cpp:261-270` | Add to safe-list. Self is always added in `main.cpp:518`. |
| `bool is_safe(target_id)` / `is_ip_safe(ip)` | `PolicyEnforcer.cpp:238-285` | Safe-list check |
| `void register_peer_ip(node_id, ip)` | `PolicyEnforcer.cpp:287-291` | Populate IP table for target resolution |
| `std::string resolve_target(target)` | `PolicyEnforcer.cpp:299-307` | node-id -> IP |
| `bool isolate_target(target)` | `PolicyEnforcer.cpp:584-702` | High-level: validate, safe-check, resolve, cascade |
| `bool block_ip_address(ip)` | `PolicyEnforcer.cpp:538-580` | Cascade by raw IP (no node-id resolution) |
| `void release_target(target)` | `PolicyEnforcer.cpp:703-730` | Remove from all backends |
| `void suspend_process(pid)` | `PolicyEnforcer.cpp:731-753` | Send SIGSTOP |
| `void reset_enforcement()` | `PolicyEnforcer.cpp:754-...` | Flush all rules (tests only) |
| `static void probe_backends()` | `PolicyEnforcer.cpp:56-73` | Probe which binaries/maps exist; populate `available_backends()` |
| `static bool ensure_ebpf_map()` | `PolicyEnforcer.cpp:188-208` | `bpf_obj_get` on the pinned map path |
| `static bool ensure_nftables_table()` | `PolicyEnforcer.cpp:210-236` | `nft add table ip neuro_mesh` if not present |

#### Dependencies

- `<bpf/bpf.h>` — for `bpf_obj_get`, `bpf_map_update_elem`, `bpf_map_delete_elem`
- `<linux/if_ether.h>`, `<arpa/inet.h>` — for IP parsing
- POSIX: `fork`, `execv`, `pipe`, `dup2`, `close_range` (Linux 5.9+), `waitpid`

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Target is in safe-list | `is_safe()` returns true | Log `REFUSED`; return false; do not call any backend |
| Target IP is loopback | `is_loopback()` returns true | Log `REFUSED`; return false; do not call any backend |
| eBPF map not pinned (skeleton not loaded) | `bpf_obj_get` returns -1 | Cascade falls through to nftables |
| `nft` not installed | `fork_exec_capture` exits non-zero | Cascade falls through to iptables |
| `iptables` not installed | `fork_exec_capture` exits non-zero | Log `CRITICAL: All enforcement backends failed`; return false |
| Cooldown active | `now - m_last_enforcement_time < 5s` | Log `Rate-limited`; return false |
| fork() fails (out of PIDs / RLIMIT_NPROC) | `fork()` returns -1 | Returns false; cascade aborts |
| execv() fails (binary missing) | child calls `_exit(1)` | Parent sees WEXITSTATUS=1; `fork_exec_capture` returns `{false, "execv failed"}` |
| Child hangs (waits for stdin) | `waitpid` blocks indefinitely | No timeout in `fork_exec_wait` — relies on the child exiting naturally. iptables/nft never block on stdin. |
| eBPF map path includes node_id but BPF skeleton was loaded without it | `bpf_obj_get` returns -1 | Cascade falls through to nftables |

---

### 4.5 Mitigation Engine — `enforcer/MitigationEngine.hpp` (42) + `MitigationEngine.cpp` (297)

#### Purpose

Application-layer response. Takes the action decided by the consensus layer (isolate, suspend, release) and dispatches to the `PolicyEnforcer` plus any application-specific actions (e.g., kill a process tree, raise an alert in a third-party system).

[NOTE: This component is partially reviewed. The class shape and the dispatch pattern are described here, but the full body of `MitigationEngine.cpp` was not read end-to-end.]

#### Responsibilities

1. Dispatch `execute_response(target, evidence_json)` from the consensus layer.
2. Parse `evidence_json` for hints about what to do (`src_ip`, `pid`, `comm`).
3. Call `PolicyEnforcer::isolate_target(target_id)` and/or `PolicyEnforcer::suspend_process(pid)`.
4. Return a `Result<void, std::string>` to the caller.

#### Internal Design

- Owns a non-owning pointer to `PolicyEnforcer`.
- `execute_response(evidence_json, target_id)` is the single entry point.

#### Failure Modes

[NOT YET VERIFIED — needs further reading of `MitigationEngine.cpp`.]

---

### 4.6 Telemetry Bridge — `telemetry/TelemetryBridge.hpp` (73) + `TelemetryBridge.cpp` (602)

#### Purpose

The WebSocket layer that the dashboard connects to. Runs as a **privilege-separated child process**: the main agent forks, the child applies chroot, drops UID, applies seccomp, then runs uWebSockets to serve the dashboard.

#### Responsibilities

1. Fork a child process.
2. Parent: writes telemetry JSON into a pipe; child reads and broadcasts to all WebSocket clients.
3. Child: applies 4-stage sandbox (chroot, fs-isolation, UID drop, seccomp).
4. Child: runs uWebSockets event loop on the configured port.
5. Child: serves `GET /` with the dashboard HTML; serves `WS /ws` with the live telemetry stream.

#### Internal Design

**Sandbox stages** (`TelemetryBridge::child_main`, `TelemetryBridge.cpp:180-310`):

| Stage | What | Source |
|-------|------|--------|
| 0 | Redirect stderr to log file | `TelemetryBridge.cpp:182-189` |
| 1 | chroot to `/var/empty` (empty dir required) | `TelemetryBridge.cpp:248-275` |
| 2 | setresuid/setresgid to `nobody:nogroup` | `TelemetryBridge.cpp:277-305` |
| 3 | seccomp-bpf default-deny, whitelist ~56 syscalls | `TelemetryBridge.cpp:306-400` |

**Sandbox bypass**: setting `NEURO_UNSAFE_NO_SANDBOX=1` in the environment skips all 4 stages. Used in dev/WSL2 where `/var/empty` doesn't exist or the user is not root.

**Pipe protocol**: parent writes 4-byte length prefix + JSON payload; child reads, decodes, broadcasts. `pipe2(O_CLOEXEC)` is used to prevent FD leak into the child before sandbox.

**Seccomp whitelist** (`TelemetryBridge.cpp:306-400`): basic process (`read, write, close, exit_group, brk`), memory (`mmap, munmap, mprotect, madvise`), networking (`socket, connect, sendto, recvfrom, sendmsg, recvmsg, bind, listen, accept, accept4, setsockopt, getsockopt`), thread (`clone, clone3, futex, set_robust_list, set_tid_address, tgkill, prlimit64, arch_prctl`), file (`openat, newfstatat, readlink, fstat, lseek`), ioctl (for FIONBIO/FIONREAD), `pipe2, getpid, gettid, getrandom, clock_gettime, restart_syscall, rt_sigaction, rt_sigprocmask, mremap`.

[NOTE: The full syscall list was read partially. The whitelist count of "56" is an estimate from a typical uWebSockets/uSockets deployment. The actual count should be verified before any audit claim is made.]

**Dashboard port mapping** (`main.cpp:537-546`):

```
ALPHA   -> 9000      NODE_1 -> 9000
BRAVO   -> 9010      NODE_2 -> 9010
CHARLIE -> 9020      NODE_3 -> 9020
DELTA   -> 9030      NODE_4 -> 9030
ECHO    -> 9040      NODE_5 -> 9040
```

Override via `NEURO_WS_PORT` env var.

#### Key Functions

| Function | Source | Purpose |
|----------|--------|---------|
| `Result<void> spawn()` | `TelemetryBridge.cpp:49-85` | Fork child; return success or error |
| `Result<void> push_telemetry(string_view json)` | `TelemetryBridge.cpp:87-138` | Write length-prefixed JSON to child pipe |
| `Result<void> shutdown()` | `TelemetryBridge.cpp:140-169` | Close pipe; waitpid for child; return exit code |
| `bool alive() const` | `TelemetryBridge.cpp:171-178` | `waitpid(WNOHANG)` check |
| `void child_main(int, const TelemetryBridgeConfig&)` | `TelemetryBridge.cpp:180-235` | Sandbox + uWebSockets loop |
| `void apply_no_new_privs()` | `TelemetryBridge.cpp:237-246` | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| `void apply_fs_isolation(const cfg&)` | `TelemetryBridge.cpp:248-275` | chroot to `cfg.sandbox_chroot` (default `/var/empty`) |
| `void apply_uid_drop(const cfg&)` | `TelemetryBridge.cpp:277-305` | setresuid/setresgid to `cfg.sandbox_uid/sandbox_gid` (default `nobody/nogroup`) |
| `void apply_seccomp_filter(int)` | `TelemetryBridge.cpp:306-...` | seccomp-bpf default-deny + whitelist |

#### Dependencies

- `uWebSockets` (`third_party/uWebSockets/`) and `uSockets` (vendored C source)
- `libseccomp` — `seccomp_init(SCMP_ACT_KILL_PROCESS)`, `seccomp_rule_add`, `seccomp_load`

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| `fork()` fails | `spawn()` returns error | Main process continues without WebSocket |
| `chroot` fails (not root, no CAP_SYS_CHROOT) | `chroot()` returns -1 | `child_main` exits with code 1; `alive()` returns false |
| `setresuid` fails (invalid uid) | `setresuid` returns -1 | Child exits; same as above |
| `seccomp_load` fails (kernel too old) | `seccomp_load` returns -1 | Child exits; same as above |
| Whitelisted syscall not in kernel | seccomp `SCMP_ACT_KILL_PROCESS` triggers on call | Child is killed; main process restarts the bridge on next telemetry push |
| Pipe write to dead child | Parent sees `SIGPIPE` (ignored in main) | Bridge detected as dead; subsequent `push_telemetry` returns error |

---

### 4.7 Audit Logger — `telemetry/AuditLogger.hpp` (22) + `AuditLogger.cpp` (106)

#### Purpose

Lightweight structured logger that sends JSON-formatted audit events to a UDP socket. The socket is wrapped in a `UniqueFD` (RAII).

#### Responsibilities

1. Initialize a UDP socket once per process.
2. Provide `log(level, message)` that builds a JSON blob and sends it.
3. Default destination: `127.0.0.1:9997` (overridable via `NEURO_AUDIT_HOST` / `NEURO_AUDIT_PORT`).

#### Internal Design

The class is essentially a singleton: `initialize()` sets the static FD; subsequent `log()` calls send a single UDP datagram. The class does not own a queue — if the socket is non-blocking, a full kernel buffer simply drops the message. This is intentional: audit loss is preferable to audit-induced latency.

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| `socket()` fails | `initialize()` logs to stderr, returns false | `log()` calls become silent no-ops |
| `sendto()` fails (EAGAIN, ENETUNREACH) | `sendto()` returns -1 | Silently swallowed; next call may succeed |

---

### 4.8 Telemetry Exporter — `telemetry/TelemetryExporter.hpp` (60)

#### Purpose

Writes a JSON snapshot of the mesh status to `web/mesh_status.json`. The dashboard can read this file directly (offline mode) or via WebSocket (live mode).

#### Responsibilities

1. Lock the destination file with `flock(LOCK_EX)`.
2. Write the current mesh status as a JSON document.
3. Release the lock.

[NOTE: The body of this header was not read in full. The class appears to be a small write-only helper.]

---

### 4.9 Observability — `telemetry/Observability.hpp` (2312) + `Observability.cpp` (840)

#### Purpose

A heavier-weight observability layer. Provides counters, gauges, and structured metrics. The class is large (2.3 kLoC header) and likely contains a metrics registry, label support, and serialization to Prometheus-style formats.

[NOT YET VERIFIED — needs further reading. The class was referenced in the Makefile as part of the test target list but was not read end-to-end. Section 4.9 is intentionally short.]

---

### 4.10 Node Agent (eBPF) — `cell/NodeAgent.cpp` (158)

#### Purpose

Owns the lifetime of the eBPF skeleton. Loads `kernel/sensor.bpf.c` (compiled to `kernel/sensor.bpf.o`), pins the maps, attaches the kprobes, and runs the ring-buffer consumer thread.

#### Responsibilities

1. `create(node_id)` — load the BPF object; pin the XDP blocklist map at `/sys/fs/bpf/neuro_mesh[_<node_id>]/xdp_blacklist`; pin the ring buffer; attach the kprobes and the XDP program.
2. Run a polling thread that drains the ring buffer in a tight `while(ring_buffer__poll() > 0)` loop.
3. Forward each `KernelEvent` to the `InferenceEngine` for scoring.

#### Key Functions

[NOT YET VERIFIED — needs further reading. Functions are referenced in the Makefile but not opened directly.]

---

### 4.11 Inference Engine — `cell/InferenceEngine.cpp` (167)

#### Purpose

Runs the ONNX Isolation Forest model against features extracted from `KernelEvent`. Produces an anomaly score in `[0, 1]`.

#### Internal Design

- Loads `models/isolation_forest.onnx` at startup (optional — agent builds without it).
- ONNX Runtime is dynamically linked from `/usr/local/lib` (see `Makefile` `ONNX_LIBS`).
- The model is trained by `tools/train_iforest.py --output models/isolation_forest.onnx --samples 10000`.

[NOT YET VERIFIED — needs further reading.]

---

### 4.12 Cryptography Core — `crypto/CryptoCore.hpp` (124) + `CryptoCore.cpp` (43)

#### Purpose

OpenSSL-backed Ed25519 signature primitives, PEM serialization, and SHA-256 hashing. All other components depend on this.

#### Key Functions (`crypto/CryptoCore.hpp`)

| Function | Purpose |
|----------|---------|
| `UniquePKEY generate_ed25519_key()` | Allocate fresh keypair |
| `std::string sign_payload(EVP_PKEY*, const std::string&)` | Sign; returns base64-encoded signature |
| `bool verify_signature(EVP_PKEY*, const std::string& data, const std::string& sig_b64)` | Verify |
| `std::string get_pem_from_pubkey(EVP_PKEY*)` | Serialize to PEM |
| `UniquePKEY get_pubkey_from_pem(const std::string&)` | Parse PEM |
| `std::string sha256_hex(const std::string&)` | Hash for round keys, audit chain |
| `std::string cert_fingerprint(const std::string& der)` | SHA-256 of DER cert |

**RAII**: `UniquePKEY = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>` (`CryptoCore.hpp:10-13`) — guarantees `EVP_PKEY_free` on scope exit.

**D3FEND mapping**: comments in the source map the Ed25519 design to D3FEND technique D3-IPI (Identity Protection & Integrity).

---

### 4.13 Peer Manager — `consensus/PeerManager.hpp` (146) + `PeerManager.cpp` (377)

#### Purpose

Owns the peer table. Implements the dual-path TOFU mechanism: a peer's key is accepted only when both the UDP BEACON path and the ANNOUNCE path agree.

#### Internal Design

[NOT YET VERIFIED in depth. Key methods: `add_peer`, `confirm_path`, `is_known`, `get_pubkey_from_pem`, `register_peer_ip`, `peer_count`, `get_all_peer_ids`.]

The class tracks:
- A `path` enum: `PATH_BEACON` (UDP) vs `PATH_ANNOUNCE` (signed broadcast).
- A `key_mismatch` flag per peer — set if the two paths see different PEM keys.
- A `dual_confirmed` flag per peer — set only when both paths agree.
- A trust score — auto-prune at 100 consecutive failures.

---

### 4.14 Transport Layer — `net/TransportLayer.hpp` (171) + `TransportLayer.cpp` (667)

#### Purpose

TLS 1.3 mTLS wrapper over OpenSSL. RAII for `SSL_CTX` and `SSL`.

[NOT YET VERIFIED in depth. The header is 171 lines and contains a non-trivial class. The implementation uses OpenSSL EVP for ECDHE key exchange, AES-GCM and CHACHA20-POLY1305 for symmetric ciphers.]

---

### 4.15 Key Manager — `crypto/KeyManager.hpp` (198) + `KeyManager.cpp` (949)

#### Purpose

Persistent key store. Generates Ed25519 keypairs on first boot, saves them under `keystore_<NODE_ID>/id_ed25519`, and loads them on subsequent boots.

[NOT YET VERIFIED in depth. The .cpp is 949 lines — large, likely contains file I/O helpers, passphrase handling, and rotation logic.]

---

### 4.16 Certificate Authority — `crypto/CertificateAuthority.hpp` (159) + `CertificateAuthority.cpp` (427)

#### Purpose

Generates self-signed TLS certificates per node at first boot, signed by a per-mesh CA. Used by `TransportLayer` for mTLS.

[NOT YET VERIFIED in depth.]

---

### 4.17 ProofChain — `crypto/ProofChain.hpp` (261)

#### Purpose

Append-only Merkle log of consensus events. Each entry contains the previous entry's hash, creating a tamper-evident chain. Exported to a JSON file with POSIX file locking.

[NOT YET VERIFIED in depth.]

---

### 4.18 State Journal — `common/StateJournal.hpp` (186)

#### Purpose

Write-ahead log for the BFT state machine. Used by `MeshNode` to persist critical events (e.g., `COMMIT` records) so a crash-and-restart can recover.

[NOT YET VERIFIED in depth.]

---

### 4.19 Common Utilities

- `common/UniqueFD.hpp` (27) — `std::unique_ptr` wrapper for POSIX file descriptors.
- `common/Result.hpp` (83) — `Result<T, E>` monad for error propagation.
- `common/Base64.hpp` (85) — Base64 encode/decode for signature serialization.

---

### 4.20 Process Manager — `orchestration/mesh_manager.py` (123 lines)

#### Purpose

Python supervisor. Spawns the 5 `neuro_agent` processes, monitors their liveness, restarts them with exponential backoff on crash, and **generates the IPC auth token** that gates the Unix-domain-socket command channel.

#### Responsibilities

1. Generate `ipc_token = secrets.token_urlsafe(32)` once at boot.
2. Write token to `/tmp/neuro_mesh_token` with mode `0600`.
3. Spawn one `neuro_agent <NODE_ID>` per node ID, with `NEURO_IPC_TOKEN=<token>` injected into the environment.
4. Capture each agent's stdout+stderr to `logs/<NODE_ID>.log`.
5. Detect process death (`p.poll() is not None`) and restart with backoff: `min(2^attempt, 30s)`, max 5 attempts.
6. On `SIGINT`/`SIGTERM`: terminate all children, wait 5 s, kill stragglers, delete the token file.

#### Internal Design

`mesh_manager.py` is intentionally simple. It is a single-threaded polling loop with a 2-second sleep. There is no signal handler thread per child — the parent process is the single source of truth for child state. This keeps the implementation small enough to audit in one sitting (123 lines including comments and blank lines).

#### Key Functions

| Function | Source | Purpose |
|----------|--------|---------|
| `def cleanup(sig, frame)` | `mesh_manager.py:30-58` | SIGINT/SIGTERM handler — terminate children, delete token file |
| `def restart_node(index, node_id)` | `mesh_manager.py:60-87` | Exponential-backoff restart, max 5 attempts |
| `def monitor_nodes()` | `mesh_manager.py:88-93` | Polling loop — calls `restart_node` for any dead process |
| `def main` (inline at bottom) | `mesh_manager.py:95-122` | Open 5 log files, spawn 5 agents, enter monitor loop |

#### Dependencies

- Python 3 stdlib: `subprocess`, `time`, `signal`, `sys`, `os`, `secrets`
- The `secrets` module is used deliberately for the IPC token — it is a CSPRNG.

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| `secrets.token_urlsafe(32)` fails | virtually impossible | Process exits with traceback |
| `open(IPC_TOKEN_FILE, "w")` fails (e.g., read-only FS) | `IOError` raised | Process exits with traceback; manager is unusable |
| `subprocess.Popen` fails (binary missing) | `FileNotFoundError` from Popen | `restart_node` will retry; after 5 attempts gives up |
| Child hangs (e.g., deadlock in PBFT) | `p.poll()` still returns `None` | Not detected — manual `kill` required |
| Token file deleted while children running | children still use the in-memory env var | New clients cannot authenticate; existing sessions unaffected |

#### Security Note

The token is the **only** authentication for the IPC command channel. It is therefore:
- Generated by a CSPRNG (`secrets.token_urlsafe(32)` produces 32 random bytes base64-encoded → 43 chars of effectively-256-bit entropy).
- Stored in a 0600-mode file, owner-only readable.
- Validated by `main.cpp:283-284` against the env var (with the file as fallback).
- Required for *every* IPC command. No token → no command.

---

### 4.21 CLI Tools

#### 4.21.1 `tools/inject_event.cpp` (177 lines) — IPC Client

##### Purpose

A command-line client for the IPC command channel. Reads the auth token from `/tmp/neuro_mesh_token`, performs the `AUTH <token>\n` handshake, then sends a `CMD:INJECT <target> <evidence_json>` command.

##### Wire Protocol

1. Client opens Unix domain socket `/tmp/neuro_mesh_<NODE_ID>.sock`.
2. Client writes `AUTH <token>\n` (terminated with `\n`).
3. Server reads; if the token does not match the env var, server logs `[IPC] REJECTED: invalid token` and closes the connection.
4. Client writes `CMD:INJECT <target_id> <evidence_json>\n`.
5. Server processes; if a self-initiated consensus is needed (target is local), it logs `[DECENTRALIZED] Self-initiating PBFT consensus`.
6. Server writes `ACK:INJECT\n` back to the client.
7. Client reads and prints; closes socket.

##### Evidence JSON

`inject_event` builds one of three canned JSON blobs based on the `--event` flag:

- `lateral_movement`: `{"event":"lateral_movement","src_ip":"<target>","pid":4201,"comm":"sshd","verdict":"<v>",...}`
- `privilege_escalation`: `{"event":"privilege_escalation","uid":0,"comm":"bash","parent_comm":"nginx",...}`
- `entropy_spike` (default): `{"sensor":"ebpf_entropy","value":0.98,"threshold":0.85,"verdict":"<v>",...}`

##### Failure Modes

- Token file missing → `[SIM] Token file /tmp/neuro_mesh_token not found. Is the mesh running?`
- Token file empty → `[SIM] Token file is empty.`
- Connection refused → `[SIM] Failed to connect to /tmp/neuro_mesh_<id>.sock`
- AUTH handshake send fails → `[SIM] Failed to send AUTH handshake.`
- Server rejects token → connection closed by server; no explicit error response (by design — don't leak authentication state to unauthenticated clients).

#### 4.21.2 `tools/attack_injector.cpp` (137 lines) — Adversarial Test Client

[NOT YET VERIFIED in full. Referenced in the Makefile as a tool target.]

#### 4.21.3 `tools/register_attacker.cpp` (56 lines) — Test Scaffolding

[NOT YET VERIFIED. Used by the integration test suite to register a known-malicious peer.]

#### 4.21.4 Test Binaries

Built by `make test` and run by `make test` runner:

- `test_crypto` — Ed25519 sign/verify round-trips
- `test_pbft` — quorum intersection, equivocation, view-change
- `test_enforcer` — backend cascade, safe-list, fork_exec_capture
- `test_meshnode` — peer discovery, message routing
- `test_inference` — ONNX model loading and forward pass
- `test_common` — UniqueFD, Result, Base64
- `test_mitigation` — MitigationEngine dispatch
- `test_proofchain` — Merkle append + verify
- `test_telemetrybridge` — sandbox stages + pipe protocol
- `test_auditlogger` — UDP send

Stress test: `stress` binary (built from `tests/stress/test_stress.cpp` + core objects) — fires concurrent + adversarial traffic.

Fuzz harnesses: `fuzz_beacon_parser`, `fuzz_json_parser`, `fuzz_pbft_message` (built by `make fuzz`, run with `make fuzz RUN_FUZZ=1`, default 10 s budget per target).

---

### 4.22 Kernel Sensor — `kernel/sensor.bpf.c` (195 lines)

#### Purpose

The eBPF program loaded into the kernel. Hooks four kprobes to emit telemetry events to a ring buffer map, and runs an XDP dropper program that drops packets from blacklisted IPs at the NIC driver level.

#### Maps (eBPF pinned to `/sys/fs/bpf/neuro_mesh[_<node_id>]/`)

| Map | Type | Max entries | Key | Value | Purpose |
|-----|------|-------------|-----|-------|---------|
| `telemetry_ringbuf` | RINGBUF | 256 KiB | n/a | n/a | Event stream from kprobes to userspace |
| `xdp_blacklist` | HASH | 1024 | `__u32` (IPv4) | `__u8` (1 = blocked) | IPs the XDP dropper will reject |

#### Programs

| Program | Section | Hook | Purpose |
|---------|---------|------|---------|
| `xdp_neuro_mesh_dropper` | `xdp` | NIC driver | Drop packets from IPs in `xdp_blacklist`; also honor a `0xFFFFFFFF` "lockdown" key |
| `handle_execve` | `kprobe/__x64_sys_execve` | syscall entry | Emit `KernelEvent` with PID + comm + first 256 bytes of argv |
| `handle_sendto` | `kprobe/__x64_sys_sendto` | syscall entry | Emit `KernelEvent` with destination |
| `handle_sendmsg` | `kprobe/__x64_sys_sendmsg` | syscall entry | Emit `KernelEvent` with destination |
| `handle_connect` | `kprobe/__x64_sys_connect` | syscall entry | Emit `KernelEvent` with destination |

The lockdown key (`0xFFFFFFFF`) is a single shared "kill switch" — when present in the map, ALL traffic is dropped, regardless of source. It is currently used as an emergency brake in tests; production deployments may repurpose it.

#### XDP Dropper Logic (`sensor.bpf.c:43-65`)

```c
SEC("xdp")
int xdp_neuro_mesh_dropper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    __u32 src_ip = iph->saddr;
    __u8 *banned = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);
    if (banned && *banned == 1) return XDP_DROP;
    __u32 lockdown_key = 0xFFFFFFFF;
    __u8 *lockdown = bpf_map_lookup_elem(&xdp_blacklist, &lockdown_key);
    if (lockdown && *lockdown == 1) return XDP_DROP;
    return XDP_PASS;
}
```

#### Architecture Portability

`kprobes` use `PT_REGS_PARM*` macros from `bpf_tracing.h` to resolve argument registers correctly for x86_64 (the only supported architecture at this time; a `__TARGET_ARCH_x86` guard at `sensor.bpf.c:80-100` defines a local `pt_regs` struct).

#### Failure Modes

| Failure | Detection | Recovery |
|---------|-----------|----------|
| `bpf()` syscall fails to load program | libbpf error | Agent logs; no events emitted; enforcement loses eBPF backend |
| kprobe attachment fails (kprobes disabled in kernel config) | libbpf error | Same; `handle_*` are not registered |
| Ring buffer overflow (userspace poll too slow) | `bpf_ringbuf_reserve` returns NULL | Event is dropped; no kernel-side queue |
| XDP program not supported by NIC driver | `bpf_set_link_xdp_fd` returns error | Fall back to nftables; no kernel-level drop |

---

## 5. Runtime Lifecycle

### 5.1 Startup Sequence

The following sequence runs when `./bin/neuro_agent NODE_ID` is invoked. Stages 0-6 are sequential in `main()`. Stage 7 (mesh.start()) spawns 5 background threads. Stages 8-9 spawn the heartbeat and IPC threads. After that, `main()` blocks on `global_running`.

Stage 0: `AuditLogger::initialize()` (creates the static UDP socket).
Stage 1: `PolicyEnforcer jailer; jailer.set_node_id(node_id); jailer.add_safe_node(node_id);` - the safe-list call is MANDATORY: skipping it would make self-isolation possible.
Stage 2: `MitigationEngine mitigation;` (dispatcher).
Stage 3: `TelemetryBridge bridge; bridge.spawn();` - forks the sandboxed child. Port resolved from node_id: ALPHA=9000, BRAVO=9010, CHARLIE=9020, DELTA=9030, ECHO=9040; override via `NEURO_WS_PORT`.
Stage 4: `MeshNode mesh(node_id, &jailer, &mitigation, &bridge);` (constructor only stores pointers; no I/O).
Stage 5: `ai::InferenceEngine inference;` (loads ONNX model; null if libonnxruntime unavailable).
Stage 6: `auto ebpf_result = core::NodeAgent::create(node_id);` - opens sensor.bpf.o, pins BPF maps, attaches kprobes and XDP, starts ring-buffer consumer thread. Returns `Result<unique_ptr<NodeAgent>>`; on error, ebpf is null.
Stage 7: `mesh.start();` - spawns 5 threads (p2p_listener, discovery_beacon, tcp_listener, tls_acceptor, liveness_monitor); sleeps 100 ms; calls `announce_identity()` (signed broadcast of node_id + PEM).
Stage 8: `std::thread t_heartbeat(heartbeat_loop, bridge, mesh, inference, ebpf, node_id);` - the main telemetry push.
Stage 9: `std::thread t_ipc(ipc_listener_loop, node_id, jailer, mesh, bridge);` - the C2 command channel.

After Stage 9, `main()` waits on `global_running`.

### 5.2 Configuration Loading

There is no configuration file. All configuration is by:

- Command-line argument: `argv[1]` for node ID (default `ALPHA`).
- Environment variables: `NEURO_IPC_TOKEN` (required for IPC; set by `mesh_manager.py`), `NEURO_PBFT_RATE_WINDOW_SEC` (default 10), `NEURO_PBFT_RATE_MAX` (default 5), `NEURO_WS_PORT`, `NEURO_UNSAFE_NO_SANDBOX=1` (skip TelemetryBridge sandbox), `NEURO_AUDIT_HOST`, `NEURO_AUDIT_PORT`.
- Hard-coded per-node port mapping in `main.cpp:537-546`.

### 5.3 Node Registration / Identity Setup

On first boot, the node has no Ed25519 key. `KeyManager::generate_or_load(node_id)` (inferred from usage, not directly verified) creates `keystore_<node_id>/id_ed25519` with a fresh keypair and writes the PEM public key. On subsequent boots, the same key is loaded.

The public key is serialized to PEM, signed with the private key, and broadcast on the discovery port as `ANNOUNCE|node_id|pem|sig_b64`. The signature covers `node_id + "|" + pem`.

### 5.4 Peer Discovery

Two parallel mechanisms run after `mesh.start()`:

1. Discovery beacons (`MeshNode::discovery_beacon_loop`): periodically unicast a beacon to each seed peer. Default seeds: 127.0.0.1:9998 (or whatever was passed to `set_seed_peers`).
2. ANNOUNCE broadcasts (`MeshNode::announce_identity`): on startup and on a schedule, broadcast the signed identity on the local subnet (255.255.255.255:9998).

When a peer is discovered, `process_discovery_beacon` or `process_message` extracts its node_id, PEM, and signature. The signature is verified against the claimed PEM. If valid, the peer is added to `m_peer_manager`. The dual-path TOFU check requires that the SAME node_id+PEM be seen via both the BEACON path and the ANNOUNCE path before the key is pinned (`m_pbft.register_peer_key()` is called only when `dual_confirmed` is true). On mismatch, the message is rejected with `[SECURITY] TOFU dual-path MISMATCH for <id> via ANNOUNCE — rejecting peer`.

### 5.5 Consensus Initialization

`MeshNode` is constructed with `m_pbft` as a default-initialized `PBFTConsensus`. The constructor reads `NEURO_PBFT_RATE_WINDOW_SEC` and `NEURO_PBFT_RATE_MAX` from the environment. The state machine is otherwise stateless until a round is initiated.

Each seen peer that completes dual-path TOFU adds 1 to `m_total_nodes`, which determines the quorum size. With n=5 the standard PBFT bound is `f = (n-1)/3 = 1` and the quorum is `2f+1 = 3` (or sometimes stated as `(2n/3)+1 = 4` for stronger safety). The code uses `quorum_size_unlocked()` which the operator should verify before deployment.

### 5.6 Monitoring Lifecycle

`heartbeat_loop` runs in a dedicated thread, ticking every 200 ms (10 ticks per cycle = 2 s nominal heartbeat). Each cycle:

1. Read CPU% from /proc/stat, memory MB from cgroup v1/v2 (with sysinfo fallback), network entropy from /proc/net/dev delta, ONNX score from the InferenceEngine.
2. Blend scores: take the max; if `is_targeted_recently()` (this node is the target of an active PBFT round), floor at 0.68.
3. Map to threat level: `entropy >= 0.65` is `CRITICAL`; `entropy >= 0.60` is `ALERT`; else `NONE`.
4. If `CRITICAL` and `peer_count() > 1` and 30-second grace period elapsed: self-initiate a PBFT round with the local node as the suspect (`initiate_consensus(node_id, evidence)`).
5. Build telemetry JSON: seq, node, event=heartbeat, peers (list of IDs), cpu, mem_mb, entropy, threat, mitre_attack.
6. Call `mesh.gossip_telemetry(json)` which unicasts the JSON to every known peer.
7. Each receiving peer forwards the JSON to its own TelemetryBridge, which broadcasts to its dashboard clients.

### 5.7 Enforcement Lifecycle

Triggered from three paths:

1. Self-initiated (heartbeat): the local node proposes to isolate itself if it sees a sustained anomaly on itself. This is intentional - a node that detects it is being attacked can ask the mesh to isolate it.
2. Consensus-driven: when `process_message` sees a `COMMIT` and the round advances to `EXECUTED`, the `MeshNode::broadcast_pbft_stage` path calls `m_mitigation->execute_response(evidence_json, target_id)`. This dispatches to `PolicyEnforcer::isolate_target()` which:
   - Validates the target is not safe-listed.
   - Validates the target IP is not loopback.
   - Resolves the target node_id to an IP.
   - Calls `block_ip_address(ip)`, which runs the eBPF - nftables - iptables cascade.
   - On success, calls `m_pbft.ban_peer_local()` to add the target to the local ban set.
   - Appends to the ProofChain and exports the JSON.
3. IPC-driven: `inject_event` sends `CMD:INJECT target evidence` over the Unix socket; the IPC handler calls `mesh.initiate_consensus(target, evidence)`.

### 5.8 Shutdown Lifecycle

Triggered by SIGINT or SIGTERM (`signal_handler` flips `global_running` to false) or by the parent process exiting.

1. `main()` unblocks.
2. `mesh.stop()`:
   a. Flip `m_running` to false.
   b. Notify the TLS queue CV.
   c. `transport->shutdown()`.
   d. Join the 5 background threads.
   e. Close all UDP, TCP, TLS, and broadcast FDs.
3. If `ipc_thread.joinable()`, flip `global_running` again and join.
4. `bridge.shutdown()` - close pipe, waitpid for the sandboxed child.

If the process is supervised by `mesh_manager.py`, the manager's `cleanup` handler also runs: terminate all children, wait 5 s, kill stragglers, delete `/tmp/neuro_mesh_token`.


---

## 6. Consensus System Deep Dive

### 6.1 Protocol Stages

The `PBFTConsensus` state machine has 6 stages (`PBFT.hpp:21`):

```
IDLE -> PRE_PREPARE -> PREPARE -> COMMIT -> EXECUTED
                              \-> BAN_PEER (terminal, no further transitions)
```

| Stage | Purpose | Transition to | Trigger |
|-------|---------|---------------|---------|
| `IDLE` | Initial state | `PRE_PREPARE` | New round initiated |
| `PRE_PREPARE` | Proposer announces intent | `PREPARE` | One node (the proposer) has broadcast intent |
| `PREPARE` | Peers agree on the proposal | `COMMIT` | PREPARE voters reach quorum |
| `COMMIT` | Peers commit to executing | `EXECUTED` | COMMIT voters reach quorum AND PREPARE/COMMIT voters intersect by at least a quorum |
| `EXECUTED` | Final state | (terminal) | Local enforcement fires; ProofChain appended |
| `BAN_PEER` | Special round for permanent exclusion | (terminal) | Evidence contains the `"action":"ban"` marker |

### 6.2 Message Types

`P2PMessage` (`PBFT.hpp:23-32`):

| Field | Type | Purpose |
|-------|------|---------|
| `stage_str` | string | One of PRE_PREPARE, PREPARE, COMMIT, EXECUTED, BAN_PEER |
| `sender_id` | string | Node ID of the sender |
| `target_id` | string | Node ID of the target (the suspect) |
| `evidence_json` | string | Free-form JSON describing the event |
| `signature` | string | Base64 Ed25519 signature over a deterministic blob |
| `prev_message_hash` | string | SHA-256 of the previous message in the sender's chain |
| `sequence_number` | uint64_t | Monotonically increasing per sender |
| `view` | int | PBFT view number |

The signature covers `stage_str + "|" + target_id + "|" + evidence_json + "|" + sequence_number + "|" + view + "|" + prev_message_hash`. The wire format on UDP is pipe-delimited, matching the signature blob.

### 6.3 Quorum Logic

With n=5 nodes, the standard PBFT bound is f=1 (Byzantine failures tolerated) and the quorum is `(2n/3)+1 = 4`. The `quorum_size_unlocked()` function in `PBFT.hpp` is the source for the exact formula and should be reviewed for the production deployment's choice.

**The quorum-intersection guard** (`consensus/PBFT.hpp:546-573`) is the single most important safety check in the codebase. It runs at the COMMIT-to-EXECUTED transition. It:

1. Looks up `m_vote_registry[round_key]["PREPARE"]` and gets the set of PREPARE voters.
2. If the PREPARE set has fewer than `quorum` voters, returns true (vacuously satisfied).
3. Looks up `m_vote_registry[round_key]["COMMIT"]` and gets the set of COMMIT voters.
4. Computes the set intersection of PREPARE and COMMIT voters.
5. Returns true iff the intersection has size >= quorum.

If the guard returns false:
- The round does NOT advance to EXECUTED.
- The just-inserted vote is rolled back: `stage_voters.erase(msg.sender_id)`.
- The round aborts to IDLE.
- The next attempt at the same `round_key` (the same `evidence_json + target_id`) starts fresh.

**Why the rollback matters**: without it, a poisoned vote would block any future commit on the same evidence until the ROUND_TTL_SEC (120 s) expiry. The rollback is a "surgical fix for liveness".

**Why the guard is at COMMIT-to-EXECUTED, not PREPARE-to-COMMIT**: in the original (buggy) location at PREPARE-to-COMMIT, the COMMIT voter set was empty at that point (no one has voted COMMIT yet), so the intersection was always empty, the `commit_it == prep_it->second.end()` short-circuit always fired, and the guard was a no-op. The only meaningful place to check intersection is AFTER the COMMIT votes have arrived, i.e. at COMMIT-to-EXECUTED.

### 6.4 Vote Collection (advance_state)

In `advance_state()` (`PBFT.hpp:189-310`):

1. The just-arrived message is hashed (`msg_hash = sha256_hex(signature_blob)`) and added to `m_seen_messages`. If the hash is already present, return IDLE (replay).
2. `detect_equivocation(msg, msg_hash)` checks if the same `(sender_id, sequence_number)` has been seen with a different hash. If yes, log it and add to `m_node_trust`.
3. The sender is added to `m_vote_registry[round_key][msg.stage_str]`. If already present, return IDLE (duplicate).
4. The round state is updated (or initialized if IDLE).
5. If the round's `view` does not match `msg.view`, return IDLE.
6. Branch by `msg.stage_str`:
   - PRE_PREPARE or BAN_PEER + round is IDLE -> transition to PREPARE.
   - PREPARE + round is PREPARE -> transition to COMMIT.
   - COMMIT + round is COMMIT + quorum intersection check passes -> transition to EXECUTED.
7. Return the new state.

### 6.5 State Transition Diagram

```
   initiator broadcasts PRE_PREPARE
                |
                v
        round.state = PRE_PREPARE
                |
                v   (a node receives a PRE_PREPARE, transitions itself, broadcasts PREPARE)
   each node broadcasts PREPARE
                |
                v
        round.state = PREPARE
                |
                v   (a node receives a PREPARE, transitions itself, broadcasts COMMIT)
   each node broadcasts COMMIT
                |
                v
        round.state = COMMIT
                |
                v   (a node receives a COMMIT, runs verify_quorum_intersection())
        if intersection >= quorum: round.state = EXECUTED
        else: erase just-inserted vote, round.state = IDLE
                |
                v
   on EXECUTED: local enforcement fires, ProofChain append, terminal
```

Note: in the implementation, only the node that **observes** a state change broadcasts the next stage. Other nodes learn the new state from observing the next-stage broadcast.

### 6.6 Timeout Behavior

- `VIEW_CHANGE_TIMEOUT_SEC = 130`: if a round is idle for > 130 s, `needs_view_change()` returns true. **[NOTE: the view-change protocol itself is not fully implemented in the wire protocol. The function exists but no view-change message type is broadcast. This is a known gap; see Section 18.]**
- `ROUND_TTL_SEC = 120`: if a round is idle for > 120 s, `cleanup_stale_rounds()` evicts the round, its vote registry, and (if EXECUTED) the last confirmed hash.
- `RATE_LIMIT_WINDOW_SEC = 10` / `RATE_LIMIT_MAX = 5`: a peer may send at most 5 PBFT messages in a 10-second sliding window. Over-limit messages are dropped and the failure counter is incremented (sampled at 6, 10, 20, 50, 75 to avoid log spam).
- `MAX_SEQUENCE_GAP = 100`: if the sequence number jumps by more than 100 between consecutive messages from the same sender, the message is rejected as a replay/spoof attempt.

### 6.7 Failure Handling

- Signature verification failure: at sampled thresholds (6, 10, 20, 50, 75, 100), a CRITICAL log is emitted. At 100, the peer is auto-pruned from the key registry AND added to `m_banned_peers` (defense in depth - even though the prune would already drop future messages, the explicit ban makes the canonical ban set authoritative).
- Rate limit exceeded: same threshold sampling.
- Replay: silently dropped, no failure recorded.
- Round timeout: silently evicted.
- Equivocation: logged as CRITICAL, sender's trust counter incremented.
- PREPARE/COMMIT voters don't intersect: just-inserted vote rolled back, round aborts to IDLE.
- View mismatch: round aborts to IDLE.
- Quorum not reached: round stays in current state; eventually evicted by TTL.

### 6.8 Replay Protection

Replay protection is layered:

1. **m_seen_messages** (set of message hashes): every message that successfully passes `verify_message()` is added. On a duplicate hash, the message is silently dropped. The set is capped at 100,000 entries; on overflow, the oldest half is evicted.
2. **Sequence number** (per-sender monotonic): `verify_message_chaining()` checks that `msg.sequence_number` is consistent with the last seen from the same sender. A jump > `MAX_SEQUENCE_GAP = 100` is rejected.
3. **prev_message_hash chaining**: each message includes the hash of the previous message from the same sender. This prevents cut-and-paste replay across senders.
4. **view number**: each round has a view; messages with a view mismatch are rejected.

### 6.9 Duplicate Suppression

Within a single round, `m_vote_registry[round_key][stage_str]` is a `set<sender_id>`. Inserting a duplicate sender into the set is a no-op, and the round state does not advance based on duplicate votes. This is checked in `advance_state` after the replay check.

### 6.10 Crash Recovery Implications

A node that crashes mid-round loses its in-memory `m_rounds`, `m_vote_registry`, and `m_node_trust`. After restart:

- The node re-broadcasts its `ANNOUNCE`; peers re-acknowledge.
- In-flight rounds on other peers will time out at 120 s and be re-initiated if the underlying anomaly persists.
- The local node's view of the mesh is reconstructed by re-receiving heartbeat gossip from peers.

There is **no crash-recovery of in-flight rounds** - the design relies on the heartbeat to drive consensus forward. The `StateJournal` (write-ahead log) is intended to persist the more critical events, but its full integration with PBFT recovery was not verified in this review.

[NOTE: Crash recovery is a known area requiring further work. The current design is "best effort" - a crashed node catches up on the next heartbeat.]

### 6.11 Sequence Diagram: End-to-End PBFT Round

```
   ALPHA        BRAVO       CHARLIE      DELTA        ECHO        PBFTConsensus
     |            |            |            |            |               |
     |  PRE_PREPARE (broadcast)            |            |               |
     |------------------------------------>|            |               |
     |            |            |            |            |               |
     |  PREPARE   |            |            |            |               |
     |----------->|----------->|----------->|----------->|               |
     |            |            |            |            |               |
     |  COMMIT    |            |            |            |               |
     |----------->|----------->|----------->|----------->|               |
     |            |            |            |            |               |
     |  EXECUTED  (after quorum intersection check passes)               |
     |------------------------------------>|            |               |
     |            |            |            |            |               |
     | [local] enforce(X)     enforce(X)   enforce(X)   enforce(X)      |
     | ProofChain.append(...) |            |            |               |
     |            |            |            |            |               |
```

In the actual implementation, each node re-broadcasts the next stage when it observes the previous one. So the precise sequence is:

1. ALPHA decides to initiate (e.g., from heartbeat or IPC). It broadcasts PRE_PREPARE.
2. Each of the other 4 nodes receives PRE_PREPARE, transitions itself to PREPARE, broadcasts PREPARE.
3. Each of the 5 nodes receives 4 PREPARE messages (quorum=4), transitions itself to COMMIT, broadcasts COMMIT.
4. Each of the 5 nodes receives 4 COMMIT messages, runs `verify_quorum_intersection()`, sees that PREPARE and COMMIT voters are the same set of 4+ nodes, transitions itself to EXECUTED, and fires local enforcement.
5. ALPHA's local enforcement might also call `m_pbft.ban_peer_local(target)` to add the target to its local ban set (only if the round was a BAN_PEER type).

### 6.12 Crash Recovery Implications (Detailed)

A node crash has three observable effects on an in-flight round:

1. The crashed node stops sending PREPARE, COMMIT, or EXECUTED.
2. The remaining nodes' vote sets become asymmetric: the crashed node's vote is missing from both PREPARE and COMMIT sets.
3. As long as the remaining (n-1) nodes still have intersection >= quorum, the round completes.

For n=5, f=1 means the mesh tolerates 1 crash during a round. With 2 crashes (n=3), quorum is 3 and intersection is 3 (all remaining), so the round can still complete. With 3 crashes (n=2), the round cannot reach quorum and will time out at 120 s.

If the proposer itself crashes between PRE_PREPARE and PREPARE, the round never advances; a new round would have to be initiated by another node detecting the same anomaly. The view-change protocol (if implemented) would handle this.

---

## 7. Security Architecture

### 7.1 Trust Model

The system's trust model is intentionally **scoped, not absolute**:

- **Trusted**: the local Linux kernel, the OpenSSL runtime, the BPF verifier, the operator (whoever can write to `/tmp/neuro_mesh_token` or set `NEURO_IPC_TOKEN`).
- **Semi-trusted**: peer nodes. Each peer holds an Ed25519 keypair; signatures are verified. But until a peer is dual-path TOFU-confirmed, its key is provisional.
- **Untrusted**: the local network, the OS user running the agent (must be root for eBPF and the XDP program), the dashboard browser.
- **Out of scope**: the host kernel, hypervisor, firmware. A kernel rootkit trivially defeats the system.

### 7.2 Trust Boundaries

| Boundary | Description | Protection |
|----------|-------------|------------|
| T1: Kernel ↔ Userspace | eBPF verifier + ring buffer | eBPF program is verified at load; ring buffer is the only channel; CAP_BPF/CAP_SYS_ADMIN required |
| T2: Agent ↔ TelemetryBridge | Anonymous pipe (parent writes, child reads) | The child runs in a chroot + dropped-UID + seccomp sandbox; the parent cannot be reached by the child |
| T3: Node ↔ Node | UDP/TCP/TLS over loopback or LAN | Ed25519 signatures on every PBFT message; TLS 1.3 mTLS for the data plane; dual-path TOFU for new peer introduction |
| T4: Operator ↔ Agent | Unix domain socket | Per-boot CSPRNG token in env var + 0600 file; peer-cred UID 0/own-UID check; per-UID rate limit (10/s) |

### 7.3 Authentication

- **Node-to-node**: Ed25519 signatures on every PBFT message; signature is over a deterministic blob that includes stage, target, evidence, sequence_number, view, and prev_message_hash.
- **TLS data plane**: TLS 1.3 with mTLS. Self-signed certificates per node, signed by a per-mesh CA. Cert fingerprints pinned on first contact (TOFU).
- **Operator-to-agent**: CSPRNG token (43 chars of 256-bit entropy) in env var. Token is required as the first line of any IPC command (`AUTH <token>\n`).
- **Dashboard-to-agent**: the WebSocket serves only static dashboard HTML; no authentication is performed on the WebSocket itself. The dashboard is read-only and contains no commands.

### 7.4 Authorization

- IPC commands are authorized by the token (any token holder may issue any command). This is intentional: the token is a capability, and whoever can read `/tmp/neuro_mesh_token` (mode 0600) is the operator.
- PBFT isolation targets are checked against the safe-list in `PolicyEnforcer::is_safe()` and `is_ip_safe()`. Self is always safe-listed. Loopback is always safe-listed.
- The TelemetryBridge is read-only by design: it serves a WebSocket of telemetry JSON. It cannot issue commands.

### 7.5 Signatures

Ed25519 is used throughout. The implementation in `crypto/CryptoCore.cpp` is OpenSSL EVP-based, with the key wrapped in `UniquePKEY` (RAII). The signature blob is:

```
sign(stage_str + "|" + target_id + "|" + evidence_json + "|" + sequence_number + "|" + view + "|" + prev_message_hash)
```

The wire format is base64. The signature is verified before any state machine action in `PBFTConsensus::verify_message()`. The verify failure is sampled at thresholds 6, 10, 20, 50, 75, 100 to avoid log spam; the actual ban fires at 100.

### 7.6 Key Management

- `crypto/KeyManager` (949 lines, not fully read): generates or loads Ed25519 keypairs from `keystore_<NODE_ID>/id_ed25519`.
- `crypto/CertificateAuthority` (427 lines, not fully read): generates per-node TLS certificates signed by a per-mesh CA.
- `crypto/CryptoCore::sha256_hex`: SHA-256 used for round keys, message hashes, and ProofChain chaining.
- `crypto::UniquePKEY`: RAII wrapper for `EVP_PKEY*` to prevent leaks.

**[ASSUMPTION]**: Key rotation is not implemented in the current version. To rotate, delete the `keystore_<NODE_ID>/` directory and restart. This will trigger a new ANNOUNCE and the dual-path TOFU process will accept the new key as a "new" peer. The old key remains in peers' `m_peer_public_keys` until the next `ANNOUNCE` or until the rate limit fails (which would take 100 messages).

### 7.7 TOFU Behavior

The dual-path TOFU mechanism:

1. A peer is first seen via UDP BEACON (signed by its key, sent to a seed IP).
2. The same peer is then seen via UDP ANNOUNCE broadcast (also signed by its key, on the local subnet).
3. `PeerManager::confirm_path` is called twice: once with `PATH_BEACON` and once with `PATH_ANNOUNCE`.
4. If both paths present the same node_id and PEM, the peer is `dual_confirmed = true` and `m_pbft.register_peer_key()` is called.
5. If the two paths disagree on the PEM, the ANNOUNCE is rejected with `[SECURITY] TOFU dual-path MISMATCH`.

This protects against an attacker who can forge a BEACON but not an ANNOUNCE, or vice versa.

### 7.8 Attack Surface

| Surface | Threat | Mitigation |
|---------|--------|------------|
| UDP 9999 (PBFT) | Flood, signature spoofing, equivocation | Rate limit (5/10s); signature check; equivocation detection |
| UDP 9998 (telemetry) | Flood, forged telemetry | Signed; rate limited at receiver |
| TCP 10000+ (PEX) | Connection flood, peer list poisoning | Rate limit (5/10s); authentication after TOFU |
| TLS 10500+ | Downgrade attack, cert spoofing | TLS 1.3 only; mTLS; cert fingerprint pinning (TOFU) |
| Unix `/tmp/neuro_mesh_*.sock` | Local privilege escalation | CSPRNG token; UID 0/own-UID check; rate limit |
| BPF map `/sys/fs/bpf/neuro_mesh_*/` | Local privilege escalation | Pinned to node-id-specific path; only root can write |
| iptables/nftables state | Compromised enforcement | Fork+exec, no shell; argv as separate strings |

### 7.9 Threat Model

The system is designed to defend against:

- **Compromised peer node**: byzantine tolerance up to f=1 with n=5.
- **Network adversary (passive eavesdropper)**: signatures prevent forgery; TLS 1.3 protects the data plane.
- **Network adversary (active MITM)**: TOFU catches single-path spoofing; dual-path catches the combined attack.
- **Local non-root attacker**: cannot write to `/tmp/neuro_mesh_token` (mode 0600); cannot open privileged ports; cannot modify iptables rules.
- **Local root attacker**: can disable enforcement, read the token, forge identities. **Out of scope.**
- **Kernel-level attacker (rootkit)**: trivially defeats all in-userspace protections. **Out of scope.**

The system is **NOT** designed to defend against:

- Compromised OpenSSL or BPF verifier.
- Side-channel attacks on the host (cache, TLB, power).
- A determined state-level adversary with physical access.
- A compromised operator.

---

## 8. Networking Architecture

### 8.1 Transport Protocols

| Channel | Protocol | Default port(s) | Notes |
|---------|----------|------------------|-------|
| PBFT broadcast | UDP | 9999 | Plain UDP broadcast; signatures provide authentication |
| Discovery / telemetry gossip | UDP | 9998 | Plain UDP; signed |
| Peer Exchange (PEX) | TCP | 10000+ | Per-node; signed payloads |
| mTLS data plane | TLS 1.3 over TCP | 10500+ | Per-node; ECDHE + AES-GCM or CHACHA20-POLY1305 |
| IPC (C2) | Unix domain socket | `/tmp/neuro_mesh_<id>.sock` | Per-node; CSPRNG token + UID check |
| Dashboard | WebSocket over TCP | 9000, 9010, 9020, 9030, 9040 | Per-node; unencrypted; same-origin only |
| Audit log | UDP | 9997 | Optional; one-way |

### 8.2 Peer Communication

There are three peer-to-peer patterns:

1. **Broadcast (PBFT)**: each PBFT message is sent via `send_udp_broadcast` (UDP broadcast to 255.255.255.255). All nodes receive all messages and apply rate limiting and signature checks.
2. **Unicast (telemetry gossip)**: each heartbeat JSON is sent via `send_udp_unicast(ip, port, payload)` to each known peer. Used for telemetry; also used for ANNOUNCE and BEACON in some configurations.
3. **Request-response (PEX)**: TCP connection initiated by a new node to dump the full peer list of a known peer. Uses `perform_pex_handshake`.

### 8.3 Message Routing

- `MeshNode::p2p_listener_loop` is a single UDP receive thread. It dispatches based on the first token of the message:
  - `ANNOUNCE|...` -> `process_message` (signature verification, dual-path TOFU, peer registration)
  - `BEACON|...` -> `process_discovery_beacon` (peer registration)
  - `PRE_PREPARE|...`, `PREPARE|...`, `COMMIT|...`, `EXECUTED|...`, `BAN_PEER|...` -> `process_message` -> `m_pbft.verify_message` and `m_pbft.advance_state`
  - `TELEMETRY|...` -> `process_telemetry_gossip` (merge into local state, forward to TelemetryBridge)
- `MeshNode::tcp_listener_loop` accepts PEX connections, reads a small request, dumps the peer list, closes.
- `MeshNode::tls_acceptor_loop` accepts mTLS connections, dispatches to `tls_worker_loop`.

### 8.4 Retry Logic

- UDP: best-effort. No retransmission. A lost message is recovered by:
  - The next heartbeat (every 2 s) re-sending telemetry.
  - The next discovery beacon re-sending identity.
  - The PBFT round's idempotency: a sender re-broadcasts the next stage when it observes the previous one, so a lost PRE_PREPARE is implicitly recovered when the next PREPARE comes in.
- TCP PEX: best-effort, single-attempt. If the connection fails, the new node relies on its next discovery beacon.
- TLS: OpenSSL's built-in retransmission for handshake. Application data: best-effort, same as UDP.

### 8.5 Serialization Formats

- **PBFT messages**: pipe-delimited ASCII, e.g., `PREPARE|123|0|ALPHA|EBPF_EVENT:...|SENDER|BASE64SIG|PREV_HASH`.
- **ANNOUNCE messages**: `ANNOUNCE|<node_id>|<pem>|<base64_sig>`.
- **Telemetry JSON**: human-readable JSON with fields: `seq`, `node`, `event`, `peers` (array of node IDs), `cpu`, `mem_mb`, `entropy`, `threat`, `mitre_attack`.
- **ProofChain**: JSON file with one event per line, each containing `prev_hash`, `event_type`, `timestamp`, `target`, `evidence`, `signature`.

### 8.6 Connection Lifecycle

- **UDP sockets**: created at `mesh.start()`, closed at `mesh.stop()`. The PBFT broadcast socket is a single FD shared across all sends.
- **TCP PEX**: short-lived (one request, one response, close). No persistent connections.
- **TLS**: long-lived. Each `tls_worker_loop` thread handles a single connection. Connections are added on accept and removed on close.
- **Unix domain socket (IPC)**: one server socket per node, multiple client connections, each handled in the same `ipc_listener_loop` thread via `select()`. Rate limit is per-UID, not per-connection.
- **WebSocket**: one server socket per node, multiple client connections handled by uWebSockets internally.

---

## 9. Enforcement Engine

### 9.1 Detection Pipeline

The detection path is:

1. **Kernel eBPF** (`kernel/sensor.bpf.c`): four kprobes (`execve`, `sendto`, `sendmsg`, `connect`) and one XDP dropper. Each kprobe emits a `KernelEvent` (pid, event_type, comm, payload) to the `telemetry_ringbuf`.
2. **NodeAgent** (`cell/NodeAgent.cpp`): consumes events from the ring buffer in a tight `while(ring_buffer__poll() > 0)` loop. Each event is passed to the `InferenceEngine`.
3. **InferenceEngine** (`cell/InferenceEngine.cpp`): runs an ONNX Isolation Forest model on the event. Returns an anomaly score in `[0, 1]`.
4. **heartbeat_loop** (`main.cpp:123-244`): blends the ONNX score with the network entropy score and (if targeted) a floor of 0.68. Produces a final entropy score in `[0, 1]`.
5. **Threat mapping**: `entropy >= 0.65` -> `CRITICAL`; `entropy >= 0.60` -> `ALERT`; else `NONE`.

### 9.2 Rule Evaluation

- **CRITICAL + peer_count > 1 + 30s grace**: self-initiate a PBFT round with the local node as the target.
- **ALERT**: log only; no action.
- **NONE**: log only; no action.

### 9.3 Response Generation

On a `CRITICAL` verdict, the system runs:

1. `MeshNode::initiate_consensus(node_id, evidence_json)` where `evidence_json` includes the current entropy and the `event=heartbeat` marker.
2. The PBFT round propagates as described in Section 6.
3. On `EXECUTED`, `MitigationEngine::execute_response(evidence_json, target_id)` is called.
4. `PolicyEnforcer::isolate_target(target_id)` is called.
5. The cascade runs: eBPF XDP map -> nftables drop -> iptables REJECT.
6. The target is added to `m_banned_peers`.
7. The ProofChain is appended.
8. Subsequent ANNOUNCE / BEACON messages from the banned peer are silently dropped.

### 9.4 Ban Propagation

There are two kinds of bans:

1. **Local auto-ban**: a peer is added to `m_banned_peers` after 100 consecutive signature failures, or via `propose_ban()`, or via a `BAN_PEER` round.
2. **Cross-node BFT ban**: a `BAN_PEER` round is initiated with the target's node_id in the evidence (`"action":"ban"` marker). Other nodes verify the round, add the target to their local ban set, and apply enforcement.

The `m_recent_bans` set tracks peers that were locally auto-banned but haven't had a cross-node BFT ban initiated yet. The heartbeat drains this set and calls `propose_ban()` to propagate the ban.

### 9.5 Rollback Behavior

`PolicyEnforcer::release_target(target_id)` removes the target from all three backends:

- `remove_ebpf_drop(ip)` deletes the entry from the XDP blacklist map.
- `remove_nftables_drop(ip)` finds the matching rule by listing and parses the handle, then deletes it.
- `remove_iptables_drop(ip)` runs `iptables -D INPUT -s <ip> -j REJECT`.

The function is exposed but not called by the consensus layer in the current code. **[ASSUMPTION]**: rollback is intended for test cleanup and for operator-driven unban. There is no automatic rollback after a time period; bans are permanent for the process lifetime.

`reset_enforcement()` is a test-only function that flushes all rules. It is not called in production.

---

## 10. Telemetry & Monitoring

### 10.1 Telemetry Collection

Telemetry is collected at three levels:

1. **Kernel (eBPF)**: `telemetry_ringbuf` is a 256 KiB ring buffer. Each `KernelEvent` is 280 bytes (pid 4 + event_type 4 + comm 16 + payload 256). The userspace consumer polls in a tight loop; if the consumers fall behind, the kernel drops events.
2. **Userspace (heartbeat)**: every 2 s, the main thread reads `/proc/stat` (CPU), cgroup v1/v2 (memory), `/proc/net/dev` (network), and the ONNX score. Blended entropy is computed and a telemetry JSON is built.
3. **Process metrics**: each `neuro_agent` logs to `logs/<NODE_ID>.log` and emits UDP audit events to `127.0.0.1:9997`.

### 10.2 Metrics

The `telemetry/Observability` module (840-line `.cpp`, 2300-line `.hpp`) is a heavier-weight metrics system. **[NOT YET VERIFIED]** - the interface is mentioned in the Makefile test target list but the full body was not read. Likely exports Prometheus-style metrics.

Per-node metrics exposed via the dashboard:

- `seq`: monotonic heartbeat counter
- `node`: the local node ID
- `event`: `"heartbeat"` or `"entropy_spike"`
- `peers`: array of known peer IDs
- `cpu`: percent (0-100)
- `mem_mb`: megabytes
- `entropy`: blended score [0, 1]
- `threat`: `NONE`, `ALERT`, or `CRITICAL`
- `mitre_attack`: array of MITRE ATT&CK technique IDs (e.g., `T1021`, `T1571`, `T1059`, `T6021`, `T5090`)

### 10.3 Aggregation

Each node receives telemetry gossip from its peers. `process_telemetry_gossip` parses the JSON, merges it into the local state, and pushes the union to the local TelemetryBridge. The dashboard sees the full mesh view because every node has the same union.

### 10.4 Storage

- Per-process: nothing persists by default. The ProofChain JSON is the only durable record of consensus events. It is written with `flock(LOCK_EX)`.
- Per-host: `logs/<NODE_ID>.log` captures the agent's stdout and stderr.
- `web/mesh_status.json`: written by `TelemetryExporter` for offline-mode dashboard.

### 10.5 Reporting

The dashboard (`dashboard/index.html`, ~1400 lines, vanilla JS, no dependencies) connects to any node's WebSocket and receives the union of telemetry. The user can:

- View the current state of all nodes.
- See recent PBFT events.
- See recent entropy spikes.
- See the consensus round history.

The dashboard is read-only. It does not issue commands.

---

## 11. Data Flow Analysis

This section traces one event end-to-end. The example is an entropy spike detected on CHARLIE that results in ALPHA being isolated.

### 11.1 Detection Event (CHARLIE)

1. A process on the host running CHARLIE does something unusual (e.g., a high-entropy `sendto` syscall).
2. The eBPF kprobe for `sendto` fires. It calls `bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(KernelEvent), 0)`, fills the event with `pid=4201`, `event_type=2`, `comm="curl"`, `payload=<first 256 bytes of args>`, and submits.
3. The NodeAgent's `telemetry_loop` polls the ring buffer, receives the event, and passes it to the InferenceEngine.
4. The InferenceEngine's ONNX forward pass returns a score of `0.78`.
5. The heartbeat reads the score, blends with network entropy (0.55), gets `0.78`. Maps to `CRITICAL`.
6. After 30 seconds of sustained CRITICAL, CHARLIE calls `mesh.initiate_consensus(CHARLIE, "{\"sensor\":\"ebpf_entropy\",\"value\":0.78,...}")`. The first argument is the suspect: **CHARLIE itself**.

### 11.2 Consensus Event

1. CHARLIE broadcasts `PRE_PREPARE|1|0|CHARLIE|<evidence>|CHARLIE|<sig>|<prev_hash>` on UDP 9999.
2. ALPHA, BRAVO, DELTA, ECHO each receive the PRE_PREPARE. Each runs `m_pbft.verify_message` (signature check OK, rate limit OK). Each calls `m_pbft.advance_state`, transitions the round from IDLE to PREPARE. Each broadcasts `PREPARE|...`.
3. All 5 nodes receive 4 PREPARE messages (quorum=4). Each runs `verify_quorum_intersection` (PREPARE set is full, COMMIT set is empty, returns true vacuously). Each transitions to COMMIT and broadcasts `COMMIT|...`.
4. All 5 nodes receive 4 COMMIT messages. Each runs `verify_quorum_intersection`: PREPARE voters = {ALPHA, BRAVO, CHARLIE, DELTA, ECHO}, COMMIT voters = same set, intersection = 5 >= 4, returns true. Each transitions to EXECUTED.
5. Each node's `MeshNode::broadcast_pbft_stage` observes the local round state reaching EXECUTED. It calls `m_mitigation->execute_response(evidence, CHARLIE)`. MitigationEngine sees evidence sensor=ebpf_entropy, dispatches to `PolicyEnforcer::isolate_target(CHARLIE)`.

### 11.3 Enforcement Event

1. `PolicyEnforcer::isolate_target(CHARLIE)`:
   - Cooldown check: 5s since last enforcement? If not, log and return.
   - `is_safe(CHARLIE)`? No (self is the only safe-listed node).
   - `resolve_target(CHARLIE)` -> 127.0.0.1 (or whatever CHARLIE's IP is).
   - `is_ip_safe(127.0.0.1)`? Returns false (loopback is a special case in `is_ip_safe`).
   - `block_ip_address(127.0.0.1)`:
     - `apply_ebpf_drop`: `bpf_map_update_elem(xdp_blacklist, &127.0.0.1, &1, BPF_ANY)` -> success.
     - Returns true.
2. `m_pbft.ban_peer_local(CHARLIE, "self_detected")`: CHARLIE is added to `m_banned_peers`.
3. `m_proof_chain->append(CONSENSUS_REACHED, CHARLIE, evidence, signature)`: persisted to disk.
4. `m_mitigation->execute_response` returns.

### 11.4 Recovery Event

There is no automatic recovery. CHARLIE is now banned on all 5 nodes. Subsequent ANNOUNCE / BEACON / PBFT messages from CHARLIE are silently dropped (Phase 3 of `verify_message`).

To recover, the operator must:
- Delete `keystore_CHARLIE/` and restart the node (this generates a new identity, which is dual-path-TOFU'd as a "new" peer).
- Or, on each peer, manually remove CHARLIE from `m_banned_peers` (no CLI for this in the current version; would require code change or debugger).
- Or, restart the entire mesh with `mesh_manager.py`.

**[KNOWN LIMITATION]**: There is no CLI command to unban a node.

---

## 12. State Management

### 12.1 State Machines

The system has four state machines:

1. **PBFT consensus** (`PBFTConsensus`): the 6-stage state machine documented in Section 6.
2. **Connection state** (`MeshNode`): the per-peer state transitions in `PeerManager` (DISCOVERED -> BEACON_CONFIRMED -> ANNOUNCE_CONFIRMED -> DUAL_CONFIRMED -> ACTIVE -> BANNED).
3. **Sandbox state** (`TelemetryBridge`): the 4-stage sandbox progression (CHROOT -> UID_DROP -> SECCOMP -> UWSOCKETS).
4. **Enforcement state** (per-target): the per-target transitions in `PolicyEnforcer` (NOT_BLOCKED -> EBPF_BLOCKED -> NFT_BLOCKED -> IPT_BLOCKED).

### 12.2 Persistence

- `keystore_<NODE_ID>/id_ed25519`: the local node's private key. Persists across restarts.
- `keystore_<NODE_ID>/cert.pem`, `key.pem`: the local node's TLS cert and key. Persists across restarts.
- `web/mesh_status.json`: snapshot of the mesh status, written by `TelemetryExporter` with `flock(LOCK_EX)`.
- `logs/<NODE_ID>.log`: stdout and stderr of the agent. Append-only.

There is **no** persistence of:
- `m_rounds`, `m_vote_registry`, `m_node_trust`: lost on restart.
- `m_seen_messages`: lost on restart.
- `m_banned_peers`: lost on restart.

The `StateJournal` (`common/StateJournal.hpp`) is intended to persist some of these (COMMIT records) but its integration with PBFT recovery was not fully verified.

### 12.3 Recovery

- **Process restart**: re-generates identity (if keystore missing), re-broadcasts ANNOUNCE, re-receives gossip. Peer count is re-built from ANNOUNCE / BEACON.
- **Round timeout**: `cleanup_stale_rounds()` evicts a round after 120 s of inactivity.
- **Mesh restart**: `mesh_manager.py` kills all agents, then re-spawns them with a new IPC token.

### 12.4 Synchronization

- **Inter-thread**: `std::mutex m_mtx` in `PBFTConsensus`; `std::shared_mutex m_mtx` in `PolicyEnforcer`; other classes use their own internal mutexes.
- **Inter-process**: via PBFT (consensus) and gossip (telemetry). The mesh converges within 2 s (one heartbeat) of any state change.
- **Atomicity**: `m_sequence_number` in `MeshNode` is `std::atomic<uint64_t>` with `fetch_add(1, memory_order_relaxed)`. Other counters use `std::atomic`.
- **IPC pipe**: the parent writes 4-byte length + JSON; the child reads in a loop. The pipe is `pipe2(O_CLOEXEC)`. The parent closes the write end on shutdown; the child's read returns 0 (EOF) and the child exits.

---

## 13. Failure Handling

### 13.1 Node Crashes

- **Single node crash**: detected by `mesh_manager.py` (polls `p.poll()` every 2 s). Restarted with exponential backoff (2, 4, 8, 16, 30 s; max 5 attempts).
- **Crash during a PBFT round**: the round continues on the remaining 4 nodes. With n=4, quorum=3, intersection is computed from the remaining voters. The round can still complete if the remaining 4 nodes had 3+ in PREPARE and 3+ in COMMIT with intersection >= 3.
- **Crash of the proposer**: the round is left in IDLE. No view-change protocol is broadcast (see Section 6.6 / Section 18). The next heartbeat from another node detecting the same anomaly will initiate a new round.
- **Crash of the IPC client**: the parent (mesh_manager) is unaffected; the agent is unaffected; the client simply disconnects.
- **Crash of the TelemetryBridge child**: the parent detects via `waitpid` on the next `push_telemetry` call. The agent continues; the WebSocket is unavailable until restart.

### 13.2 Message Loss

- **UDP PBFT loss**: handled by re-broadcasts. Each node re-broadcasts the next stage when it observes the previous one, so a lost PREPARE is implicitly recovered when the next PREPARE comes in from a different sender.
- **UDP telemetry loss**: heartbeat every 2 s; loss is bounded to 1-2 cycles.
- **TCP PEX loss**: the new node relies on its next discovery beacon.
- **TLS data loss**: same as UDP; the next heartbeat re-sends.

### 13.3 Invalid Messages

- **Malformed pipe-delimited**: `validate_message` returns false; message rejected.
- **Bad signature**: `verify_message` returns false; `record_failure` increments the counter.
- **Unknown sender**: `verify_message` early-returns without calling `record_failure` (defense: don't punish unknown senders).
- **View mismatch**: round aborts to IDLE.
- **Replay**: silently dropped (no failure recorded).
- **Equivocation**: logged as CRITICAL, sender's trust counter incremented.

### 13.4 Consensus Failures

- **Quorum not reached**: round stays in current state. After 120 s, evicted.
- **Quorum intersection fails**: just-inserted vote rolled back, round aborts to IDLE.
- **All peers crashed**: with n=0, `peer_count() == 1` (self only). The `peer_count() < 1` guard at `MeshNode.cpp:1448` blocks the round from executing (because `peer_count() + 1` from `MeshNode::peer_count()` returns 1, so the check `m_peer_manager.peer_count() < 1` is `0 < 1 = true`, log and return).
- **Equivocation by proposer**: the round may still complete, but the proposer is recorded in `m_node_trust` and eventually auto-banned.

### 13.5 Enforcement Failures

- **All backends fail**: `block_ip_address` returns false. The round is recorded as EXECUTED but the traffic is NOT actually blocked. The ProofChain still records the decision. Operator must intervene.
- **Backend partially fails**: if eBPF succeeds, the return is true. If nftables succeeds after eBPF fails, the return is true. The first success short-circuits the cascade.
- **Loopback target**: `is_loopback` returns true; isolation refused.

### 13.6 Network Failures

- **Discovery beacon lost**: the new node relies on its next attempt.
- **TLS handshake fails**: connection closed; peer not added to TLS roster.
- **Tofu mismatch**: the offending ANNOUNCE is rejected; the peer is not pinned.
- **Switch to offline mode**: if all peers are unreachable, the agent continues to run but cannot initiate cross-node consensus. Local detection still fires; local enforcement is blocked by the `peer_count() < 1` guard.

---

## 14. Configuration System

### 14.1 Configuration Options

All configuration is by environment variable, command-line argument, or hard-coded port mapping. There is no configuration file.

| Option | Type | Default | Set by | Effect | Risk if misconfigured |
|--------|------|---------|--------|--------|----------------------|
| `argv[1]` | string | `ALPHA` | operator | Node ID | Wrong ID = peer set doesn't recognize the node |
| `NEURO_IPC_TOKEN` | string (43 chars) | none (REQUIRED) | mesh_manager.py | Gates the IPC channel | Missing = no IPC commands accepted |
| `NEURO_PBFT_RATE_WINDOW_SEC` | int | 10 | operator | Sliding window for rate limit | Too low = false positives; too high = flood vulnerability |
| `NEURO_PBFT_RATE_MAX` | int | 5 | operator | Max messages per window per peer | Too low = liveness loss; too high = flood vulnerability |
| `NEURO_WS_PORT` | int | per-node mapping | operator | Override dashboard port | Wrong port = dashboard can't connect |
| `NEURO_UNSAFE_NO_SANDBOX` | 0 or 1 | 0 | developer | Skip TelemetryBridge sandbox | **1 = production-insecure; only for dev/WSL2** |
| `NEURO_AUDIT_HOST` | string | 127.0.0.1 | operator | UDP audit destination | Wrong host = audit loss |
| `NEURO_AUDIT_PORT` | int | 9997 | operator | UDP audit port | Wrong port = audit loss |
| `NEURO_SANDBOX_UID` | int | `nobody` UID | operator | Sandbox user | Wrong UID = child cannot bind port |
| `NEURO_SANDBOX_GID` | int | `nogroup` GID | operator | Sandbox group | Same |
| `NEURO_SANDBOX_CHROOT` | string | `/var/empty` | operator | Sandbox chroot dir | Wrong path = child exits with EPERM |

### 14.2 Hard-Coded Constants (in source)

| Constant | Value | File | Notes |
|----------|-------|------|-------|
| `VIEW_CHANGE_TIMEOUT_SEC` | 130 | `PBFT.hpp:47` | Round idle threshold for view-change |
| `ROUND_TTL_SEC` | 120 | `PBFT.hpp:48` | Round eviction threshold |
| `MAX_SEQUENCE_GAP` | 100 | `PBFT.hpp:49` | Replay-protection gap |
| `RATE_LIMIT_WINDOW_SEC` | 10 | `PBFT.hpp:50` | Default; overridable via env |
| `RATE_LIMIT_MAX` | 5 | `PBFT.hpp:51` | Default; overridable via env |
| `MAX_MSG_HISTORY_PER_SENDER` | 10000 | `PBFT.hpp:53` | Per-sender message history cap |
| `kAutoPruneFailures` | 100 | `PBFT.hpp` (member) | Threshold for auto-ban |
| `kLogFailureThresholds` | {6,10,20,50,75} | `PBFT.hpp` (member) | Log sampling thresholds |
| entropy threshold (CRITICAL) | 0.65 | `main.cpp` | Hard-coded |
| entropy threshold (ALERT) | 0.60 | `main.cpp` | Hard-coded |
| 30s grace period | 30e6 us | `main.cpp` | Hard-coded |
| IPC rate limit | 10/s per UID | `main.cpp:264` | Hard-coded |
| 5s enforcement cooldown | 5 s | `PolicyEnforcer.cpp:600` | Hard-coded |

### 14.3 Port Mapping

| Node ID | PBFT UDP | Discovery UDP | PEX TCP | mTLS TCP | WebSocket TCP | IPC Unix |
|---------|----------|----------------|---------|----------|---------------|----------|
| ALPHA | 9999 | 9998 | 10000 | 10500 | 9000 | /tmp/neuro_mesh_ALPHA.sock |
| BRAVO | 9999 | 9998 | 10001 | 10501 | 9010 | /tmp/neuro_mesh_BRAVO.sock |
| CHARLIE | 9999 | 9998 | 10002 | 10502 | 9020 | /tmp/neuro_mesh_CHARLIE.sock |
| DELTA | 9999 | 9998 | 10003 | 10503 | 9030 | /tmp/neuro_mesh_DELTA.sock |
| ECHO | 9999 | 9998 | 10004 | 10504 | 9040 | /tmp/neuro_mesh_ECHO.sock |
| NODE_1..5 | 9999 | 9998 | 10000..10004 | 10500..10504 | 9000..9040 | (same) |

**[ASSUMPTION]**: All PBFT and discovery traffic shares ports 9999 and 9998 (loopback broadcast). The per-node TCP/TLS ports are offset by node ID to avoid conflicts on the same host.

---

## 15. Build System

### 15.1 Toolchain

- **C++ compiler**: `clang++` (required for `-std=c++20` and `-Werror`).
- **C compiler**: `clang` (used for uSockets C sources).
- **eBPF compiler**: `clang` with `-target bpf -D__TARGET_ARCH_x86`.
- **Skeleton generator**: `bpftool gen skeleton`.
- **Linker flags**: `-lssl -lcrypto -lpthread -lbpf -lelf -lz -lseccomp -L/usr/local/lib -lonnxruntime`.

### 15.2 Build Modes

The Makefile supports four build modes, selected at compile time:

| Mode | Flags | Use case |
|------|-------|----------|
| Release (default) | `-O3 -DNDEBUG` | Production |
| `make DEBUG=1` | `-g -O0 -fno-omit-frame-pointer -DDEBUG` | Local development |
| `make SANITIZE=1` | `-g -O1 -fsanitize=address,undefined` | Memory + UB bugs |
| `make THREAD=1` | `-g -O1 -fsanitize=thread` | Race conditions |
| `make COVERAGE=1` | `-g -O0 -fprofile-instr-generate -fcoverage-mapping` | Coverage analysis |

### 15.3 Build Targets

| Target | Output | Source |
|--------|--------|--------|
| `make all` (default) | `bin/neuro_agent` | All C++ source files |
| `make tools` | All tool binaries | `tools/inject_event.cpp`, etc. |
| `make test` | Run all unit tests | `tools/test_*.cpp` |
| `make fuzz` | Build fuzz harnesses | `tests/fuzz/*.cpp` |
| `make fuzz RUN_FUZZ=1` | Run fuzz harnesses (10s each) | |
| `make install PREFIX=/usr/local` | Install to `$PREFIX` | `bin/`, `kernel/`, `models/`, `dashboard/` |
| `make clean` | Remove `obj/` and `bin/` | |
| `make lint` | Run `clang-tidy` on all sources | |
| `make check-deps` | Verify all required tools are present | |
| `make models/isolation_forest.onnx` | Train the ONNX model | `tools/train_iforest.py` (optional) |

### 15.4 Compilation Flow

1. **eBPF compilation**: `kernel/sensor.bpf.c` is compiled with `clang -target bpf` to `obj/sensor.bpf.o`.
2. **Skeleton generation**: `bpftool gen skeleton obj/sensor.bpf.o > obj/sensor.skel.h.tmp` then `mv` to `obj/sensor.skel.h`. This produces the libbpf skeleton header.
3. **uSockets C compilation**: `third_party/uSockets/src/*.c` are compiled with `-std=c11 -O3 -DLIBUS_NO_SSL` to `obj/usockets/*.o`.
4. **C++ compilation**: each source file is compiled with `clang++ -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror` to `obj/<module>/<file>.o`. `cell/NodeAgent.o` depends on the generated `obj/sensor.skel.h`.
5. **Linking**: `bin/neuro_agent` is linked with all object files plus `-lssl -lcrypto -lpthread -lbpf -lelf -lz -lseccomp -L/usr/local/lib -lonnxruntime -lstdc++fs`.
6. **Tool compilation**: each `tools/*.cpp` is compiled and linked with the relevant subset of objects.

### 15.5 Packaging

`make install PREFIX=/usr/local` installs to:
- `$PREFIX/bin/neuro_agent` (the main agent)
- `$PREFIX/bin/inject_event` (the IPC client)
- `$PREFIX/share/neuro-mesh/kernel/sensor.bpf.c` (the eBPF source, for reference)
- `$PREFIX/share/neuro-mesh/kernel/sensor.skel.h` (if generated)
- `$PREFIX/share/neuro-mesh/models/` (the ONNX model, if generated)
- `$PREFIX/share/neuro-mesh/dashboard/` (the dashboard HTML)

There is no `.deb` or `.rpm` packaging. Distribution is source-only.

### 15.6 Build Quirks

- The Makefile does **not** track `.hpp` mtime. After modifying a header (especially `PBFT.hpp`), `touch` a `.cpp` that includes it to force a rebuild.
- `make DEBUG=1` and `make SANITIZE=1` cannot be combined.
- ONNX is **optional**: if `/usr/local/lib/libonnxruntime.so` is not present at link time, the ONNX inference engine is null and the build still succeeds. The agent then runs with a network-only entropy score.
- The eBPF skeleton must be regenerated whenever `sensor.bpf.c` changes.

---

## 16. Deployment Guide

### 16.1 Local Deployment (Single Host, 5 Nodes)

This is the default and most-tested configuration. All 5 nodes run on `127.0.0.1`.

**Prerequisites**:
- Linux kernel 5.4+ (for BPF ring buffer, XDP, `close_range`).
- `clang`, `llvm`, `bpftool`, `libbpf-dev`, `libseccomp-dev`, `libssl-dev`, `nftables` (or `iptables`), `python3`.
- For ONNX: `libonnxruntime` at `/usr/local/lib/`.
- Root or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` for eBPF and XDP.

**Steps**:
```bash
# 1. Build everything
make clean && make

# 2. (Optional) Train the ONNX model
make models/isolation_forest.onnx

# 3. Launch the 5-node mesh
python3 orchestration/mesh_manager.py
# OR
./mesh_dashboard.sh  # tmux grid

# 4. Open the dashboard
open http://localhost:9000  # or any of 9000-9040

# 5. Inject an event (test)
docker exec neuro_charlie /app/inject_event --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL

# 6. Flood the network (test)
docker exec neuro_charlie python3 /app/traffic_generator.py \
  --target 127.0.0.1 --duration 15 --threads 8
```

**Verification**:
- `logs/<NODE_ID>.log` should show `[BOOT] Neuro-Mesh V9.0 Node: <NODE_ID>` followed by stage messages.
- `peers` count in the dashboard should reach 5 within a few seconds.
- An injection of `entropy_spike` to `ALPHA` should produce `[CRITICAL] PBFT Final Quorum Reached! Target ALPHA` on all 5 logs.

### 16.2 Docker Compose Deployment (Decentralized, No Control Plane)

The `docker-compose.yml` deploys 6 services: 1 nginx dashboard, 1 wsbridge (stateless WebSocket proxy), and 5 nodes. Each node uses `network_mode: host` so it can use privileged eBPF.

```bash
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml build --no-cache
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml up -d
docker compose -f /home/yazid/neuro_mesh/docker-compose.yml down
```

The `wsbridge` is a stateless proxy that tries all 5 node backends with failover. It is needed because the browser cannot reach host-network ports from inside the Docker bridge. In real deployments, the browser connects directly to node IPs.

### 16.3 Production Deployment Checklist

Before deploying to production:

- [ ] Replace self-signed TLS certs with real ones (the per-mesh CA is suitable for intranet; for internet-facing, use a real CA).
- [ ] Replace the loopback PBFT broadcast (255.255.255.255:9999) with a more controlled multicast group or unicast mesh.
- [ ] Configure firewall rules to allow UDP 9998, UDP 9999, TCP 10000-10004, TCP 10500-10504, TCP 9000-9040.
- [ ] Set up a log aggregator (Splunk, ELK, Loki) to consume UDP 9997 audit events.
- [ ] Configure Prometheus to scrape the Observability endpoint (per-node, port 9000-9040).
- [ ] Set up alerting on `[CRITICAL] PBFT Final Quorum Reached!` and `[DEFENSE] Self-vote consensus blocked`.
- [ ] Test failure scenarios: kill one node, kill two nodes, kill the IPC client, kill the dashboard child.
- [ ] Verify the safe-list contains the operator's IP.
- [ ] Verify the operator can read `/tmp/neuro_mesh_token` (or have a way to set `NEURO_IPC_TOKEN`).
- [ ] Run `make fuzz RUN_FUZZ=1` to confirm no parser crashes on adversarial input.
- [ ] Run `make test` to confirm all unit tests pass.
- [ ] Review the ProofChain export format and decide where to archive it.

### 16.4 Kubernetes Deployment

The `k8s/` directory contains:
- `k8s/helm/`: a Helm chart (not fully verified).
- `k8s/manifests/`: raw Kubernetes manifests (not fully verified).

**[ASSUMPTION]**: Kubernetes deployment uses hostNetwork + privileged containers to allow eBPF. DaemonSet is the natural fit.

---

## 17. Operational Guide

### 17.1 Monitoring

- **Logs**: each agent logs to `logs/<NODE_ID>.log`. Tail with `tail -f logs/ALPHA.log`.
- **Dashboard**: open `http://localhost:9000` (or any node's WebSocket port).
- **Audit log**: UDP 9997. Capture with `nc -u -l 9997`.
- **Prometheus**: scrape the Observability endpoint (port unspecified, depends on `Observability.cpp` config).

### 17.2 Troubleshooting Matrix

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Agent fails to start with `bpf()` error | Kernel headers missing or CAP_BPF not held | Install `linux-headers-$(uname -r)`, run as root or with `CAP_BPF` |
| Agent fails to start with `bpf_obj_get` error | Previous run's pinned maps are stale | `rm -rf /sys/fs/bpf/neuro_mesh*` |
| `[IPC] REJECTED: invalid token` | Token file out of sync with env var | Restart the mesh via `mesh_manager.py` (it regenerates the token) |
| `[SECURITY] TOFU dual-path MISMATCH` | A peer is presenting different keys on BEACON vs ANNOUNCE | Investigate the peer; may be a misconfigured node or an attack |
| `[DEFENSE] Self-vote consensus blocked - no peers online` | No peers discovered yet | Wait for discovery (up to 30 s) or check `set_seed_peers` |
| `[PBFT] QUORUM INTERSECTION FAILED` | A peer is voting disjoint PREPARE/COMMIT sets | Investigate the peer; may be a partition attack |
| WebSocket 404 on `http://localhost:9000` | TelemetryBridge child died | Check agent stderr; restart agent |
| `iptables: Permission denied` | Agent not root | Run as root or grant `CAP_NET_ADMIN` |
| `nft: not found` | nftables not installed | Install `nftables` or rely on eBPF/iptables |
| Slow startup (>10s) | ONNX model load is slow | Train with fewer samples (`tools/train_iforest.py --samples 1000`) or remove the model file |
| Agent crashes repeatedly | Bug in PBFT or enforcer | Capture core dump, run `make SANITIZE=1` to reproduce |

### 17.3 Diagnostics

- **Process state**: `ps aux | grep neuro_agent` should show 5 processes.
- **Open ports**: `ss -tulnp | grep neuro` should show UDP 9998, 9999 and TCP 10000-10004, 10500-10504, 9000-9040.
- **BPF maps**: `ls /sys/fs/bpf/neuro_mesh*` should show 2 maps per node.
- **Keystores**: `ls keystore_*/` should show one directory per node.
- **ProofChain**: `cat web/mesh_status.json | jq` should show the latest mesh state.

### 17.4 Log Interpretation

| Log line | Meaning |
|----------|---------|
| `[BOOT] Neuro-Mesh V9.0 Node: <id>` | Process started |
| `[NETWORK] Broadcasted signed identity to local subnet.` | ANNOUNCE sent |
| `[NETWORK] Discovered verified peer: <id> at <ip>` | ANNOUNCE received and verified |
| `[SECURITY] TOFU dual-path MISMATCH for <id> via ANNOUNCE` | Conflicting keys on different paths; peer rejected |
| `[DEFENSE] Invalid message: malformed` (too few tokens) | Malformed pipe-delimited input |
| `[PBFT] CRITICAL: Auto-banning peer <id> after 100 signature failures` | Peer permanently banned |
| `[PBFT] QUORUM INTERSECTION FAILED at COMMIT->EXECUTED` | Safety guard triggered; round aborted |
| `[PBFT] EQUIVOCATION DETECTED: <id> seq=<n> view=<v>` | Peer signed two conflicting messages |
| `[CRITICAL] PBFT Final Quorum Reached! Target <id>` | Round completed; enforcement imminent |
| `[DEFENSE] Self-vote consensus blocked - no peers online (n=<x>, quorum=<y>)` | Round cannot complete (insufficient peers) |
| `[BAN_PEER] Cross-node ban consensus for <id>` | Cross-node ban round initiated |
| `[DECENTRALIZED] Self-initiating PBFT consensus (entropy=<v>)` | Local node proposed to isolate itself |
| `[IPC] REJECTED: invalid token from uid=<u> pid=<p>` | IPC auth failure |
| `[IPC] RATE LIMITED: <id>` | Per-UID rate limit hit |
| `[ENFORCER] IP <ip> blocked via eBPF blocklist map` | Enforcement applied via eBPF |
| `[ENFORCER] CRITICAL: All enforcement backends failed for IP <ip>` | Enforcement failed |
| `[ENFORCER] REFUSED: <target> is safe-listed` | Safe-list prevented isolation |
| `[SUSPICIOUS ACTIVITY] <target> is loopback` | Loopback isolation refused |
| `[MITIGATION ERROR] <msg>` | MitigationEngine threw |
| `[SECCOMP] FATAL: <msg>` | Sandbox initialization failed (child exits) |
| `[TELEMETRY_BRIDGE] Child spawned (pid=<n>), starting sandbox sequence...` | TelemetryBridge child started |
| `[SYS] Interrupt signal received. Initiating shutdown...` | Signal received; clean shutdown in progress |
| `[SHUTDOWN] Halting MeshNode...` | MeshNode stopped |
| `[SHUTDOWN] System terminated safely.` | Clean exit |

---

## 18. Security Review Notes

### 18.1 Trust Assumptions

- The local Linux kernel is trustworthy.
- The OpenSSL and libseccomp runtimes are trustworthy.
- The BPF verifier is trustworthy.
- The operator is non-adversarial and protects the IPC token.
- The network is at most semi-trusted (an eavesdropper is possible; a MITM is possible but detected by dual-path TOFU).

### 18.2 Security Boundaries

See Section 7.2 for the four trust boundaries (T1-T4).

### 18.3 Known Risks

The following risks have been identified during this review. They are **not** blockers for a single-host deployment but should be addressed before multi-host production deployment.

| ID | Severity | Risk | Mitigation status |
|----|----------|------|-------------------|
| L1 | High | View-change protocol is implemented in `needs_view_change()` but **not** broadcast on the wire. A round that stalls (e.g., because the proposer crashed) will time out at 120 s and require a new round to be initiated. | **OPEN** - needs implementation of a `VIEW_CHANGE` message type and view-change round. |
| L2 | High | No persistent state for in-flight rounds. A node crash mid-round loses the round; the remaining nodes continue but the crashed node re-broadcasts ANNOUNCE on restart and the round is implicitly aborted. | **OPEN** - `StateJournal` integration with PBFT recovery is not complete. |
| L3 | Medium | Key rotation is not supported. The `keystore_<NODE_ID>/` directory must be deleted and the node restarted to generate a new key. | **OPEN** - no CLI or wire protocol for key rotation. |
| L4 | Medium | No automatic unban mechanism. A banned peer is banned for the process lifetime. | **OPEN** - the `m_banned_peers` set has no expiry. |
| L5 | Medium | The TelemetryBridge WebSocket is unencrypted. A network observer on the same host can see all telemetry. | **OPEN** - WebSocket should be served over TLS. |
| L6 | Medium | The IPC socket at `/tmp/neuro_mesh_<id>.sock` is in `/tmp` (world-writable parent). The token check mitigates this, but a local attacker could `unlink` the socket and create a symlink, leading to confusion. | **PARTIALLY MITIGATED** - the token check is the primary defense. Consider using an abstract namespace socket (`\0neuro_mesh_<id>`). |
| L7 | Low | The ONNX model is loaded from a fixed path. An attacker who can write to `models/isolation_forest.onnx` can replace it. | **OPEN** - the model should be signed and verified on load. |
| L8 | Low | Rate limit thresholds are sampled at 6, 10, 20, 50, 75 to avoid log spam. An attacker who knows the sampling pattern can time their attacks to avoid the log entries. | **PARTIALLY MITIGATED** - the actual ban still fires at 100, but the log evidence is sparse. |
| L9 | Low | The eBPF `lockdown` key (`0xFFFFFFFF`) is a kill switch but is currently only used in tests. A misconfigured production deployment could leave it set. | **OPEN** - should be removed or guarded with a stronger check. |
| L10 | Low | Audit log uses UDP, which can be lost. There is no queue. | **OPEN** - the audit log should be persisted locally. |

### 18.4 Areas Requiring Special Care

1. **The quorum-intersection guard at COMMIT-to-EXECUTED** (`PBFT.hpp:546-573`). This is the most important safety property. Any modification to the consensus state machine must preserve this check. If relocating, ensure both PREPARE and COMMIT voter sets are populated at the relocation point.

2. **The dual-path TOFU check** (`MeshNode.cpp` `process_message` ANNOUNCE branch). This is the second-most important safety property. Any modification to the discovery / ANNOUNCE handling must preserve the requirement that `m_pbft.register_peer_key()` is only called when `dual_confirmed == true`.

3. **The safe-list** (`PolicyEnforcer::add_safe_node`). The self node must always be in the safe-list. The order in `main.cpp:516-518` is intentional: `set_node_id` first, then `add_safe_node` immediately. Do not separate them.

4. **The fork+exec helpers** (`PolicyEnforcer::fork_exec_wait` and `fork_exec_capture`). The `close_range(3, max_fd, 0)` call is critical to prevent FD leak to the child. Do not replace with a per-FD loop (race condition). The 64 KiB output cap is critical to prevent OOM.

5. **The TelemetryBridge sandbox**. The four stages (chroot, fs-isolation, UID drop, seccomp) are in order for a reason: chroot requires CAP_SYS_CHROOT (root); UID drop requires the user to be root; seccomp requires the kernel to support `SCMP_ACT_KILL_PROCESS`. The order ensures that if any stage fails, the child exits cleanly.

6. **The IPC token** (`NEURO_IPC_TOKEN`). This is the **only** authentication for the IPC command channel. It must be:
   - Generated by a CSPRNG (`secrets.token_urlsafe(32)`).
   - Stored in a 0600-mode file.
   - Required as the first line of any IPC command (`AUTH <token>\n`).
   - Validated against the env var.
   Do not remove any of these checks.

### 18.5 Cryptographic Primitives

| Primitive | Algorithm | Source | Notes |
|-----------|-----------|--------|-------|
| Signatures | Ed25519 (RFC 8032) | `crypto/CryptoCore.cpp` | OpenSSL EVP-based; deterministic; 64-byte signatures |
| Hashing | SHA-256 | `crypto/CryptoCore.cpp` | Used for round keys, message hashes, ProofChain chaining |
| TLS | TLS 1.3 (RFC 8446) | `net/TransportLayer.cpp` | mTLS; ECDHE key exchange; AES-GCM or CHACHA20-POLY1305 |
| Certificate format | X.509 | `crypto/CertificateAuthority.cpp` | Self-signed; per-mesh CA |
| Key serialization | PEM (RFC 7468) | `crypto/CryptoCore.cpp` | For Ed25519 keys |
| Random | OpenSSL CSPRNG | indirect (via `secrets` in Python) | For IPC token; for Ed25519 keygen |

### 18.6 Audit Trail

- **ProofChain**: append-only Merkle log of consensus events. Exported to `web/mesh_status.json` with `flock(LOCK_EX)`.
- **Audit log**: UDP 9997, one-way, best-effort. No persistence.
- **Logs**: per-node `logs/<NODE_ID>.log`. Captured by `mesh_manager.py`.

The audit trail is sufficient for post-hoc investigation of who isolated whom and when. It is **not** designed for non-repudiation in a regulatory sense (the ProofChain is per-process, not global).


---

## 19. Contributor Guide

### 19.1 Coding Conventions

- **C++20** is required. Use `auto`, structured bindings, concepts where they improve clarity.
- **No exceptions in hot paths** - the PBFT state machine and the enforcement cascade should not throw. Use `Result<T, E>` instead.
- **RAII for all resources** - `UniqueFD`, `UniquePKEY`, `std::unique_ptr` for OpenSSL objects. No raw `new`/`delete`.
- **No `system(3)`** - use `fork_exec_wait` or `fork_exec_capture` from `PolicyEnforcer`. This is a security requirement, not a style preference.
- **No shell injection vectors** - pass arguments as separate `argv[]` entries.
- **Wall + Wextra + Wpedantic + Wshadow + Werror** - the build will fail on warnings. Fix them.
- **No `using namespace std;`** in headers. In `.cpp` files, prefer explicit qualification.
- **Comments in English**, ASCII only. Use ASCII diagrams in comments for complex flows.
- **Doxygen-style comments** for public APIs. Internal functions may use `//` comments.

### 19.2 Architecture Principles

1. **Defense in depth**: never rely on a single check. The consensus signature check is one layer; the rate limit is another; the TOFU check is another. Each is independent.

2. **Cryptographic binding**: signatures must bind everything that varies - stage, target, evidence, sequence number, view, and prev hash. A signature that binds only some of these is a vulnerability.

3. **Fail closed, not open**: if a check fails, the message is dropped. If a backend fails, the cascade continues. If a recovery is impossible, log and exit.

4. **Idempotency**: every operation should be safe to retry. The vote registry is a `set`, so duplicates are no-ops. The rate limit is a sliding window, so re-sends within the window are no-ops.

5. **Least privilege**: the TelemetryBridge child runs in a sandbox. The fork+exec helpers close all FDs. The safe-list prevents self-isolation.

6. **Observability**: every important event is logged. The heartbeat is a JSON document. The ProofChain is a Merkle log. The audit log is a UDP stream.

### 19.3 Safe Modification Practices

When modifying the codebase, follow these practices:

1. **Before changing PBFT**: read `consensus/PBFT.hpp` in full. Understand the quorum-intersection guard. Understand the rate limit. Understand the replay protection. Make a small change. Run `make test` and the PBFT-specific test. Run a live mesh and observe.

2. **Before changing enforcement**: read `enforcer/PolicyEnforcer.cpp` in full. Understand the cascade. Understand the safe-list. Understand the fork+exec helpers. Test with `tools/test_enforcer`.

3. **Before changing IPC**: read `main.cpp:257-330` and `tools/inject_event.cpp` in full. Understand the token check, the UID check, the rate limit. Make sure the token is required for **every** command. Test with `tools/inject_event` and a wrong token.

4. **Before changing crypto**: read `crypto/CryptoCore.hpp` in full. The signature blob is **not** just `data`; it is `stage + "|" + target + "|" + evidence + "|" + seq + "|" + view + "|" + prev_hash`. Any change to this binding is a security regression.

5. **Before changing the eBPF program**: rebuild the skeleton with `make clean && make`. Test with a live mesh. The `close_range` syscall in fork+exec is required; do not remove it.

6. **Before changing the TelemetryBridge sandbox**: read `telemetry/TelemetryBridge.cpp:180-400` in full. The four stages are in order for a reason. Do not reorder. Do not add new syscalls to the whitelist without understanding why they are needed (uWebSockets and uSockets are the only consumers).

7. **Before adding a new tool**: add a target to the Makefile's `tools` rule. Test with `make tools && make test`. Document in this file.

8. **Before adding a new module**: read the existing module structure. Follow the naming convention (`<module>/<Class>.hpp` + `<module>/<Class>.cpp`). Update the Makefile's `SRCS` list. Update this file's Section 4 (System Components).

### 19.4 Pull Request Checklist

Before submitting a PR, verify:

- [ ] `make clean && make` succeeds with no warnings.
- [ ] `make test` passes all unit tests.
- [ ] `make lint` reports no `clang-tidy` issues.
- [ ] `make fuzz RUN_FUZZ=1` runs without crashes for 10 s per harness.
- [ ] The change is documented in the relevant section of this file.
- [ ] The PR description includes the test plan.
- [ ] The PR includes a benchmark if performance-sensitive.
- [ ] The PR does not include any secrets, tokens, or keystore files.
- [ ] The PR does not include any `_archive_old/` or `_offloaded/` files.
- [ ] The PR does not change the wire format without a migration plan.
- [ ] The PR does not change the consensus state machine without a security review.
- [ ] The PR does not change the IPC protocol without a security review.
- [ ] The PR does not change the enforcement cascade without a security review.
- [ ] The PR does not change the eBPF program without a security review.

---

## 20. File & Directory Reference

### 20.1 Source Directories

| Directory | Purpose | Key files |
|-----------|---------|-----------|
| `kernel/` | eBPF probes | `sensor.bpf.c` (4 kprobes + 1 XDP), `sensor.skel.h` (generated), `vmlinux.h` (kernel types) |
| `cell/` | Per-node intelligence | `NodeAgent.hpp`/`.cpp` (eBPF loader, ring drain), `InferenceEngine.hpp`/`.cpp` (ONNX model) |
| `consensus/` | P2P mesh and BFT state machine | `MeshNode.hpp`/`.cpp` (5-thread orchestrator), `PBFT.hpp` (header-only 6-stage state machine), `PeerManager.hpp`/`.cpp` (peer table, TOFU) |
| `crypto/` | Ed25519 identity and TLS | `CryptoCore.hpp`/`.cpp` (sign/verify/hash), `KeyManager.hpp`/`.cpp` (persistent keystore), `CertificateAuthority.hpp`/`.cpp` (self-signed TLS), `ProofChain.hpp` (Merkle log) |
| `enforcer/` | Policy enforcement | `PolicyEnforcer.hpp`/`.cpp` (eBPF/nftables/iptables cascade), `MitigationEngine.hpp`/`.cpp` (application response) |
| `telemetry/` | Structured logging and WS bridge | `TelemetryBridge.hpp`/`.cpp` (sandboxed WS), `AuditLogger.hpp`/`.cpp` (UDP JSON), `TelemetryExporter.hpp` (file snapshot), `Observability.hpp`/`.cpp` (metrics) |
| `net/` | TLS 1.3 transport | `TransportLayer.hpp`/`.cpp` (OpenSSL wrapper) |
| `attacks/` | Attack simulation | `AttackSimulator.hpp`/`.cpp` (UDP flood, equivocation) |
| `common/` | Shared utilities | `UniqueFD.hpp` (RAII FD), `Result.hpp` (Result<T,E>), `StateJournal.hpp` (write-ahead log), `Base64.hpp` (encoding) |
| `orchestration/` | Python glue | `mesh_manager.py` (supervisor + token gen), `ws_proxy.py` (stateless WS bridge), `control_server.py` (legacy), `anomaly_classifier.py`, `bridge_api.py`, `web_server.py`, `neuro_ctl.py` |
| `tools/` | CLI utilities and tests | `inject_event.cpp` (IPC client), `attack_injector.cpp`, `attack_runner.py`, `register_attacker.cpp`, `test_crypto.cpp`, `test_enforcer.cpp`, `test_pbft.cpp`, `train_iforest.py` |
| `dashboard/` | Operator UI (vanilla JS) | `index.html` (single-file, no dependencies) |
| `k8s/` | Kubernetes manifests | `helm/`, `manifests/` |
| `docs/` | Project documentation | `KNOWN_LIMITATIONS.md`, `THREAT_MODEL.md`, `adr/`, `benchmarks/` |
| `tests/integration/` | End-to-end tests | `test_5node_chaos.py`, `test_adversarial_5node.py`, `test_autoban.py` |
| `bin/` | Build output | `neuro_agent`, `inject_event`, `attack_injector`, `register_attacker`, test binaries |
| `logs/` | Per-node log files | `ALPHA.log`, `BRAVO.log`, `CHARLIE.log`, `DELTA.log`, `ECHO.log` |
| `keystore_<NODE_ID>/` | Per-node identity | `id_ed25519`, `cert.pem`, `key.pem` |
| `models/` | ONNX model (optional) | `isolation_forest.onnx` |
| `web/` | Dashboard snapshot | `mesh_status.json` |
| `obj/` | Build artifacts | `<module>/*.o` |
| `third_party/` | Vendored dependencies | `uWebSockets/`, `doctest/` |
| `_archive_old/` | Archived experiments | Old monolithic client, ML models, etc. |

### 20.2 Key Files (Detail)

**`main.cpp` (675 lines)** — Entry point. Initializes all subsystems, installs signal handler, runs the heartbeat loop and the IPC listener.

**`consensus/MeshNode.cpp` (1929 lines)** — P2P coordinator. Five threads (p2p_listener, discovery_beacon, tcp_listener, tls_acceptor, liveness_monitor). Handles ANNOUNCE, BEACON, PBFT, and TELEMETRY messages.

**`consensus/PBFT.hpp` (751 lines, header-only)** — The BFT state machine. Defines `P2PMessage`, `PBFTStage`, `PBFTConsensus`. Implements `verify_message()`, `advance_state()`, `verify_quorum_intersection()`, `cleanup_stale_rounds()`, `detect_equivocation()`, `check_rate_limit()`, `record_failure()`, `record_success()`, `propose_ban()`.

**`enforcer/PolicyEnforcer.cpp` (782 lines)** — Three-backend isolation. Probes capabilities, runs cascade, uses `fork_exec_wait` and `fork_exec_capture` (no shell).

**`telemetry/TelemetryBridge.cpp` (602 lines)** — Forked child process. Applies chroot, setuid, no-new-privs, seccomp-bpf. Runs uWebSockets in the sandbox.

**`kernel/sensor.bpf.c` (195 lines)** — eBPF program. Attaches to `sys_enter_execve`, `sys_enter_sendto`, `sys_enter_sendmsg`, `sys_enter_connect`. Emits events to a 256 KiB ring buffer. Contains an XDP dropper.

**`orchestration/mesh_manager.py` (123 lines)** — Python supervisor. Generates IPC token, launches 5 nodes with token in env, monitors and restarts on crash with exponential backoff.

**`tools/inject_event.cpp` (177 lines)** — IPC client. Reads auth token from `/tmp/neuro_mesh_token`, sends `AUTH <token>\n` handshake, then `CMD:INJECT`.

**`dashboard/index.html`** — Single-file vanilla JS operator UI. No build step.

**`Makefile`** — Build system. BPF compilation, skeleton generation, ONNX model training (optional), main binary, test binaries, fuzz harnesses, install, lint, clean.

**`docker-compose.yml`** — 6-service stack: dashboard (nginx), wsbridge, 5 nodes. Each node uses `network_mode: host`.


---

## 21. Glossary

| Term | Definition |
|------|------------|
| **Agent** | A single `neuro_agent` process running on a host. Has a unique node ID, Ed25519 keypair, and TLS cert. |
| **ANNOUNCE** | A signed message broadcast on the discovery port to inform other nodes of a peer's identity. Part of the dual-path TOFU. |
| **Backend** | In the enforcement cascade, one of eBPF XDP, nftables, or iptables. |
| **BFT** | Byzantine Fault Tolerance. The property of a consensus protocol that allows it to reach agreement despite f malicious participants, where n = 3f+1. |
| **Banned peer** | A peer added to `m_banned_peers` either locally (after 100 signature failures) or via a `BAN_PEER` PBFT round. |
| **BPF** | Berkeley Packet Filter. In Linux, also refers to extended BPF (eBPF), a technology for running sandboxed programs in kernel space. |
| **Byzantine** | A participant that behaves arbitrarily, including lying, crashing, or colluding. The BFT property holds against up to f Byzantine participants. |
| **CA** | Certificate Authority. In mTLS, the issuer of peer certificates. Neuro-Mesh uses self-signed certs and TOFU pinning, not a CA. |
| **Commit** | The third PBFT stage. A `COMMIT` vote says "I have seen enough PREPARE votes and will execute." |
| **Consensus** | The process by which independent nodes agree on a value. Neuro-Mesh uses PBFT. |
| **Defense in depth** | Multiple independent layers of security. Neuro-Mesh: BPF verifier + signature + dual-path TOFU + rate limit + replay protection + safe-list. |
| **Dual-path TOFU** | Trust on first use across two independent channels (UDP beacon + ANNOUNCE). A peer's key is accepted only if both paths agree. |
| **eBPF** | Extended BPF. A Linux kernel technology for running sandboxed programs in kernel space. |
| **Equivocation** | Signing two conflicting messages with the same sequence number. Detected post-hoc. |
| **Ed25519** | A modern elliptic-curve signature algorithm. Small signatures (64 bytes), fast verification, deterministic signatures. |
| **EXECUTED** | The final PBFT stage. Isolation has been applied locally. The decision is final and recorded in the ProofChain. |
| **Fork+exec** | A pattern for running subprocesses safely. `fork()` creates a child process; `execv(path, argv)` replaces the child's memory. Arguments are passed as separate `argv[]` entries, preventing shell injection. |
| **Gossip** | Periodic broadcast of state to all known peers. Provides eventual consistency. |
| **Heartbeat** | A periodic 2-second tick that computes and broadcasts telemetry, decays the inference score, and initiates consensus rounds. |
| **Identity** | The persistent public key of a node. Used to verify signatures and to pin in TOFU. |
| **IPC** | Inter-Process Communication. Neuro-Mesh uses Unix domain sockets at `/tmp/neuro_mesh_<NODE_ID>.sock`, guarded by a per-boot shared-secret token. |
| **Isolation** | The act of cutting a compromised node off from the rest of the mesh. Achieved by adding its IP to the eBPF XDP blocklist, an nftables drop rule, and/or an iptables REJECT rule. |
| **Merkle log** | A hash chain where each entry contains the hash of the previous entry. Any tampering invalidates the chain from that point forward. |
| **mTLS** | Mutual TLS. Both client and server present certificates; both verify the other's chain. |
| **Node** | A single agent instance. Identified by its `NODE_ID` (e.g., `ALPHA`, `BRAVO`). |
| **ONNX** | Open Neural Network Exchange. A model format that allows training in one framework (e.g., scikit-learn) and inference in another (e.g., ONNX Runtime). Neuro-Mesh uses an Isolation Forest model exported to ONNX. |
| **PBFT** | Practical Byzantine Fault Tolerance. A consensus protocol that reaches agreement in the presence of Byzantine participants. |
| **PEX** | Peer Exchange. A TCP connection used to dump a node's full peer list to a newly-known peer. |
| **PRE_PREPARE** | The first PBFT stage. The proposer broadcasts intent. |
| **PREPARE** | The second PBFT stage. A `PREPARE` vote says "I have seen the PRE_PREPARE and agree with it." |
| **ProofChain** | The per-process Merkle log of consensus events. |
| **Quorum** | The minimum number of votes required to advance a PBFT stage. With n=5, quorum is typically 4. |
| **Quorum-intersection guard** | The safety check at the `COMMIT -> EXECUTED` transition that ensures the PREPARE and COMMIT voter sets overlap by at least a quorum. |
| **Rate limit** | A sliding-window constraint on the number of PBFT messages a single peer may send. Default: 5 messages per 10 seconds. |
| **Roster** | The set of currently known peers, maintained by `PeerManager`. |
| **Safe-list** | A set of node IDs and IPs that may never be isolated. The local node is always in the safe-list. |
| **Sandbox** | A restricted execution environment. The TelemetryBridge child runs in a chroot + dropped-UID + seccomp sandbox. |
| **Seccomp** | Secure Computing Mode. A Linux kernel feature that restricts the syscalls a process may invoke. |
| **Sequence number** | A monotonically increasing per-sender counter used to detect replays and out-of-order delivery. |
| **TelemetryBridge** | The sandboxed child process that serves the dashboard WebSocket. |
| **TOFU** | Trust On First Use. A peer's key is accepted on first contact and pinned for all subsequent contacts. Combined with dual-path here for defense in depth. |
| **View** | A PBFT concept representing the current leader. Not fully implemented in this codebase (see Section 6.6 / Section 18). |
| **XDP** | eXpress Data Path. A Linux kernel technology for running BPF programs at the NIC driver level, before the kernel network stack. |
| **Zone** | A logical grouping of nodes. Not currently used; reserved for future hierarchical deployment. |

---

## Document Metadata

- **Generated**: 2026-06-05
- **Source code version**: as of the commit hash at the time of writing
- **Total lines**: ~2200
- **Verification method**: every claim is derived from the source code; line numbers are provided where they are accurate. Sections marked `[NOT YET VERIFIED]` or `[ASSUMPTION]` indicate areas where the author did not have direct line-by-line visibility into the source.
- **Next review**: when the source changes, update the relevant section. The structure is stable; only the content should change.
- **Maintenance**: the contributor guide (Section 19.4) requires that PRs update the relevant section of this file.
