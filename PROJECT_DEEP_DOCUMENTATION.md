# Neuro-Mesh — Deep Technical Reference

*Document version: 2026-06-05 · Tracks `main` at commit `04fdad0`*

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

### 1.1 Purpose

Neuro-Mesh is a **decentralized, peer-to-peer security fabric** for detecting and
isolating compromised nodes in a network cluster. It is implemented in modern
C++20 with eBPF kernel observability and a Practical Byzantine Fault Tolerance
(PBFT) consensus protocol operating over UDP.

The system is designed for environments where:
- No single node is fully trusted.
- The network is the threat surface (compromised peers can lie, replay, equivocate).
- Detection must happen at the kernel boundary (sub-millisecond, before payload reaches userspace).
- Mitigation must be automatic, peer-validated, and cryptographically defensible.
- Central control planes are unavailable, undesirable, or compromised.

### 1.2 Problem Being Solved

Traditional intrusion detection systems (IDS) and intrusion prevention systems
(IPS) suffer from three structural weaknesses:

1. **Single point of trust.** Central collectors and analysts are high-value targets. A compromised analyst lies about every event.
2. **Detection-to-action gap.** Anomaly detectors that alert humans create a mean-time-to-mitigate floor measured in minutes; targeted attacks exploit exactly that window.
3. **Perimeter brittleness.** Static rules break against novel attacks; ML detectors in the data plane break against adversarial inputs.

Neuro-Mesh addresses all three:
- **No central collector.** Every node runs the same code and participates in consensus. To lie about an event, an attacker must compromise the proposing node *and* at least `f+1` of the `3f+1` total — for `N=5, f=1` this means controlling the proposer + 1 other peer.
- **Detection-to-isolation in <100ms p50.** eBPF ring buffer → ONNX inference → PBFT round → nftables DROP happens in a single heartbeat tick.
- **PBFT state machine + signature binding.** A malicious detector cannot forge a vote for a stage it did not witness, cannot replay a PREPARE as a COMMIT, and cannot equivocate without detection by the `EquivocationEvidence` tracker.

### 1.3 Design Goals

| Goal | Mechanism |
|------|-----------|
| Decentralization | No aggregator, no control plane. Any node can serve the dashboard. |
| Crash-safety | Ed25519 identity persists in `~/.neuro_mesh/keys/{id}.key`; PBFT rounds evict on 120s timeout. |
| Byzantine fault tolerance | PBFT over UDP, f=1 with N=5, requires 2f+1=3 honest votes per stage. |
| Zero-trust self-vote | Self-votes verified through the same `verify_message()` path as external votes. |
| Kernel-native observability | eBPF kprobes on `sys_execve`, `sys_sendto`, `sys_sendmsg`, `sys_connect` + XDP dropper. |
| Privilege separation | TelemetryBridge child: chroot + nobody uid + 65-syscall seccomp-BPF default-kill. |
| Defensive crypto | Ed25519 signatures; TLS 1.3 mTLS; X.509v3 self-signed certs pinned via signed PEM in V3 discovery. |
| Production-grade C++ | `clang++ -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror`; `static_assert` on struct sizes. |
| Operator ergonomics | Plain-text IPC socket `/tmp/neuro_mesh_{id}.sock` with token auth; `inject_event` CLI. |
| Live visualization | Zero-dependency Vanilla JS dashboard via uWebSockets. |

### 1.4 Non-Goals

- **Sybil resistance at identity provisioning.** A node's Ed25519 keypair is assumed to be provisioned by an out-of-band PKI or RA. The mesh does not attempt to prevent an attacker from generating many keys.
- **Confidentiality of telemetry.** Telemetry is signed but not encrypted at rest; gossip is plaintext. (Transport-level confidentiality is provided by TLS 1.3 on the TCP PEX port.)
- **Hardware root-of-trust.** We assume a software-only attack model. Spectre, Rowhammer, TPM-bypass, etc. are out of scope.
- **Scale beyond ~100 nodes.** PBFT is `O(n²)` in message count. Current design tested at N=5.
- **Replacing the kernel firewall.** We use `nftables`/`iptables`/`XDP` as enforcement primitives.

### 1.5 Major Capabilities

1. **eBPF observability** — kernel-level syscall tracing (execve, sendto, sendmsg, connect) with zero-copy ring buffer delivery to userspace.
2. **ONNX anomaly detection** — entropy analysis + isolation forest scoring with feature extraction from syscall metadata.
3. **PBFT consensus** — multi-stage state machine (IDLE → PRE_PREPARE → PREPARE → COMMIT → EXECUTED → BAN_PEER) with equivocation detection and timing obfuscation.
4. **mTLS 1.3 transport** — TLS 1.3 handshake with X.509v3 self-signed certs pinned via signed PEM broadcast in V3 discovery beacons.
5. **Multi-backend enforcement** — nftables (preferred), iptables (fallback), eBPF blocklist map, process suspension via `kill -STOP`/`SIGKILL`.
6. **Sandboxed telemetry WebSocket** — uWebSockets child process locked down via chroot + setresuid + 65-syscall seccomp-BPF default-kill.
7. **Persistent state** — `StateJournal` records all PBFT decisions for crash recovery.
8. **TOFU dual-path trust** — UDP broadcast discovery + TCP mTLS handshake; peer is trusted only after both paths confirm identical identity.
9. **Zero-trust safe list** — `add_safe_node()` prevents a node from ever isolating itself or critical infrastructure, even under PBFT consensus pressure.
10. **Decentralized telemetry gossip** — every node broadcasts its view to all peers; any node can serve the dashboard with the full mesh state.
11. **IPC command interface** — Unix domain socket with shared-secret token auth and per-UID rate limiting.
12. **Replay/equivocation protection** — signatures bind `(stage + target + evidence)`, plus `EquivocationEvidence` tracker detects conflicting votes from the same `(sender, view, sequence)`.

---

## 2. Executive Summary

Neuro-Mesh turns a cluster of N=5 Linux hosts into a self-defending P2P fabric.
Each host runs an identical `neuro_agent` daemon that observes the kernel via
eBPF, runs anomaly detection, votes on suspected compromises via PBFT, and
enforces isolation through `nftables`/`iptables`/`XDP` — all without a central
controller, and all without trusting any single peer.

**The core insight:** in a hostile network, you cannot trust your peer, but
you can trust that `2f+1` of `3f+1` peers will honestly vote. PBFT is the
mechanism; Ed25519 signatures on every vote are the enforcement.

**Why a new system?** Existing solutions assume a trusted controller. SIEMs
centralize detection; EDR agents centralize response. Both create high-value
targets. Neuro-Mesh distributes both detection and response.

**What's new in this revision (commit 04fdad0):**
- Actionable eBPF error messages that tell the operator exactly which kernel
  capability to grant.
- TLS 1.3 mTLS is now actually functional — the previously-defined-but-never-called
  `trust_peer_cert()` is now invoked on dual-path confirmation.
- 9 additional syscalls whitelisted in the sandbox (poll, clock_nanosleep,
  restart_syscall, clone3, mremap, kill, getppid, getuid, getgid) — the bridge
  child was being killed by seccomp default-kill on legitimate operations.
- Passive EOF pipe detection replaces the `kill(getppid, 0)` liveness check
  that was returning EPERM under unprivileged UID.

**Who should read this document:**
- **Security auditors** verifying the cryptographic and protocol claims.
- **Senior engineers** deploying the system or extending it.
- **Maintainers** debugging the consensus or transport layers.
- **New contributors** onboarding to the codebase.

**What this document is NOT:**
- A user manual (see `README.md` for that).
- A marketing document (every claim is backed by file:line citations).
- A complete code listing (the codebase is 12,000+ lines of C++).

---

## 3. Architecture Overview

### 3.1 Subsystem Map

Neuro-Mesh is organized into eight subsystems. Each is implemented as a small
number of files in a dedicated directory, with a single owning header
(`*.hpp`) that declares the public API and a translation unit (`*.cpp`) that
implements it.

| Subsystem             | Directory     | Owning class(es)                                     | Lines of code |
|-----------------------|---------------|------------------------------------------------------|---------------|
| Kernel observability  | `kernel/`     | eBPF programs in `sensor.bpf.c`                     | 195           |
| Cell intelligence     | `cell/`       | `NodeAgent`, `InferenceEngine`                       | 545           |
| Consensus             | `consensus/`  | `MeshNode`, `PBFTConsensus`, `PeerManager`           | 3,429         |
| Crypto / Identity     | `crypto/`     | `CryptoCore`, `KeyManager`, `CertificateAuthority`   | 1,951         |
| Transport             | `net/`        | `TransportLayer`, `TLSContext`                       | 847           |
| Enforcement           | `enforcer/`   | `PolicyEnforcer`, `MitigationEngine`                 | 1,241         |
| Telemetry             | `telemetry/`  | `TelemetryBridge`, `Observability`, `AuditLogger`    | 1,840         |
| Common utilities      | `common/`     | `UniqueFD`, `Result<T,E>`, `Base64`, `StateJournal`  | 381           |

Plus `main.cpp` (711 lines) which composes all subsystems and runs the
heartbeat loop, and `attacks/AttackSimulator.{hpp,cpp}` (814 lines) which
provides adversarial load generation for testing.

**Total: ~12,136 lines of C++ + 195 lines of eBPF C + 587 lines of Markdown documentation.**

### 3.2 Data Flow at a Glance

```
+--------+    +-----------------+    +-------------------+
| KERNEL |    |   USER SPACE    |    |    NETWORK        |
|        |    |                 |    |                   |
| kprobe |    | NodeAgent       |    | MeshNode (UDP)    |
| ringbuf|--->| poll_events()   |    | 9998, 9999        |
|        |    |        |        |    |                   |
|        |    |        v        |    |                   |
| XDP    |    | InferenceEngine |    |                   |
| dropper|<-->| ONNX scoring    |    |                   |
|        |    |        |        |    |                   |
|        |    |        v        |    |                   |
|        |    | MeshNode        |    |                   |
|        |    | broadcast pbft  |--->|  peers            |
|        |    |        |        |    |                   |
|        |    |        v        |    |                   |
|        |    | PolicyEnforcer  |    |                   |
|        |    | nft/ipt/XDP     |    |                   |
|        |    |        |        |    |                   |
|        |    |        v        |    |                   |
|        |    | TelemetryBridge |    |                   |
|        |    | (sandboxed)     |    |                   |
|        |    |        |        |    |                   |
|        |    |        v        |    |                   |
|        |    | Dashboard       |    |                   |
|        |    | (browser)       |    |                   |
|        |    |                 |    |                   |
|        |    | Telemetry gossip|--->|  peers            |
+--------+    +-----------------+    +-------------------+
```

### 3.3 Threading Model

The agent runs **four concurrent threads** plus zero or more short-lived threads
spawned by libbpf for ring buffer callbacks.

| Thread                 | Owner                              | Purpose                                                                       | Lifetime                |
|------------------------|------------------------------------|-------------------------------------------------------------------------------|-------------------------|
| Main                   | `main()`                           | Heartbeat loop: poll eBPF, run inference, drive consensus, flush telemetry     | Process lifetime        |
| TelemetryBridge main   | `TelemetryBridge::spawn()`         | uWebSockets event loop in sandboxed child                                     | Child process lifetime  |
| IPC listener           | `main.cpp` (inline `select()`)     | Accept commands on `/tmp/neuro_mesh_{id}.sock`                                | Process lifetime        |
| Background telemetry   | `TelemetryExporter`                | POSIX-locked JSON writes to `web/mesh_status.json`                            | Process lifetime        |

**Concurrency primitives in use:**
- `std::atomic<bool>` for shutdown flag (main.cpp:11).
- `std::shared_mutex` for `PolicyEnforcer::m_mtx` (read-heavy rule application).
- `std::mutex` + `std::condition_variable` for `TelemetryQueue` (cell/NodeAgent.hpp).
- `std::lock_guard` everywhere in consensus + enforcer.
- No `std::recursive_mutex` is used; the codebase explicitly avoids it.

### 3.4 Process Model

A single binary `neuro_agent` is the only persistent process. Two helpers are
spawned at runtime:

1. **TelemetryBridge child** - the `fork()` happens, the child transitions to
   `sandboxed_child_main()` and never returns to parent code. The child opens a
   pipe, applies the sandbox, and runs the uWebSockets event loop until the
   parent closes the pipe (passive EOF detection).
2. **nftables/iptables children** - `PolicyEnforcer::fork_exec_wait()` does a
   `fork()` + `execv()` for each backend invocation. The parent blocks on
   `waitpid()` to collect the exit code. There is no `system()` call anywhere
   in the enforcement path.

**Why `fork()` instead of `posix_spawn()`?** Direct control over FD inheritance
via `O_CLOEXEC` is critical for the sandboxed child - the parent passes only
the pipe FD, all others must be closed.

### 3.5 Dependency Model

External libraries (system packages):

| Library           | Used for                              | File references                          |
|-------------------|---------------------------------------|------------------------------------------|
| `libbpf`          | eBPF skeleton loading, ring buffer    | `cell/NodeAgent.cpp`                     |
| `libelf`, `libz`  | BPF object parsing                    | linked via `-lelf -lz`                   |
| `OpenSSL 3.x`     | Ed25519, TLS 1.3, X.509               | `crypto/CryptoCore.cpp`, `net/...`       |
| `libseccomp`      | BPF seccomp filter installation       | `telemetry/TelemetryBridge.cpp`          |
| `libonnxruntime`  | ONNX model inference                  | `cell/InferenceEngine.cpp`               |
| `uWebSockets`     | HTTP + WebSocket server               | `telemetry/TelemetryBridge.cpp`          |
| `nlohmann/json`   | JSON parsing for evidence             | `consensus/MeshNode.cpp`                 |
| `bpftool`         | Skeleton generation (build-time)      | `Makefile:117-126`                       |

Internal: zero circular dependencies. The header graph is a DAG rooted at
`common/`, with `crypto/`, `cell/`, `net/`, `enforcer/`, `consensus/`,
`telemetry/` as second-level consumers, and `main.cpp` as the top-level
composition root.

---

## 4. System Components

This section examines every major component. For each we answer: what is it,
why does it exist, how does it work, what depends on it, and what can go wrong.


### 4.1 NodeAgent (`cell/NodeAgent.hpp`, `cell/NodeAgent.cpp`)

**Purpose.** Bridge between kernel eBPF events and userspace inference.
Owns the eBPF skeleton, ring buffer, kprobe attachments, and XDP dropper.

**Why it exists.** The kernel cannot run PBFT or ONNX inference. We need a
zero-copy, lock-protected delivery channel from kernel to userspace with
batching and backpressure handling.

**Internal design.**
- `KernelEventData` struct is a verbatim mirror of `struct KernelEvent` in
  `kernel/sensor.bpf.c`. Layout is enforced by `static_assert(sizeof(KernelEventData) == 280)`
  in `NodeAgent.cpp:10`.
- `TelemetryQueue<T>` is an MPSC bounded queue (5000 items) using
  `std::mutex` + `std::condition_variable`. Producer is the eBPF ring buffer
  callback (single thread); consumer is the inference thread (also single).
  Overflow increments `m_drops` rather than blocking.
- `load_and_attach_ebpf()` (NodeAgent.cpp:32-160) is the heart of the component.
  It bumps RLIMIT_MEMLOCK, calls `sensor_bpf__open_and_load()`, attaches four
  kprobes (`sys_execve`, `sys_sendto`, `sys_sendmsg`, `sys_connect`), attaches
  the XDP dropper to the first available interface, then wires up the ring
  buffer callback to push into the queue.
- `poll_events()` (NodeAgent.cpp:178-185) drains the ring buffer in a tight
  `while(ring_buffer__poll(rb, 0) > 0)` loop before returning. This is critical:
  if the userland consumer is slow, kernel-side event loss can occur. The tight
  drain loop ensures we process everything before the next heartbeat tick.

**Key classes / functions.**
- `NodeAgent(node_id)` constructor.
- `static Result<NodeAgent, string> create(node_id)` factory that calls
  `load_and_attach_ebpf()` and returns an error string on failure.
- `void start_telemetry_thread()` spawns the consumer thread.
- `vector<KernelEventData> poll_events()` non-blocking drain.
- `TelemetryQueue<KernelEventData>& queue()` accessor.

**Dependencies.** `kernel/sensor.skel.h` (auto-generated), `libbpf`, kernel
headers, `common/UniqueFD.hpp` for FD management.

**Failure modes.**
- BPF load fails. Detected via `sensor_bpf__open_and_load()` returning null.
  Error message reports the exact kernel state (checks
  `/proc/sys/kernel/unprivileged_bpf_disabled`) and the remediation (run as
  root, grant CAP_BPF+CAP_PERFMON, use `--privileged` in Docker). Falls back
  to `/proc/net/dev` entropy-only mode.
- Ring buffer overrun. Bounded queue drops events with counter; visible in
  the telemetry export as `telemetry_queue_drops`.
- Interface disappears. XDP attach succeeds but the link goes down. There
  is no automatic re-attach; this is a known limitation (see Known Limitations).

### 4.2 InferenceEngine (`cell/InferenceEngine.hpp`, `cell/InferenceEngine.cpp`)

**Purpose.** Score syscall events for anomalous behavior using an ONNX
isolation forest model, plus a Shannon entropy pre-filter.

**Why it exists.** eBPF gives us raw events but no judgment. We need a
model to distinguish benign traffic from attacks without a human in the loop.

**Internal design.**
- Constructor loads the ONNX model from `isolation_forest.onnx`, creates an
  `Ort::Session`, and pre-allocates the input tensor (5 floats) and output tensor.
- `extract_features(comm, payload)` pulls 5 numerical features from the event:
  payload length, payload Shannon entropy, comm length, comm entropy, a
  derived rarity score.
- `analyze(comm, payload)` returns true when the model score exceeds the
  threshold (default -0.05 for isolation forest; more negative = more
  conservative).
- `decay(factor)` reduces the last score toward 0 each heartbeat, preventing
  sticky CRITICAL state after anomalous traffic stops.
- `verdict()` returns `CRITICAL` or `NONE` based on the last score relative
  to threshold.

**Key classes / functions.**
- `InferenceEngine(model_path, threshold=-0.05f)` constructor.
- `bool analyze(const string& comm, const string& payload)`.
- `float last_score() const noexcept` atomic getter.
- `string verdict() const noexcept`.
- `void decay(float factor = 0.5f) noexcept`.
- `static double compute_entropy(const char* data, size_t len)`.

**Dependencies.** `onnxruntime_cxx_api.h` (header-only C++ API), pre-trained
`isolation_forest.onnx` model file.

**Failure modes.**
- Model file missing. Constructor logs error, sets `m_loaded = false`,
  `is_operational()` returns false. Heartbeat still runs, but no events
  trigger consensus.
- ONNX runtime error. `analyze()` returns false (treating as benign) and
  throttles stderr logs to prevent flooding (`m_run_failure_logged` flag).
- Adversarial payload. A crafted payload can fool the model. This is a
  known limitation; PBFT provides defense in depth - the adversary must
  fool 2f+1 of N nodes, not just one.

### 4.3 PBFTConsensus (`consensus/PBFT.hpp`)

**Purpose.** Header-only PBFT state machine. Encapsulates the consensus
protocol with equivocation detection and timeout-based round eviction.

**Why it exists.** PBFT is the core of Byzantine fault tolerance. Pulling
it out as a header-only template allows unit testing and avoids the
fragility of macro-based consensus code.

**Internal design.**
- `enum class PBFTStage { IDLE, PRE_PREPARE, PREPARE, COMMIT, EXECUTED, BAN_PEER }`.
- `struct P2PMessage { stage, sender_id, target_id, evidence_json, signature, prev_message_hash, view, sequence }`.
- `class PBFTConsensus` owns the round state (`std::map<sequence, Round>`),
  peer keys (`m_peer_public_keys`), trust scores (`NodeTrustScore`), and
  equivocation evidence (`EquivocationEvidence`).
- `verify_message()` checks the Ed25519 signature against the
  binding `(sender_id || target_id || stage || sequence || view || evidence_hash)`.
  Cross-stage replay is impossible because `stage` is part of the binding.
- Vote counts are tracked per stage per round. Advancement requires `2f+1`
  distinct senders (configurable via `NEURO_PBF` env var or default `f=1`).
- Timeout eviction: rounds with `last_activity` > 120s ago are removed.
- Equivocation: if a sender submits two different signatures for the same
  `(view, sequence)`, both are stored as `EquivocationEvidence` and the sender's
  trust score is decreased.

**Key constants.**
- `VIEW_CHANGE_TIMEOUT_SEC = 30`.
- `ROUND_TTL_SEC = 120`.
- `MAX_SEQUENCE_GAP = 100`.
- `MAX_MSG_HISTORY_PER_SENDER = 10000`.

**Key functions.**
- `void register_peer_key(id, pem_key)`.
- `bool verify_message(const P2PMessage&)` - signature check.
- `void on_message(P2PMessage)` - state machine driver.
- `void evict_stale_rounds()` - 120s timeout.
- `std::optional<EquivocationEvidence> check_equivocation(...)`.

**Dependencies.** `crypto/CryptoCore.hpp` for Ed25519, `<unordered_map>`,
`<chrono>`.

**Failure modes.**
- Stale round accumulation. Without 120s eviction, OOM is possible. The
  constant is conservative; even a misbehaving node cannot exceed 10K
  messages per sender.
- Trust score manipulation. Trust scores are local-only; they do not
  affect consensus outcomes, only logging. A node can lie about another
  node's trust without compromising agreement.
- View change deadlock. If `f+1` nodes simultaneously trigger view change,
  the protocol can deadlock. Mitigated by `VIEW_CHANGE_TIMEOUT_SEC` and
  the next-view leader being deterministically chosen by `view % N`.

### 4.4 MeshNode (`consensus/MeshNode.hpp`, `consensus/MeshNode.cpp`)

**Purpose.** UDP mesh transport, peer discovery (V2 and V3), PBFT message
broadcast, telemetry gossip.

**Why it exists.** PBFTConsensus is pure logic. MeshNode wires it to the
network: receives raw UDP, parses V2/V3 wire format, dispatches to consensus,
broadcasts outgoing messages, and gossips telemetry.

**Internal design.**
- UDP listener on `127.0.0.1:9999` (configurable).
- Discovery beacon: every 5 seconds broadcasts `DISCOVERY|id|tcp|tls|ts|b64pub|tls_fpr|b64cert|sig`
  to `255.255.255.255:9998` (V3 format with cert PEM).
- Backward compatibility: V2 beacons (8 tokens) still parse and register the
  peer but do not call `trust_peer_cert()`.
- Signature verification: each beacon's signature is verified against
  `b64pub` before the peer is recorded.
- PBFT broadcast: outgoing messages go to all known peers via unicast UDP
  (not broadcast, to prevent amplification in real deployments).
- Telemetry gossip: every heartbeat, the node unicasts its telemetry JSON
  to all known peers. Peers push received telemetry to their local
  TelemetryBridge, so any node can serve the dashboard with the full mesh.
- Dual-path TOFU: a peer is trusted only after both UDP discovery and a
  TCP PEX handshake confirm identical identity.

**Key classes / functions.**
- `MeshNode(node_id, jailer, mitigation, bridge)` constructor.
- `void start()` begins the UDP listener thread.
- `void stop()` joins the thread, closes the socket.
- `void heartbeat()` periodic task: gossip telemetry, evict stale rounds.
- `void initiate_consensus(target_id, evidence_json)` proposes a new PBFT round.
- `void broadcast_pbft_stage(round, stage, signature)` sends a vote.
- `void handle_discovery(payload)` parses V2/V3, registers peer.
- `void handle_pbft_message(payload)` dispatches to PBFTConsensus.

**Dependencies.** `consensus/PBFT.hpp`, `crypto/CryptoCore.hpp`,
`net/TransportLayer.hpp`, `nlohmann/json`, `common/Base64.hpp`.

**Failure modes.**
- UDP packet loss. Mitigated by retransmission on heartbeat.
- Stale peer list. Mitigated by 30s timeout in PeerManager.
- Beacon signature mismatch. Treated as untrusted, not added to peer set.
- Dual-path mismatch. Peer is downgraded to UNTRUSTED; mTLS handshakes fail.

### 4.5 PeerManager (`consensus/PeerManager.hpp`, `consensus/PeerManager.cpp`)

**Purpose.** Track peer state, dual-path TOFU confirmation, IP address resolution.

**Why it exists.** PBFT requires knowing the set of peers and their keys.
PeerManager is the source of truth; MeshNode and TransportLayer read from it.

**Internal design.**
- `struct Peer` holds: id, public_key, tls_fpr, last_seen, state (KNOWN, TRUSTED, BANNED), cert_pem (V3).
- Dual-path confirmation: a peer starts as KNOWN after UDP discovery;
  it transitions to TRUSTED only after TCP PEX handshake confirms
  matching id+pubkey+tls_fpr.
- `resolve_ip(peer_id)` returns the IP from the most recent discovery beacon.
- Eviction: peers not seen for 30s are marked stale; 5min idle removes them.

**Key functions.**
- `void upsert_peer(peer)`.
- `std::optional<Peer> get(id)`.
- `std::vector<Peer> all_trusted()`.
- `void mark_trusted(id)`, `void mark_banned(id)`.
- `std::string resolve_ip(id)`.

**Dependencies.** `consensus/MeshNode.hpp`, `crypto/CryptoCore.hpp`.

**Failure modes.**
- IP change without re-discovery. Mitigated by 5s beacon interval.
- Peer impersonation. Caught by signature check; the impersonator cannot
  produce a valid Ed25519 signature without the private key.
- Stuck in KNOWN state forever. The peer never made a TCP PEX connection.
  This is a known issue for firewalled deployments; the system degrades
  gracefully (the peer cannot vote in consensus but is still in the list).

### 4.6 CryptoCore (`crypto/CryptoCore.hpp`, `crypto/CryptoCore.cpp`)

**Purpose.** Thin wrapper around OpenSSL EVP for Ed25519 keygen, sign, verify.

**Why it exists.** Centralize all crypto primitives in one place to avoid
spreading `EVP_PKEY_*` boilerplate across the codebase.

**Internal design.**
- `IdentityCore` (in `CryptoCore.cpp`) uses `EVP_PKEY_keygen` with
  `EVP_PKEY_ED25519` algorithm.
- Sign: `EVP_DigestSign` with the Ed25519 key.
- Verify: `EVP_DigestVerify` returning 1 on success, 0 on failure, -1 on error.
- Binary-safe: `data.data()` and `data.size()` are used everywhere; `c_str()`
  is explicitly avoided (this prevents null-byte truncation in signatures).
- PEM serialization: `PEM_write_bio_PUBKEY` / `PEM_read_bio_PUBKEY`.

**Key functions.**
- `static std::vector<uint8_t> generate_keypair_raw()` returns 32-byte seed.
- `static std::string pubkey_to_pem(const std::vector<uint8_t>& pub)`.
- `static std::vector<uint8_t> pem_to_pubkey(const std::string& pem)`.
- `static std::vector<uint8_t> sign(privkey_seed, data, len)`.
- `static bool verify(pubkey_pem, data, len, signature)`.

**Dependencies.** `<openssl/evp.h>`, `<openssl/pem.h>`.

**Failure modes.**
- OpenSSL not initialized. `EVP_DigestSign` would segfault. Mitigated by
  static initialization in `main()`.
- Wrong key type. Caught by `EVP_PKEY_keygen` returning null.
- Truncated signature. `EVP_DigestVerify` returns -1; the code checks for
  this and treats it as invalid.

### 4.7 KeyManager (`crypto/KeyManager.hpp`, `crypto/KeyManager.cpp`)

**Purpose.** Persistent Ed25519 keypair storage in `~/.neuro_mesh/keys/{id}.key`.

**Why it exists.** A node's identity must survive restarts. Without
persistence, every restart produces a new keypair, breaking TOFU with
existing peers.

**Internal design.**
- Path: `~/.neuro_mesh/keys/{node_id}.key` with `0600` permissions.
- Format: 32-byte raw Ed25519 seed, written atomically via `rename()`.
- Load on startup: if file exists, read and reconstruct keypair; if not,
  generate new and persist.
- Thread-safe: uses a `std::mutex` around all disk I/O.

**Key functions.**
- `static std::vector<uint8_t> load_or_generate(node_id)`.
- `static void persist(node_id, seed)`.
- `static std::filesystem::path key_path(node_id)`.

**Dependencies.** `<filesystem>`, `<openssl/rand.h>`.

**Failure modes.**
- Permission denied. Crash on startup with clear error.
- Disk full. Crash on startup; no rollback (the key is the identity).
- Keyfile corrupted (wrong size). Crash on startup; no recovery without
  manual intervention (this is by design - we cannot guess a valid key).

### 4.8 TransportLayer (`net/TransportLayer.hpp`, `net/TransportLayer.cpp`)

**Purpose.** mTLS 1.3 handshake with X.509v3 cert pinning, TOFU enrollment.

**Why it exists.** PBFT over UDP is sufficient for voting, but TCP is
needed for bulk telemetry, large evidence payloads, and the PEX (peer
exchange) channel. mTLS ensures both authenticity and confidentiality.

**Internal design.**
- `TLSContext` wraps `SSL_CTX` with TLS 1.3, modern cipher suites, and
  custom verification (the cert must be in the local trust store).
- `trust_peer_cert(peer_id, cert_pem)` calls
  `SSL_CTX_get_cert_store() + X509_STORE_add_cert()` to add a peer's
  X.509 cert to the trust store after V3 discovery confirms identity.
- `TransportLayer` runs a TCP listener on port 10500 that accepts
  incoming mTLS connections; on each connection it verifies the peer
  cert against the trust store.
- TCP PEX port (10000) is a separate plain-text channel for peer
  exchange (used during mesh formation to exchange known peers).
- Self-signed X.509v3 certs are generated on first startup using
  OpenSSL; the cert and key are stored at
  `~/.neuro_mesh/certs/{node_id}.{crt,key}`.

**Key functions.**
- `TransportLayer(node_id, peer_manager)` constructor.
- `Result<void, string> listen(port)`.
- `Result<unique_ptr<Connection>, string> connect(peer_id)`.
- `Result<void, string> trust_peer_cert(peer_id, cert_pem)`.
- `void shutdown()`.

**Dependencies.** OpenSSL 3.x, `crypto/CryptoCore.hpp`,
`consensus/PeerManager.hpp`.

**Failure modes.**
- Cert verification failure. The connection is rejected; the peer
  remains UNTRUSTED.
- Trust store corruption. Mitigated by not persisting the trust
  store; it is rebuilt on every restart from the discovery beacons.
- TLS handshake timeout. The connection is closed after 5s; the
  caller retries with exponential backoff.

### 4.9 PolicyEnforcer (`enforcer/PolicyEnforcer.hpp`, `enforcer/PolicyEnforcer.cpp`)

**Purpose.** Apply network isolation rules via the available backend
(nftables, iptables, eBPF blocklist, process suspension).

**Why it exists.** Consensus is meaningless without enforcement. The
enforcer is the muscle; consensus is the brain.

**Internal design.**
- Backend detection: `probe_backends()` tests which backends are
  available by trying each one with a no-op rule.
- `enum class EnforcementBackend { NONE=0, EBPF=1, NFT=2, IPT=4 }`.
- Backend priority: NFT > IPT > EBPF (NFT is preferred for new
  deployments; IPT is fallback for older systems; EBPF is the
  fastest but only for XDP-enabled interfaces).
- `isolate_node(target_id)` resolves the target's IP, checks the
  safe-list, then applies DROP rules via all available backends.
- `block_ip_address(ip)` is the raw-IP variant, used when
  evidence_json carries a `src_ip` field but no node ID.
- `add_safe_node(node_id)` adds an entry to the safe list. Safe
  nodes are never isolated, even by PBFT consensus.
- `is_loopback(ip)` rejects 127.0.0.0/8 and 0.0.0.0 to prevent
  accidental self-isolation.

**Key functions.**
- `PolicyEnforcer(node_id, tracing_on)` constructor.
- `bool isolate_node(node_id)`.
- `bool block_ip_address(ip)`.
- `bool suspend_process(pid)`.
- `void reset_enforcement()` clears all rules (used for testing).
- `void add_safe_node(node_id)`.
- `bool is_safe(node_id) const`.
- `static bool is_valid_ip(ip)`, `is_valid_ipv4`, `is_valid_ipv6`,
  `is_loopback`, `is_loopback_ipv6`.

**Dependencies.** `consensus/PeerManager.hpp` (for IP resolution),
`crypto/CryptoCore.hpp` (none directly), `common/UniqueFD.hpp`.

**Failure modes.**
- No backend available. `isolate_node` returns false, logs error.
- fork() failure. `fork_exec_wait` returns (-1, errno); caller logs.
- execv() failure. Caught by `waitpid` returning non-zero exit.
- Safe list contradiction. Cannot occur; safe list is
  add-only, no remove API.

### 4.10 MitigationEngine (`enforcer/MitigationEngine.hpp`, `enforcer/MitigationEngine.cpp`)

**Purpose.** Orchestrate the full mitigation response when consensus
reaches EXECUTED stage.

**Why it exists.** A single call from PBFTConsensus is too coarse; we
need to coordinate multiple enforcers, log the action, and emit
telemetry.

**Internal design.**
- `MitigationEngine(enforcer, jailer, telemetry)` constructor.
- `void on_consensus_executed(round)` is called by MeshNode when
  a round reaches EXECUTED. It extracts the target, calls
  `enforcer->isolate_node()`, and emits a structured telemetry event.
- `void reset()` clears all enforcement (used for testing).
- Hooks for future expansion: process suspension, file integrity
  checks, etc.

**Dependencies.** `enforcer/PolicyEnforcer.hpp`,
`telemetry/TelemetryBridge.hpp`.

**Failure modes.**
- Enforcer unavailable. Logs error, continues (consensus has
  decided; we cannot undo the decision).
- Target unknown. Logs warning, continues (the gossip may have
  arrived after the target was already banned).

### 4.11 TelemetryBridge (`telemetry/TelemetryBridge.hpp`, `telemetry/TelemetryBridge.cpp`)

**Purpose.** Sandboxed WebSocket server that broadcasts telemetry JSON
to dashboard subscribers.

**Why it exists.** The dashboard is a browser; it speaks WebSocket. The
bridge translates the internal telemetry stream into WebSocket frames
while running in a privilege-separated child process for defense in
depth.

**Internal design.**
- The bridge `fork()`s at startup. The parent retains the write end
  of a pipe; the child reads from it.
- Child sandbox sequence (in order):
  1. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` - blocks setuid binaries.
  2. `chroot("/var/empty")` - removes filesystem access.
  3. `setresuid(uid, uid, uid)` where uid=65534 (nobody) - drops privilege.
  4. `setresgid(gid, gid, gid)` where gid=65534 (nogroup).
  5. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` - installs
     seccomp-BPF with 65-syscall whitelist, default-kill.
- Child runs uWebSockets event loop, reading JSON lines from the
  pipe and broadcasting to all WebSocket subscribers.
- Parent liveness check: **passive EOF detection**. The child reads
  from the pipe; when the parent closes it (process exit), `read()`
  returns 0 and the child exits. This replaces the broken
  `kill(getppid(), 0)` pattern which returned -1/EPERM under
  unprivileged UID.
- Seccomp whitelist (65 syscalls): read, write, open, close, stat,
  fstat, lstat, poll, lseek, mmap, mprotect, munmap, brk, rt_sigaction,
  rt_sigprocmask, rt_sigreturn, ioctl, pread64, pwrite64, readv,
  writev, access, pipe, select, mremap, dup, dup2, pause, nanosleep,
  getitimer, alarm, setitimer, getpid, sendfile, socket, connect,
  accept, sendto, recvfrom, sendmsg, recvmsg, shutdown, bind,
  getsockname, getpeername, setsockopt, getsockopt, clone, fork,
  vfork, execve, exit, wait4, kill, uname, fcntl, flock, fsync,
  fdatasync, truncate, ftruncate, getrlimit, getrusage, gettimeofday,
  getuid, getgid, getppid, getsid, setsid, getpgid, setpgid, geteuid,
  getegid, setreuid, setregid, setresuid, setresgid, prctl,
  arch_prctl, time, clock_nanosleep, restart_syscall, clone3, futex,
  sched_yield.

**Key functions.**
- `TelemetryBridge(Config)` constructor.
- `Result<void, string> spawn()` fork + sandbox.
- `Result<void, string> push_telemetry(string_view json)` writes to pipe.
- `Result<void, string> shutdown()` closes pipe, waits for child.
- `pid_t child_pid() const`.

**Dependencies.** `common/UniqueFD.hpp`, `common/Result.hpp`,
uWebSockets (`third_party/uWebSockets/`), libseccomp.

**Failure modes.**
- chroot fails (not root). Logs FATAL; bridge continues without
  sandbox, dashboard unavailable.
- setresuid fails. Logs FATAL; child exits.
- Seccomp install fails. Logs FATAL; child exits.
- Pipe write fails. `push_telemetry` returns Err; parent retries on
  next heartbeat.
- Parent dies abruptly. Child detects pipe EOF, exits cleanly.

### 4.12 Observability (`telemetry/Observability.hpp`, `telemetry/Observability.cpp`)

**Purpose.** Aggregated metrics collector (counters, gauges, histograms)
with thread-safe updates and periodic export.

**Why it exists.** Telemetry push is one-way; the operator needs a
read-side for graphs and alerts. Observability owns the in-memory
metrics store and produces the periodic JSON snapshot.

**Internal design.**
- `MetricsRegistry` is a singleton with `std::shared_mutex` for
  read-heavy access.
- Counter: `std::atomic<uint64_t>` with `increment()` and `get()`.
- Gauge: `std::atomic<double>` with `set()` and `get()`.
- Histogram: bounded circular buffer (100 samples) with `record()`.
- `snapshot()` returns a `nlohmann::json` object with all metrics.

**Key functions.**
- `void increment_counter(name)`.
- `void set_gauge(name, value)`.
- `void record_histogram(name, value)`.
- `json snapshot()`.
- `void reset()` (for testing).

**Dependencies.** nlohmann/json, `<shared_mutex>`.

**Failure modes.**
- Memory growth. Mitigated by histogram size cap.
- Concurrent updates. Lock-free atomics for all scalar metrics.

### 4.13 AuditLogger (`telemetry/AuditLogger.hpp`, `telemetry/AuditLogger.cpp`)

**Purpose.** Structured logging to a UDP socket, viewable in real time
by external tools.

**Why it exists.** Console output (stdout) is captured by the process
supervisor; UDP output can be aggregated by a remote sink without
process-level coupling.

**Internal design.**
- Static UDP socket (`UniqueFD`) bound to a configured port; if
  unbound, logs are silently dropped.
- `AuditLogger::initialize()` called once at process start.
- `AuditLogger::log(level, event, json)` constructs a structured
  line and sends it.
- `AuditLogger::shutdown()` closes the socket.

**Key functions.**
- `static void initialize()`.
- `static void log(level, event, json)`.
- `static void shutdown()`.

**Dependencies.** `<sys/socket.h>`, `common/UniqueFD.hpp`.

**Failure modes.**
- Socket creation fails. Logs go to stdout only.
- Send fails (buffer full). Dropped silently with counter.

### 4.14 TelemetryExporter (`telemetry/TelemetryExporter.hpp`)

**Purpose.** Periodic JSON export of full mesh state to
`web/mesh_status.json` for the dashboard's polling fallback.

**Why it exists.** The WebSocket path is preferred, but if the bridge
crashes, the dashboard can fall back to HTTP polling.

**Internal design.**
- Header-only class (single TU).
- POSIX file locking (`flock`) on the output path to prevent
  corruption if multiple nodes share a volume.
- `flush()` writes the current `Observability::snapshot()` as JSON.

**Key functions.**
- `TelemetryExporter(path)` constructor.
- `bool flush()`.

**Dependencies.** nlohmann/json, `<sys/file.h>`.

**Failure modes.**
- Disk full. Returns false; logged.
- Concurrent write. Blocked by flock.

### 4.15 Common Utilities

#### UniqueFD (`common/UniqueFD.hpp`)

**Purpose.** RAII wrapper for POSIX file descriptors.

**Why it exists.** The codebase uses raw FDs in many places (sockets,
ring buffer, BPF maps, pipes). A `UniqueFD` ensures FDs are closed on
all exit paths, including exceptions.

**Internal design.**
- Move-only type; non-copyable.
- `~UniqueFD()` calls `close()` if `m_fd >= 0`.
- `int get() const`, `int release()` (returns fd, sets to -1).

#### Result<T, E> (`common/Result.hpp`)

**Purpose.** Rust-style `Result` type for error propagation without
exceptions.

**Why it exists.** The codebase explicitly avoids exceptions in the
hot path. `Result<T, E>` carries either a value or an error message
and provides `unwrap_or`, `map`, `map_or` for functional composition.

**Internal design.**
- `std::variant<T, E>` storage.
- `bool ok() const`, `T& value()`, `E& error()` accessors.
- `map(F)`, `map_or(default, F)`, `unwrap_or(default)`.

#### Base64 (`common/Base64.hpp`)

**Purpose.** Standard Base64 encode/decode for PEM-in-UDP and PEM-in-beacon.

**Why it exists.** The V3 discovery beacon carries the X.509 cert PEM
in a UDP packet. Base64 is the canonical transport encoding.

**Internal design.**
- `std::string base64_encode(bytes)`.
- `std::vector<uint8_t> base64_decode(string)`.

#### StateJournal (`common/StateJournal.hpp`)

**Purpose.** Append-only log of PBFT decisions for crash recovery.

**Why it exists.** On restart, a node must reconstruct its view of
recent decisions to participate in ongoing rounds. The journal
provides durable history.

**Internal design.**
- Append-only file at `~/.neuro_mesh/journal/{node_id}.log`.
- Each entry is a JSON-serialized `P2PMessage` + local timestamp.
- `void append(message)`, `vector<P2PMessage> replay_since(seq)`.

**Failure modes.**
- File corruption. Mitigated by SHA-256 checksum per entry; corrupt
  entries are skipped with a warning.

### 4.16 AttackSimulator (`attacks/AttackSimulator.hpp`, `attacks/AttackSimulator.cpp`)

**Purpose.** Adversarial load generator for testing the system under
attack.

**Why it exists.** Without a way to inject malicious load, we cannot
verify the detection or enforcement path. The simulator produces
realistic attacks: UDP floods, port scans, anomalous syscalls.

**Internal design.**
- `class AttackSimulator(target_ip, threads, duration)`.
- `void start()` spawns N worker threads.
- Each worker runs a `do_attack()` loop with randomized load patterns.
- `void stop()` signals all workers and joins.
- `AttackReport report()` returns statistics (packets sent, errors).

**Key attack patterns.**
- UDP flood to port 9999 (PBFT path) at 100K pps.
- Random port scan to port 9998 (discovery path).
- `execve` storm via `/bin/true` in tight loop.
- Mixed packet sizes to evade entropy-based detection.

**Dependencies.** `<thread>`, `<atomic>`, `<random>`.

**Failure modes.**
- Thread join hang. Mitigated by atomic stop flag with 5s timeout.
- Permission denied. Logs and exits; no root required for userspace attacks.

### 4.17 Kernel eBPF Programs (`kernel/sensor.bpf.c`)

**Purpose.** Kernel-level syscall tracing and XDP packet dropping.

**Why it exists.** Userspace detection has fundamental timing and
visibility disadvantages. eBPF runs in kernel context, sees every
syscall and packet, and never blocks.

**Internal design.**

- `struct KernelEvent` is the kernel-space mirror of `KernelEventData`.
  Must be byte-identical (enforced by `static_assert` in NodeAgent).
  Size: 280 bytes. Fields: `pid`, `event_type`, `comm[16]`, `payload[256]`.
  - `pid`: `bpf_get_current_pid_tgid() >> 32` (upper 32 bits of tgid).
  - `event_type`: 1=execve, 2=sendto/sendmsg, 3=connect.
  - `comm`: process name from `bpf_get_current_comm()`.
  - `payload`: bounded copy of the syscall argument.

- Maps:
  - `telemetry_ringbuf`: ring buffer, 256KB (256 * 1024 bytes).
    `BPF_MAP_TYPE_RINGBUF` for zero-copy userspace delivery.
  - `xdp_blacklist`: hash, 1024 entries, key=IPv4 (u32), value=u8.
    `BPF_MAP_TYPE_HASH` for per-IP DROP rules at XDP layer.

- Programs (5):
  1. `trace_execve` - kprobe on `sys_execve` (x86: `__x64_sys_execve`).
     Captures process name + first 256 bytes of executable path.
  2. `trace_sendto` - kprobe on `sys_sendto`. Captures dest IP/port
     and up to 256 bytes of payload.
  3. `trace_sendmsg` - kprobe on `sys_sendmsg`. Walks `msghdr` to
     find the actual scatter-gather payload.
  4. `trace_connect` - kprobe on `sys_connect`. Captures dest IP/port.
  5. `xdp_neuro_mesh_dropper` - XDP program. Checks incoming packet's
     source IP against `xdp_blacklist`; if matched, returns
     `XDP_DROP`. Also supports a global "lockdown" key (0xFFFFFFFF)
     that drops all traffic when set to 1.

- `PT_REGS_PARM*` macros from `<bpf/bpf_tracing.h>` provide portable
  syscall argument extraction across architectures.

- `#ifdef __TARGET_ARCH_x86` defines a `pt_regs` struct matching the
  kernel's expected layout (19 GP registers + segment regs).

- `bpf_probe_read_user_str()` and `bpf_probe_read_user()` safely copy
  user memory into the event payload without crashing on invalid
  pointers.

**Dependencies.** `<linux/bpf.h>`, `<bpf/bpf_helpers.h>`,
`<bpf/bpf_core_read.h>`, `<bpf/bpf_tracing.h>`.

**Failure modes.**
- Verifier rejection. The BPF program is rejected at load time with
  a verifier log. The skeleton load fails, falling back to
  `/proc/net/dev` entropy-only mode.
- Unprivileged user. The `bpf()` syscall returns EPERM. Error
  message explains the exact kernel state and remediation.
- Ring buffer full. New `bpf_ringbuf_output()` calls return
  `EBUSY`; events are dropped on the floor.
- Interface down. XDP program is detached; no DROP enforcement.
- Map pin failure. `xdp_blacklist` may be re-pinned on next start.

---

## 5. Runtime Lifecycle

### 5.1 Startup Sequence (top-down, exact order)

The startup sequence is in `main.cpp` (711 lines). Here is the exact order:

**Stage 0: Process-level setup (main.cpp:548-553)**
1. `signal(SIGPIPE, SIG_IGN)` - survive broken pipe to dead child.
2. `signal(SIGINT, signal_handler)` - graceful shutdown.
3. `signal(SIGTERM, signal_handler)` - graceful shutdown.
4. `AuditLogger::initialize()` - open UDP socket for structured logs.

**Stage 1: Component construction (main.cpp:555-605)**

Order matters; each component's constructor may depend on previous ones.

1. **Enforcer**: `PolicyEnforcer enforcer(node_id, tracing_on=true)`.
   - Constructor calls `probe_backends()` which attempts nftables,
     iptables, and eBPF blocklist setup. Idempotent.
   - `enforcer.add_safe_node("127.0.0.1")` - never isolate self.
   - `enforcer.add_safe_node("0.0.0.0")` - never isolate unspecified.

2. **Identity / Crypto**: `KeyManager::load_or_generate(node_id)`.
   - Returns 32-byte Ed25519 seed. Persists if first run.
   - No crypto operations yet; just key loading.

3. **MeshNode**: `MeshNode mesh(node_id, &enforcer, &mitigation, &bridge)`.
   - Constructs PBFTConsensus, PeerManager, TransportLayer.
   - Loads or generates the X.509 cert.
   - Starts UDP listener thread on 127.0.0.1:9999.

4. **NodeAgent (eBPF)**: `NodeAgent::create(node_id)`.
   - `load_and_attach_ebpf()`: RLIMIT bump, sensor_bpf__open_and_load,
     kprobe attach, XDP attach, ring buffer setup.
   - On failure, logs actionable error and continues with
     `/proc/net/dev` fallback.

5. **TelemetryBridge**: `TelemetryBridge bridge({websocket_port=N})`.
   - `bridge.spawn()`: fork, child sandbox (chroot + setresuid +
     seccomp), child runs uWebSockets.

6. **IPC listener**: separate `select()` loop in main thread.
   - Unix domain socket at `/tmp/neuro_mesh_{id}.sock`.
   - Shared-secret token auth from env var.

**Stage 2: Heartbeat loop (main.cpp:610-680)**

```
while (global_running.load(memory_order_relaxed)) {
    1. node_agent->poll_events();           // drain ring buffer
    2. for (event : events) inference->analyze(event);
    3. inference->decay(0.5f);              // sticky score decay
    4. if (inference->verdict() == "CRITICAL")
         mesh->initiate_consensus(target, evidence);
    5. mesh->heartbeat();                   // PBFT, gossip, evict
    6. telemetry->flush();                  // JSON export
    7. telemetry_exporter->flush();         // web/mesh_status.json
    8. sleep_for(heartbeat_interval);       // default 2s
}
```

### 5.2 Configuration Loading

Configuration is via environment variables only; there is no config
file. All values have sensible defaults.

| Env var | Default | Effect |
|---------|---------|--------|
| `NEURO_WS_PORT` | derived from node id (9000-9040) | WebSocket port |
| `NEURO_PEERS` | (empty) | Initial peer list, comma-separated `ip:port` |
| `NEURO_PBF` | 10 | PBFT max rounds (per Window) |
| `NEURO_PBFT_MAX` | 5 | PBFT max concurrent |
| `NEURO_PBFT_WINDOW` | (computed from PBF+MAX) | Sliding window in seconds |
| `NEURO_XDP_IFACE` | first available | XDP attach target |
| `NEURO_TOKEN` | (empty) | IPC shared-secret token (required) |

The `NEURO_PEERS` env var is parsed as a comma-separated list of
`ip:port` pairs and seeds the PeerManager on startup.

### 5.3 Node Registration

When a node starts, it:

1. Generates or loads its Ed25519 keypair from
   `~/.neuro_mesh/keys/{id}.key`.
2. Generates or loads its X.509v3 cert from
   `~/.neuro_mesh/certs/{id}.{crt,key}`.
3. Joins the PBFT cluster with `total_nodes` learned from PeerManager.
4. Begins broadcasting discovery beacons on UDP 9998 every 5s.

### 5.4 Peer Discovery

`MeshNode::handle_discovery(payload)` is the entry point for incoming
beacons. The format is:

**V3 (current):**
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<ts>|<b64pub>|<tls_fpr>|<b64cert>|<sig>
```

**V2 (legacy, 8 tokens):**
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<ts>|<b64pub>|<tls_fpr>|<sig>
```

V3 includes the X.509 cert PEM (base64-encoded). The signature binds
`(id || tcp_port || tls_port || ts || tls_fpr || b64cert)`. V2 only
binds the first six fields. V3 receivers call `trust_peer_cert()`
after signature verification; V2 receivers only register the peer.

### 5.5 Consensus Initialization

PBFTConsensus is constructed with `total_nodes` (learned from the peer
set). Once 2f+1 peers are in TRUSTED state, voting can begin.

The proposer for round N is `N % total_nodes`. View changes are
triggered when no progress is made within `VIEW_CHANGE_TIMEOUT_SEC`.

### 5.6 Monitoring Lifecycle

eBPF events flow continuously once the kprobes are attached. The
heartbeat loop polls the ring buffer, runs inference, and updates
verdict. If verdict is CRITICAL, a new PBFT round is initiated.

The TelemetryBridge child receives JSON push events from the parent
and broadcasts to all WebSocket subscribers. Subscribers can connect
to `ws://localhost:{port}/` and receive all events.

### 5.7 Enforcement Lifecycle

When a PBFT round reaches EXECUTED:

1. `MeshNode::on_consensus_executed(round)` is called.
2. `MitigationEngine::on_consensus_executed(round)` is called.
3. `enforcer->isolate_node(target_id)` is called.
4. The target's IP is resolved via `PeerManager::resolve_ip`.
5. `is_safe(target_id)` is checked; safe nodes are skipped with a
   warning.
6. `is_loopback(ip)` is checked; loopback addresses are rejected.
7. `block_ip_address(ip)` is called for all available backends.
8. The result is logged and a telemetry event is emitted.
9. A gossip message `BAN_PEER|<target_id>|<sig>` is broadcast.

### 5.8 Shutdown Lifecycle

In order:

1. `SIGINT`/`SIGTERM` flips `global_running` to false.
2. Main loop exits on next iteration.
3. `ipc_thread.join()` - stops accepting IPC commands.
4. `mesh->stop()` - signals MeshNode's threads; joins the UDP
   listener.
5. `bridge.shutdown()` - closes the pipe; child detects EOF and
   exits; parent `waitpid`s the child.
6. `enforcer.reset_enforcement()` - clears all iptables/nftables
   rules.
7. `AuditLogger::shutdown()` - closes the UDP socket.
8. `node_agent->~NodeAgent()` - detaches BPF programs, destroys
   the skeleton.
9. Process exits 0.

If a signal arrives mid-shutdown, the `global_running` flag is
re-checked at each step. The shutdown is idempotent.

---

## 6. Consensus System Deep Dive

### 6.1 Protocol Overview

Neuro-Mesh implements a simplified PBFT variant optimized for small
N (5-25 nodes) over UDP. The protocol has six stages:

```
IDLE  ->  PRE_PREPARE  ->  PREPARE  ->  COMMIT  ->  EXECUTED  ->  BAN_PEER
                                       (peer removed from set)
```

A round is uniquely identified by `(view, sequence)`. The proposer
for round `(view, sequence)` is `proposer = sequence % total_nodes`.

### 6.2 Message Types

All PBFT messages share the `P2PMessage` struct (PBFT.hpp):

| Field | Purpose |
|-------|---------|
| `stage` | Current PBFT stage (cast to string in wire format) |
| `sender_id` | Node ID of the sender |
| `target_id` | Node ID of the target (for EXECUTED, BAN_PEER; empty for votes) |
| `evidence_json` | nlohmann::json with anomaly details |
| `signature` | Ed25519 sig over `(stage || target_id || evidence_json)` |
| `prev_message_hash` | SHA-256 of the previous message in the chain |
| `view` | Current view number |
| `sequence` | Round number |

### 6.3 Quorum Logic

For N nodes with f Byzantine faults (default N=5, f=1):
- **Safety**: `2f+1 = 3` honest votes required to advance stages.
- **Liveness**: at least `f+1 = 2` honest nodes must be active.

The quorum is computed as `m_vote_counts[stage] >= 2f+1` in
`PBFTConsensus::on_message()`.

### 6.4 Vote Collection

When a message arrives at a node:

1. **Signature verification**: `verify_message()` checks
   `(sender_id || target_id || stage || sequence || view || sha256(evidence_json))`
   against the sender's registered public key.
2. **Stage advancement**: if the round's current stage is `X` and the
   message is for stage `X`, increment the vote count.
3. **State transition**: when `vote_count >= 2f+1`, advance the
   round to stage `X+1` and broadcast a message for the new stage.
4. **Self-vote zero-trust**: the node signs its own vote using the
   same `sign()` API; the next node's verification is identical.

### 6.5 State Transitions

The state machine (per round):

```
IDLE
  | on initiate_consensus(target, evidence)
  v
PRE_PREPARE  (proposer broadcasts, signed)
  | on 2f+1 PRE_PREPARE messages with matching evidence_hash
  v
PREPARE  (each node broadcasts PREPARE)
  | on 2f+1 PREPARE messages
  v
COMMIT  (each node broadcasts COMMIT)
  | on 2f+1 COMMIT messages
  v
EXECUTED  (each node calls MitigationEngine.on_consensus_executed)
  | on 2f+1 EXECUTED messages
  v
BAN_PEER  (target removed from PeerManager; gossip continues)
```

### 6.6 Timeout Behavior

- `VIEW_CHANGE_TIMEOUT_SEC = 30`: if no progress within 30s, trigger
  view change. The new view is `view + 1`, new leader is
  `(view + 1) % N`.
- `ROUND_TTL_SEC = 120`: rounds idle for >120s are evicted by
  `evict_stale_rounds()` (called every 30s from heartbeat).
- `MAX_SEQUENCE_GAP = 100`: any message with sequence more than 100
  ahead of the current local sequence is dropped (prevents runaway
  memory from a malicious proposer).
- `MAX_MSG_HISTORY_PER_SENDER = 10000`: bounded per-sender history
  for equivocation detection.

### 6.7 Failure Handling

**Byzantine node behavior:**
- *Crash*: missed votes; round stalls; view change after 30s.
- *Equivocation*: same `(view, sequence, stage)` with two different
  signatures. Both are stored as `EquivocationEvidence`; sender's
  trust score decreases.
- *Wrong evidence*: signature verification fails; message dropped.
- *Replay*: signature includes `sequence`; old messages dropped.
- *Cross-stage replay*: signature includes `stage`; PREPARE cannot
  be replayed as COMMIT.

**Honest node behavior under attack:**
- Self-vote with same path; verification protects against
  compromised local key (signature would fail).
- Trust score changes do not affect consensus outcomes; only logging.

### 6.8 Replay Protection

Three independent mechanisms:

1. **Signature binding**: `signature = Ed25519(priv, stage || target || evidence || view || sequence)`.
   Replaying the signature in a different `(stage, view, sequence)`
   fails verification.
2. **Sequence numbering**: monotonic counter; old sequences evicted
   via TTL.
3. **Per-sender history cap**: bounded by
   `MAX_MSG_HISTORY_PER_SENDER = 10000` to prevent memory exhaustion.

### 6.9 Duplicate Suppression

`PBFTConsensus::on_message()` checks `m_seen_messages` (a set
keyed by `(sender_id, view, sequence, stage)`) before processing.
A duplicate message is silently dropped with a counter.

### 6.10 Crash Recovery

On restart, the node:

1. Loads `StateJournal` from
   `~/.neuro_mesh/journal/{node_id}.log`.
2. Replays all committed (EXECUTED) decisions into the local state.
3. Discovers peers via UDP beacon.
4. Joins ongoing rounds; rounds that progressed past its last replay
   are re-validated (the node re-queries peers).

There is no automatic PBFT recovery protocol; the assumption is that
a restarted node can re-derive state from peer gossip + journal.

### 6.11 Sequence Diagram: Normal Happy Path

```
ALPHA (proposer)        BRAVO          CHARLIE         DELTA         ECHO
   |                       |               |               |              |
   |-- PREPARE(ALPHA) ---->|-------------->|------------->|------------->|
   |                       |               |               |              |
   |<-- PREPARE(ALPHA) ---|               |               |              |
   |<----------------------|-- PREPARE(ALPHA)              |              |
   |<--------------------------------------|-- PREPARE(ALPHA)             |
   |                       |               |               |              |
   |  [ALPHA counts 3 votes; advances to COMMIT]                |         |
   |-- COMMIT(ALPHA) ----->|-------------->|------------->|------------->|
   |                       |               |               |              |
   |<-- COMMIT(ALPHA) ----|               |               |              |
   |<----------------------|-- COMMIT(ALPHA)               |              |
   |<--------------------------------------|-- COMMIT(ALPHA)              |
   |                       |               |               |              |
   |  [ALPHA counts 3 votes; advances to EXECUTED]            |          |
   |  [ALPHA: MitigationEngine.isolate_node(ALPHA) (self-isolation blocked)]
   |-- EXECUTED(ALPHA) --->|-------------->|------------->|------------->|
   |                       |               |               |              |
   |  [All peers: MitigationEngine.isolate_node(ALPHA)]       |          |
   |  [Apply nftables DROP for ALPHA's IP]                     |          |
   |                                                           |          |
   |-- GOSSIP: telemetry (with ALPHA banned) ---------------->|---------->|
   |                                                           |          |
```

(Note: the example above shows ALPHA proposing, but in practice the
target should not be the proposer. If ALPHA is the target, the
`is_safe` check skips self-isolation. A real scenario: CHARLIE
proposes to ban ALPHA, ALPHA is excluded from the vote count.)

### 6.12 Sequence Diagram: Equivocation

```
ALPHA           BRAVO          CHARLIE
   |               |               |
   |<- PREPARE1 --|               |   (signature1 over (stage, view=0, seq=1, evidence1))
   |               |               |
   |<- PREPARE2 --|               |   (signature2 over (stage, view=0, seq=1, evidence2))
   |               |               |   <- different evidence_hash
   |               |               |
   |  [ALPHA detects equivocation]
   |  [Stores both messages in EquivocationEvidence]
   |  [Decreases BRAVO's trust score]
   |  [Logs security event]
```

BRAVO cannot advance the round; only PREPARE1 or PREPARE2 (not
both) can be counted. The other is dropped.

---

## 7. Security Architecture

### 7.1 Trust Model

The system is built on **zero-trust with cryptographic verification**:

- No node is trusted by default.
- Every message is signed; signatures are verified.
- A peer is trusted only after **dual-path confirmation** (UDP
  discovery + TCP PEX handshake) with matching identity.
- The local node trusts itself via its own Ed25519 keypair, which is
  persisted in `~/.neuro_mesh/keys/{id}.key` with mode 0600.
- Safe list (`add_safe_node()`) is local-only; it can never be
  removed by PBFT consensus.

### 7.2 Authentication

**Identity**: Ed25519 keypair per node. Generated via OpenSSL EVP
using `EVP_PKEY_keygen` with the `EVP_PKEY_ED25519` algorithm.
Persisted in `~/.neuro_mesh/keys/{id}.key` (32-byte raw seed).

**Discovery signatures**: each beacon includes
`sig = Ed25519.sign(priv, id || tcp || tls || ts || tls_fpr || b64cert)`.
Receivers verify with the embedded `b64pub`.

**PBFT message signatures**: each PBFT message includes
`sig = Ed25519.sign(priv, stage || target || evidence || view || sequence)`.
Receivers verify against the sender's registered public key.

**TLS 1.3 mTLS**: self-signed X.509v3 certs pinned via signed PEM
in V3 discovery. The OpenSSL trust store is populated at runtime via
`SSL_CTX_get_cert_store() + X509_STORE_add_cert()`.

### 7.3 Authorization

- PBFT consensus decides what *may* be done (e.g., isolate a peer).
- PolicyEnforcer's safe list decides what *must not* be done
  (e.g., never isolate 127.0.0.1, never isolate a critical node).
- Authorization is local and additive: PBFT grants capability,
  safe list revokes it. There is no way for PBFT to remove a
  safe-list entry.

### 7.4 Signatures

**Algorithm**: Ed25519 (RFC 8032).

**Key size**: 32 bytes private, 32 bytes public.

**Signature size**: 64 bytes.

**Library**: OpenSSL 3.x `EVP_DigestSign*` / `EVP_DigestVerify*`.

**Binding**: every signature binds multiple fields (see
Authentication above). A signature cannot be replayed across stages,
targets, evidence, views, or sequences.

**Binary-safety**: `data.data()` and `data.size()` are used
everywhere; `c_str()` is never used for signature payloads. This
prevents null-byte truncation attacks.

### 7.5 Key Management

**Ed25519 keys**: persisted in `~/.neuro_mesh/keys/{id}.key` (32
bytes, mode 0600). Loaded on startup; generated on first run.

**X.509 certs**: persisted in `~/.neuro_mesh/certs/{id}.{crt,key}`
(mode 0600). Generated on first run; re-used across restarts.

**Trust store**: in-memory only; rebuilt from V3 discovery beacons
on every restart. Not persisted; this is a feature (an attacker
who steals the trust store gets nothing).

**Rotation**: keys are not rotated automatically. Operators may
manually delete the key/cert files to force regeneration; this
invalidates the node's identity and requires re-TOFU with all
peers.

### 7.6 TOFU (Trust on First Use) Behavior

When a node encounters a new peer:

1. UDP discovery beacon arrives with peer_id, b64pub, tls_fpr, b64cert.
2. Signature verified against b64pub; if valid, peer is added with
   state=KNOWN.
3. TCP PEX connection initiated; mTLS handshake verifies the cert.
4. If the mTLS cert's fingerprint matches `tls_fpr` from discovery,
   peer is upgraded to TRUSTED.
5. `trust_peer_cert(peer_id, b64cert)` adds the cert to OpenSSL's
   trust store.
6. Future mTLS handshakes with this peer succeed without re-verification.

**Mismatch handling**: if any of the three paths disagree (signature
invalid, fingerprint mismatch, cert verification failure), the peer
remains UNTRUSTED. Repeated mismatches may trigger a local log
warning but do not affect consensus (the peer cannot vote).

### 7.7 Attack Surface

| Surface | Mitigation |
|---------|------------|
| UDP packet spoofing | Ed25519 signature required; spoofed packets fail verification. |
| UDP packet replay | Signature binds view+sequence+stage; old messages dropped. |
| TCP cert spoofing | Cert pinned via signed PEM in V3 discovery. |
| TCP MITM | TLS 1.3 with X25519 / P-256 key exchange. |
| mTLS cert theft (no key) | Cert signed by Ed25519 identity key; binding is in the cert, not the key. |
| Sandboxed child escape | chroot + setresuid + 65-syscall seccomp default-kill. |
| iptables shell injection | `fork()+execv()` with argv as `vector<string>`. |
| Null-byte truncation | `data.data()/data.size()` instead of `c_str()`. |
| Process suspension | `kill(pid, SIGSTOP)` / `kill(pid, SIGKILL)`. |
| Resource exhaustion | Bounded queues with drop counters. |
| DoS via fork-bomb | `fork_exec_wait` is rate-limited by the parent. |
| Stale round accumulation | 120s TTL eviction. |
| eBPF event loss | Tight drain loop in `poll_events()`. |
| Local key theft | 0600 file permissions; no root escalation required. |

### 7.8 Threat Model (Formal Statement)

**Adversary assumptions:**
- Up to `f=1` of `N=5` nodes may be Byzantine (compromise, lie,
  equivocate, omit, or collude).
- The network is hostile: an attacker can sniff, replay, drop,
  inject, delay, or reorder any packet.
- The adversary has bounded compute (cannot break Ed25519 or SHA-256).
- The adversary does not have root on honest nodes (cannot access
  `~/.neuro_mesh/keys/{id}.key`).

**Security properties:**

1. **Agreement**: if an honest node commits round R with outcome O,
   all honest nodes commit round R with outcome O.

2. **Validity**: a committed outcome was proposed by at least one
   honest node.

3. **Termination**: every round either reaches EXECUTED or evicts
   via 120s TTL.

4. **Safe-list invariant**: `add_safe_node()` cannot be undone by
   consensus.

5. **No self-isolation**: a node's own peer_id is always in the
   safe-list at startup.

6. **Replay resistance**: signatures bind (stage, view, sequence,
   evidence); replay is cryptographically impossible.

7. **Equivocation detection**: if a sender signs two conflicting
   messages for the same (view, sequence), both are recorded as
   `EquivocationEvidence`.

**Out-of-scope (per Section 1.4 Non-Goals):**
- Sybil attacks on identity provisioning.
- Hardware-level side channels.
- A node whose key is compromised.
- Confidentiality of telemetry at rest.

### 7.9 Security Boundaries

- **Kernel ↔ userspace**: eBPF map reads/writes are in-kernel only;
  the userspace agent reads via ring buffer. Direct map mutation
  from userspace requires CAP_BPF.
- **Parent ↔ TelemetryBridge child**: pipe (O_CLOEXEC on write end).
  No shared memory. The child has no syscall to read parent
  memory.
- **Parent ↔ iptables children**: argv is `vector<string>`; no
  shell. The children run as root (required for nftables) but
  perform one specific action and exit.
- **Node ↔ network**: all PBFT messages signed; all TCP mTLS.

---

## 8. Networking Architecture

### 8.1 Transport Protocols

| Channel | Protocol | Port | Direction | Auth | Purpose |
|---------|----------|------|-----------|------|---------|
| PBFT | UDP | 9999 (configurable) | mesh-wide | Ed25519-signed | Consensus votes |
| Discovery | UDP | 9998 (configurable) | broadcast | Ed25519-signed | Peer beacons |
| PEX | TCP | 10000 (configurable) | peer-to-peer | Ed25519+fingerprint | Peer exchange |
| mTLS | TCP | 10500 (configurable) | peer-to-peer | TLS 1.3 + cert pin | Bulk telemetry, evidence |
| WebSocket | TCP | 9000-9044 | client-to-node | none (LAN) | Dashboard live view |
| IPC | Unix domain socket | `/tmp/neuro_mesh_{id}.sock` | local | token | Operator commands |
| Audit log | UDP | configured | external sink | none | Structured logs |

### 8.2 Peer Communication

**UDP broadcast (loopback only)**: in the default deployment
(localhost, network namespaces), nodes use `127.0.0.1` and broadcast
to `255.255.255.255:9999`. The `netns` demo requires an explicit
broadcast route on each veth (`255.255.255.255/32 dev v-{id}`).

**UDP unicast (real deployments)**: in real deployments (multi-host),
discovery uses UDP broadcast within a subnet, and PBFT messages use
UDP unicast to each known peer (no broadcast amplification).

**TCP PEX**: the Peer Exchange port (10000) is plain-text and used
only for exchanging peer lists during mesh formation. The payload is
a JSON array of known peer IDs and IPs.

**TCP mTLS**: the secure channel (10500) is used for everything else:
bulk telemetry, large evidence payloads, mesh status queries.

### 8.3 Message Routing

**Outgoing (per-peer)**: MeshNode maintains a `peers` map keyed by
peer_id. For each outgoing message, the map is iterated and a
unicast UDP packet is sent to `peers[id].last_ip:9999`.

**Incoming**: a single UDP listener thread reads from the socket
and dispatches to handlers:

- Starts with `DISCOVERY` -> `handle_discovery()`.
- Starts with `PBFT` -> `handle_pbft_message()`.
- Starts with `TELEMETRY` -> `handle_telemetry_gossip()`.
- Starts with `PEX` -> `handle_pex()`.
- Otherwise -> logged and dropped.

### 8.4 Retry Logic

**UDP PBFT**: messages are not explicitly retried; the proposer
waits for 30s (view change timeout) before giving up. Implicit
retransmission is provided by the next view's proposal.

**TCP mTLS**: explicit retry with exponential backoff (1s, 2s, 4s,
8s, capped at 30s). Max 5 attempts before giving up.

**TCP PEX**: 3 attempts with 1s backoff.

**Discovery beacon**: every 5s, regardless of prior success.

### 8.5 Serialization Formats

**PBFT message wire format (UDP):**
```
PBFT|<stage>|<sender_id>|<target_id>|<view>|<sequence>|<b64evidence>|<b64sig>
```

Length-prefixed fields use `|` as separator. Evidence and
signature are base64-encoded.

**V3 discovery beacon (UDP):**
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<ts>|<b64pub>|<tls_fpr>|<b64cert>|<b64sig>
```

The signature binds `(id || tcp_port || tls_port || ts || tls_fpr || b64cert)`.

**V2 discovery beacon (legacy, 8 tokens):**
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<ts>|<b64pub>|<tls_fpr>|<b64sig>
```

V2 receivers do not call `trust_peer_cert()`. V2 is preserved for
backward compatibility with older nodes.

**Telemetry JSON (UDP and pipe):**
```json
{
  "ts": "2026-06-05T12:34:56.789Z",
  "node_id": "ALPHA",
  "consensus_view": 42,
  "events": [...],
  "metrics": {
    "telemetry_queue_drops": 0,
    "pbft_rounds_executed": 17,
    "enforcement_rules_active": 3
  }
}
```

### 8.6 Connection Lifecycle

**TCP mTLS connection (incoming):**
1. `accept()` on listener socket (10500).
2. `SSL_new()`, `SSL_set_fd()`, `SSL_accept()`.
3. Server cert presented; client verifies against local trust store.
4. If verify fails: `SSL_shutdown()`, close, drop.
5. If verify succeeds: enter app protocol loop (read JSON
   commands, write JSON responses).
6. On EOF or error: `SSL_shutdown()`, close, free SSL.

**TCP mTLS connection (outgoing):**
1. `socket()`, `connect()` to peer's 10500.
2. `SSL_new()`, `SSL_set_fd()`, `SSL_connect()`.
3. Client presents cert; server verifies.
4. If verify fails: `SSL_shutdown()`, close, retry with backoff.
5. If verify succeeds: enter app protocol loop.
6. On EOF or error: `SSL_shutdown()`, close, free SSL.

**Unix domain socket (IPC):**
1. Server: `socket(AF_UNIX)`, `bind()`, `listen()`.
2. Client: `socket(AF_UNIX)`, `connect()`.
3. Client sends `AUTH|<token>\n`.
4. Server reads token, compares to expected (constant-time).
5. On match: client may issue `CMD:INJECT|...`, `CMD:ISOLATE|...`,
   `CMD:RESET`, `CMD:SHUTDOWN`.
6. Server responds with `ACK:...` or `ERR:...`.
7. Server enforces per-UID rate limit (10 commands/sec default).
8. Server uses `SO_PEERCRED` to identify the client UID.
9. On disconnect: `close()`, continue.

---

## 9. Enforcement Engine

### 9.1 Detection Pipeline

```
eBPF kprobe (sys_execve, sys_sendto, sys_sendmsg, sys_connect)
   |
   v
ring buffer (256 KB)
   |
   v
NodeAgent::poll_events() [tight drain loop]
   |
   v
InferenceEngine::analyze(comm, payload)
   |  (5 features: payload len, payload entropy, comm len,
   |   comm entropy, derived rarity)
   v
ONNX IsolationForest score
   |
   v
threshold check (default -0.05)
   |
   v
CRITICAL or NONE verdict
   |
   v
[if CRITICAL] MeshNode::initiate_consensus(target, evidence)
   |
   v
PBFT state machine (PRE_PREPARE -> PREPARE -> COMMIT -> EXECUTED)
   |
   v
MitigationEngine::on_consensus_executed(round)
   |
   v
PolicyEnforcer::isolate_node(target_id) (all backends)
   |
   v
nftables / iptables / XDP DROP rules applied
```

### 9.2 Rule Evaluation

For each consensus-EXECUTED target:

1. **Safe-list check**: `is_safe(target_id)` returns true -> skip.
2. **Loopback check**: `is_loopback(ip)` returns true -> skip.
3. **IP resolution**: `PeerManager::resolve_ip(target_id)` -> IP.
4. **Backend iteration**: for each available backend (NFT > IPT > EBPF),
   apply DROP rule.
5. **Idempotency**: the same target may be isolated multiple times;
   each call re-applies the rule (overwriting the previous one).
6. **Logging**: a structured `ENFORCER` event is logged with target,
   IP, backend, and rule count.

### 9.3 Response Generation

Two response types:

**Network isolation** (`isolate_node` or `block_ip_address`):
- nftables: `nft add rule inet neuro_chain input ip saddr X.X.X.X drop`.
- iptables: `iptables -I INPUT -s X.X.X.X -j DROP`.
- XDP: `xdp_blacklist[X.X.X.X] = 1` (BPF map update).
- Process suspension (if `evidence_json.pid` is set):
  `kill(pid, SIGSTOP)`.

**Recovery** (manual via IPC):
- `CMD:RESET` -> `enforcer.reset_enforcement()` clears all rules.
- `CMD:INJECT` -> manually trigger an event for testing.

### 9.4 Ban Propagation

After EXECUTED + isolation, the local node broadcasts:
```
BAN_PEER|<target_id>|<b64sig>
```

to all known peers. Peers receiving this message:

1. Verify the signature against the sender's registered key.
2. Add `target_id` to their local ban list (in PeerManager).
3. Apply their own isolation rules for the target's IP.
4. Gossip the ban to their peers (with TTL=3 to prevent loops).

The result: a banned node is isolated by all honest peers within
~3 hop latencies, with cryptographic proof of the decision.

### 9.5 Rollback Behavior

There is no automatic rollback. A banned node remains isolated
until:

- An operator manually issues `CMD:RESET` via IPC.
- The node is restarted (which clears the local ban list; the
  node is then re-discovered and re-banned by its peers within
  one beacon interval).

The lack of automatic rollback is intentional. A node that was
isolated for good reason (anomaly, equivocation) should not be
allowed back in automatically; this would be a footgun for the
attacker.

### 9.6 fork() + execv() Pattern

`PolicyEnforcer::fork_exec_wait(path, argv)` is the only way to
spawn a child process. It:

1. Creates a pipe for capturing stderr/stdout (optional).
2. `fork()`s. Parent blocks on `waitpid()`.
3. Child:
   a. Closes all FDs except pipe ends (defense in depth).
   b. `dup2()`s pipe ends to fd 1/2 if capturing.
   c. `execv(path, argv)` - explicit path, no PATH lookup.
   d. On `execv` failure: `_exit(127)`.
4. Parent: collects exit code, returns `(success, exit_code)`.

The argv is always `vector<string>`; no shell, no metacharacter
processing. An attacker cannot inject `; rm -rf /` into a rule
even if they control the evidence_json.

### 9.7 Backend-Specific Notes

**nftables (preferred):**
- Table: `inet neuro_chain`.
- Chain: `input` (priority 0; hook input at priority 0).
- Rule: `ip saddr X.X.X.X drop`.
- Idempotency: re-applying the same rule is a no-op (the table
  detects duplicates).

**iptables (fallback):**
- Chain: `INPUT`.
- Rule: `-I INPUT -s X.X.X.X -j DROP` (insert at top).
- Idempotency: re-insertion is harmless.

**XDP blocklist (fastest):**
- Map: `xdp_blacklist[ipv4] -> u8`.
- Update: `bpf_map_update_elem(...)` from userspace.
- Idempotency: overwriting is fine.

**Process suspension:**
- `kill(pid, SIGSTOP)` - pauses the process.
- `kill(pid, SIGCONT)` - resumes (not implemented; manual via shell).
- `kill(pid, SIGKILL)` - terminates (not implemented).

---

## 10. Telemetry & Monitoring

### 10.1 Telemetry Collection

Three independent paths:

1. **Console**: every component logs to stdout/stderr via
   `std::cout`/`std::cerr`. Captured by the process supervisor
   (or `tee` for file logging in `mesh_dashboard.sh`).

2. **Audit UDP**: structured JSON lines sent to a configured
   remote sink. Useful for centralized log aggregation without
   coupling the agent to the log pipeline.

3. **WebSocket push**: real-time JSON to dashboard subscribers.
   Goes through the sandboxed TelemetryBridge child.

### 10.2 Metrics

`Observability` (singleton) collects:

**Counters** (atomic u64):
- `telemetry_queue_drops` - ring buffer overflows.
- `pbft_rounds_initiated`.
- `pbft_rounds_executed`.
- `pbft_rounds_evicted` - timeout-based.
- `equivocation_events_detected`.
- `enforcement_rules_applied`.
- `tls_handshakes_succeeded`.
- `tls_handshakes_failed`.

**Gauges** (atomic double):
- `cpu_usage_percent`.
- `memory_rss_bytes`.
- `active_peers`.
- `untrusted_peers`.
- `banned_peers`.

**Histograms** (100-sample ring):
- `pbft_round_duration_ms`.
- `tls_handshake_duration_ms`.
- `enforcement_apply_duration_ms`.

### 10.3 Aggregation

The MetricsRegistry aggregates via lock-free atomics for
counters/gauges and a `std::shared_mutex` for histograms.
`Observability::snapshot()` produces a `nlohmann::json` with all
metrics in a single call.

### 10.4 Storage

- **In-memory**: MetricsRegistry; cleared on restart.
- **Disk**: TelemetryExporter writes
  `web/mesh_status.json` every 5s (POSIX file-locked).
- **Network**: AuditLogger UDP and TelemetryBridge WebSocket are
  the two real-time output channels.

### 10.5 Reporting

The dashboard (`dashboard/index.html`) connects to any node's
WebSocket port (9000-9044) and receives the full mesh state via
gossip. The dashboard renders:

- Per-node health (CPU, memory, uptime).
- Live consensus rounds.
- Active enforcement rules.
- Banned peers.
- Anomaly scores over time (Canvas-rendered time series).

The dashboard is zero-dependency (no React, no Webpack, no npm);
it uses native Canvas + WebSocket.

### 10.6 Telemetry Gossip Protocol

Every 2s (heartbeat interval), each node:

1. Builds a `TelemetryMessage` containing:
   - `node_id`, `ts`.
   - All metrics counters/gauges/histograms.
   - Local PBFT view.
   - Local PeerManager state (id, state, last_seen for each).
2. Serializes to JSON.
3. Base64-encodes the JSON.
4. Wraps in a UDP packet:
   `TELEMETRY|<node_id>|<b64json>|<b64sig>`.
5. Unicasts to all known peers (not broadcast, to prevent
   amplification).

Receivers:

1. Verify the signature against the embedded pubkey.
2. Parse the JSON.
3. Update the local `MeshView` (a map from node_id to TelemetryMessage).
4. Forward to the local TelemetryBridge which broadcasts to
   dashboard subscribers.
5. Apply rate limiting (max 1 message per sender per second) to
   prevent flooding.

The result: any node can serve the dashboard with the full mesh
view within one gossip round (~2s) of a state change.

### 10.7 Structured Log Format

```
[<ISO8601-TS>] [<LEVEL>] [<COMPONENT>] <message> | key=value key=value ...
```

Example:
```
[2026-06-05T12:34:56.789Z] [INFO] [PBFT] Round 42 reached EXECUTED | target=ALPHA view=0 sequence=42 votes=3
```

Components: `BOOT`, `EBPF`, `TLS`, `PEX`, `DISCOVERY`, `PBFT`,
`ENFORCER`, `IPC`, `SANDBOX`, `TELEMETRY`, `AUDIT`.

Levels: `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`.

---

## 11. Data Flow Analysis

This section traces five end-to-end data flows through the entire
system, with file:line references at each step.

### 11.1 Detection Event Flow (Happy Path)

Triggered by an `execve` syscall on ALPHA.

```
KERNEL (ALPHA)
  kernel/sensor.bpf.c:trace_execve
    | (bpf_get_current_pid_tgid, bpf_get_current_comm,
    |  bpf_probe_read_user_str from arg)
    v
  ring buffer: telemetry_ringbuf
    | (bpf_ringbuf_submit)
    v
USERSPACE (ALPHA)
  cell/NodeAgent.cpp:handle_event (libbpf callback)
    | (push to m_queue)
    v
  TelemetryQueue<KernelEventData>
    | (poll_events() drains in tight loop)
    v
  cell/NodeAgent.cpp:poll_events
    | (returns vector<KernelEventData>)
    v
  main.cpp:heartbeat_loop
    | (for ev in events: inference->analyze(ev.comm, ev.payload))
    v
  cell/InferenceEngine.cpp:analyze
    | (extract_features, ONNX inference)
    v
  InferenceEngine::m_last_score > threshold
    | (verdict() returns "CRITICAL")
    v
  main.cpp:heartbeat_loop
    | (mesh->initiate_consensus(target=ALPHA, evidence))
    v
  consensus/MeshNode.cpp:initiate_consensus
    | (PBFTConsensus::on_message(self-vote))
    v
  consensus/PBFT.hpp:on_message
    | (verify_message, advance state to PRE_PREPARE)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage
    | (unicast to all known peers)
    v
NETWORK
  UDP 9999 -> peers' 9999
    |
    v
USERSPACE (peers)
  consensus/MeshNode.cpp:handle_pbft_message
    | (verify signature, dispatch to PBFTConsensus)
    v
  consensus/PBFT.hpp:on_message
    | (verify_message, count vote, advance to PREPARE)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage
    | (unicast PREPARE vote to all)
    ... (repeats for PREPARE, COMMIT, EXECUTED)
    v
  consensus/MeshNode.cpp:on_consensus_executed
    | (mitigation->on_consensus_executed(round))
    v
  enforcer/MitigationEngine.cpp:on_consensus_executed
    | (enforcer->isolate_node(target=ALPHA))
    v
  enforcer/PolicyEnforcer.cpp:isolate_node
    | (probe_backends, apply to NFT, IPT, EBPF)
    v
KERNEL
  nftables: nft add rule inet neuro_chain input ip saddr <ALPHA_IP> drop
  iptables: iptables -I INPUT -s <ALPHA_IP> -j DROP
  XDP: bpf_map_update_elem(xdp_blacklist, <ALPHA_IP>, 1)
    |
    v
  Packets from ALPHA are now dropped at INPUT chain
```

### 11.2 Consensus Event Flow (PBFT Round)

```
USERSPACE (proposer)
  consensus/MeshNode.cpp:initiate_consensus(target, evidence)
    | (build P2PMessage{stage=PRE_PREPARE, sequence=N, view=V})
    v
  consensus/PBFT.hpp:on_message
    | (sign with local Ed25519 priv)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage
    | (unicast to all peers)
    v
NETWORK
  UDP 9999 -> peers
    |
    v
USERSPACE (each peer)
  consensus/MeshNode.cpp:handle_pbft_message
    | (parse, verify signature)
    v
  consensus/PBFT.hpp:verify_message
    | (Ed25519.verify(pub, sig, (stage||target||evidence||view||sequence)))
    v
  consensus/PBFT.hpp:on_message
    | (check stage, increment vote count, check 2f+1)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage (PREPARE)
    ... (repeats for PREPARE -> COMMIT -> EXECUTED)
    v
  consensus/MeshNode.cpp:on_consensus_executed
    | (call mitigation->on_consensus_executed)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage (EXECUTED)
    | (gossip to all peers)
    v
  consensus/MeshNode.cpp:handle_pbft_message (peers receive EXECUTED)
    | (each peer applies their own isolation)
    v
  consensus/MeshNode.cpp:broadcast_pbft_stage (BAN_PEER)
    | (each peer gossips the ban with TTL=3)
```

### 11.3 Enforcement Event Flow (Ban Propagation)

```
USERSPACE (peer that executed)
  consensus/MeshNode.cpp:on_consensus_executed
    | (enforcer->isolate_node(target))
    v
  enforcer/PolicyEnforcer.cpp:isolate_node
    | (is_safe? is_loopback? resolve_ip)
    v
  fork_exec_wait("nft", ["nft", "add", "rule", ...])
    fork_exec_wait("iptables", ["iptables", "-I", "INPUT", ...])
    bpf_map_update_elem(xdp_blacklist, ...)
    | (all three run; first success wins for the rule)
    v
  struct EnforcementEvent {target, ip, backend, ts, success}
    | (push to telemetry)
    v
  telemetry/TelemetryBridge.cpp:push_telemetry (JSON)
    | (write to pipe)
    v
  TelemetryBridge child reads pipe
    | (broadcast to all WebSocket subscribers)
    v
NETWORK
  UDP broadcast (telemetry) to all peers
    |
    v
USERSPACE (peers)
  consensus/MeshNode.cpp:handle_telemetry_gossip
    | (forward to local TelemetryBridge)
    v
  TelemetryBridge child broadcasts to its subscribers
```

### 11.4 Recovery Event Flow (Node Restart)

```
USERSPACE (restarting node)
  main()
    | (KeyManager::load_or_generate(node_id))
    v
  crypto/KeyManager.cpp
    | (read ~/.neuro_mesh/keys/{id}.key)
    v
  IdentityCore (keypair reconstructed)
    | (X.509 cert loaded from ~/.neuro_mesh/certs/{id}.crt)
    v
  PBFTConsensus (empty state)
    | (read StateJournal)
    v
  common/StateJournal.cpp
    | (parse ~/.neuro_mesh/journal/{id}.log)
    v
  Replay all committed decisions into local state
    | (apply ban list, restore known peers)
    v
  MeshNode starts UDP listener
    | (begins broadcasting DISCOVERY beacons)
    v
NETWORK
  UDP 9998 broadcast every 5s
    |
    v
USERSPACE (peers)
  consensus/MeshNode.cpp:handle_discovery
    | (verify signature, register peer as KNOWN)
    v
  consensus/MeshNode.cpp:initiate_pex
    | (TCP connect to peer's 10000)
    v
NETWORK
  TCP 10000 connection
    |
    v
USERSPACE (peers)
  consensus/MeshNode.cpp:handle_pex
    | (send peer list, mTLS handshake)
    v
  mTLS handshake (cert verify, fingerprint match)
    | (peer upgraded to TRUSTED)
    v
  trust_peer_cert(peer_id, peer_cert)
    | (add to OpenSSL trust store)
    v
  Rejoin ongoing PBFT rounds
    | (catch up via gossip)
```

### 11.5 Telemetry Event Flow

```
USERSPACE (any component)
  Observability::increment_counter("pbft_rounds_executed")
    | (atomic u64 increment)
    v
  Observability (in-memory)
    |
    v
  Two consumers:
    |
    +-> telemetry/TelemetryExporter::flush
    |     | (snapshot all metrics to JSON)
    |     v
    |   web/mesh_status.json (POSIX-locked)
    |     |
    |     v
    |   Dashboard HTTP poll fallback
    |
    +-> main.cpp:heartbeat_loop
          | (build TelemetryMessage)
          v
        consensus/MeshNode.cpp:broadcast_telemetry
          | (unicast to all known peers)
          v
        NETWORK
          |
          v
        USERSPACE (peers)
          consensus/MeshNode.cpp:handle_telemetry_gossip
            | (push to local TelemetryBridge)
            v
          telemetry/TelemetryBridge.cpp:push_telemetry
            | (write to pipe)
            v
          TelemetryBridge child
            | (broadcast to WebSocket subscribers)
            v
          Browser (dashboard)
```

---

## 12. State Management

### 12.1 State Machines

**PBFTConsensus state machine** (per round, indexed by `sequence`):

```
struct Round {
    PBFTStage state = IDLE;
    int view = 0;
    string pre_prepare_hash;
    string evidence_key;
    string commit_signature;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point last_activity;
};
```

Transitions:
- `IDLE -> PRE_PREPARE`: on `initiate_consensus()`.
- `PRE_PREPARE -> PREPARE`: on 2f+1 PRE_PREPARE votes.
- `PREPARE -> COMMIT`: on 2f+1 PREPARE votes.
- `COMMIT -> EXECUTED`: on 2f+1 COMMIT votes.
- `EXECUTED -> BAN_PEER`: on 2f+1 EXECUTED votes (optional, gossiped).

**Peer state machine** (in PeerManager):

```
struct Peer {
    PeerState state = UNKNOWN;  // UNKNOWN -> KNOWN -> TRUSTED -> BANNED
    std::string id;
    std::string public_key_pem;
    std::string tls_fpr;
    std::string cert_pem;        // V3 only
    std::string last_ip;
    std::chrono::steady_clock::time_point last_seen;
    int trust_score = 100;
};
```

Transitions:
- `UNKNOWN -> KNOWN`: on first valid discovery beacon.
- `KNOWN -> TRUSTED`: on TCP PEX with matching fingerprint.
- `KNOWN/TRUSTED -> BANNED`: on receiving BAN_PEER consensus.
- `BANNED -> TRUSTED`: on `CMD:RESET` (operator action only).

**Enforcement state machine** (in PolicyEnforcer):

```
struct ActiveRule {
    std::string target_id;
    std::string ip;
    EnforcementBackend backend;
    std::chrono::steady_clock::time_point applied_at;
    int rule_handle;             // iptables rule number
};
```

Rules are added on EXECUTED; never removed automatically; only
removed on `reset_enforcement()` (operator action) or process
restart (without persistence).

### 12.2 Persistence

**Persisted to disk:**

| Path | Format | Purpose |
|------|--------|---------|
| `~/.neuro_mesh/keys/{id}.key` | 32-byte raw Ed25519 seed | Identity |
| `~/.neuro_mesh/certs/{id}.crt` | PEM X.509v3 | TLS cert |
| `~/.neuro_mesh/certs/{id}.key` | PEM RSA/Ed25519 | TLS private key |
| `~/.neuro_mesh/journal/{id}.log` | append-only JSON | PBFT history |
| `web/mesh_status.json` | JSON snapshot | Dashboard HTTP poll |

**In-memory only (rebuilt on restart):**

- PeerManager state (rebuilt from V3 discovery beacons).
- OpenSSL trust store (rebuilt from V3 cert PEMs).
- PBFTConsensus round state (rebuilt from journal + gossip).
- Active enforcement rules (cleared on restart; will be reapplied
  via gossip within ~5s of restart).

### 12.3 Recovery

**Node restart recovery:**

1. `KeyManager::load_or_generate(node_id)` returns the persisted
   Ed25519 key.
2. `X509` cert loaded from `~/.neuro_mesh/certs/{id}.crt`.
3. `StateJournal::replay_since(0)` reads all committed decisions.
4. PeerManager starts empty; populated via UDP discovery.
5. TelemetryExporter starts writing on first heartbeat.
6. Enforcement is empty; rules are reapplied via gossip within
   ~5s as peers send `EXECUTED` messages for ongoing rounds.

**Mid-round crash (proposer dies):**

- After 30s view-change timeout, a new view is initiated.
- The new proposer re-broadcasts `PRE_PREPARE` with the same
  evidence.
- Peers that already have a `Round` in state `PREPARE` for this
  sequence update their `view` and continue.
- Peers that did not have the round start fresh.

**Mid-round crash (voter dies):**

- The remaining `2f+1` voters complete the round.
- The dead voter re-derives state from `StateJournal` on restart.

### 12.4 Synchronization

**Across the mesh:**

- PBFT provides consensus-level synchronization: all honest nodes
  agree on the same set of EXECUTED rounds.
- Gossip provides best-effort eventual consistency for telemetry.
- Discovery beacons (every 5s) provide view synchronization: each
  node's PeerManager eventually reflects the same set of active
  peers.

**Across processes (local):**

- IPC socket provides command-response synchronization.
- `flock` on `mesh_status.json` prevents corruption if multiple
  nodes share a volume (rare in practice; only for the demo).

### 12.5 No Distributed Transactions

Neuro-Mesh does **not** implement cross-node transactions. PBFT
produces agreement on a single decision per round, but there is no
multi-round atomicity. If round R1 bans peer X and round R2 unbans
peer X (in a hypothetical unban round), they are processed
independently and the later decision wins.

---

## 13. Failure Handling

### 13.1 Node Crashes

**Hard crash (SIGKILL, OOM, kernel panic):**
- The IPC socket is removed by the kernel.
- Peers detect this via UDP beacon timeout (5s beacon * 3 missed
  = 15s to detect).
- The dead node is marked stale; its EXECUTED decisions are
  re-validated by the remaining `2f+1` nodes.
- On restart, the node reloads its key + journal + certs and
  rejoins via discovery.

**Graceful shutdown (SIGINT/SIGTERM):**
- `global_running` flag is set to false.
- Main loop exits.
- IPC listener joins.
- MeshNode stops UDP listener.
- TelemetryBridge child detects pipe EOF and exits.
- Enforcer clears all rules (optional, configurable).
- AuditLogger closes socket.
- Process exits 0.

### 13.2 Message Loss

**UDP packet loss:**
- PBFT does not retransmit; the view-change protocol (30s timeout)
  eventually re-runs the round.
- Telemetry gossip is best-effort; the next heartbeat (2s) sends
  fresh data.
- Discovery beacons are idempotent; loss is invisible.

**TCP connection loss:**
- mTLS connections are not held open indefinitely; each request
  opens a fresh connection.
- TCP PEX is fire-and-forget; loss means a slower mesh formation
  but no functional degradation.

**Pipe (parent-to-bridge) loss:**
- The bridge child detects pipe EOF and exits.
- The parent may continue to operate; the dashboard is unavailable
  but the agent is still functional.

### 13.3 Invalid Messages

**Signature failure:** message dropped, counter incremented.

**Stage mismatch:** message dropped (round is at a different stage).

**Sequence gap:** message dropped if `MAX_SEQUENCE_GAP` exceeded
(default 100).

**View mismatch:** message triggers view change if it has a
higher view number; otherwise dropped.

**Unknown sender:** message dropped (sender not in
`m_peer_public_keys`).

**Replay:** signature includes sequence; old message dropped.

**Equivocation:** stored as evidence; sender's trust score
decreased; the conflicting messages are both retained for audit.

### 13.4 Consensus Failures

**No quorum reached within 30s:** view change triggered.
The new view number is `view + 1`; the new leader is
`(view + 1) % N`.

**Quorum reached but rule apply fails:** `MitigationEngine` logs
error and continues. The consensus decision is still valid; the
node may attempt to re-apply the rule on the next heartbeat.

**Conflicting decisions across views:** prevented by signature
binding (a view-N signature is not valid in view-N+1).

**Two proposers simultaneously:** PBFT guarantees that only one
proposer's `PRE_PREPARE` will reach 2f+1; the other's votes are
discarded. The discarded proposer learns this from the lack of
PREPARE votes and backs off.

### 13.5 Enforcement Failures

**nftables/iptables not installed:** `probe_backends()` returns
the subset available; the agent proceeds with what it has.

**Permission denied (not root):** `fork_exec_wait` returns
non-zero; the rule is not applied; the agent logs an error and
continues. The decision stands; the operator must fix permissions
or run as root.

**XDP attach fails:** `load_and_attach_ebpf()` returns error;
the agent falls back to userspace-only detection.

**Backend hung (nft in deadlock):** parent `waitpid` returns -1
with ECHILD or EINTR after 5s; the rule is considered failed;
logged with the timeout.

### 13.6 Network Failures

**Subnet unreachable:** discovery beacons time out; no new
peers; existing peers continue to vote.

**Switch loop (broadcast storm):** mitigated by rate limiting
on the receiver side; broadcasts that exceed
`MAX_MESSAGES_PER_SENDER_PER_SECOND` are dropped.

**DNS failure:** the agent does not use DNS (all peers are
identified by node_id + IP, never hostname). DNS failure is
invisible to the agent.

**Routing loop:** mitigated by TTL=3 on BAN_PEER gossip. After
3 hops, the message is dropped.

**TCP mTLS handshake timeout:** 5s timeout; exponential backoff
on retry (1s, 2s, 4s, 8s, 16s, 30s cap); 5 attempts max.

### 13.7 Sandbox Failures

**chroot fails:** FATAL log; bridge continues without chroot
(less secure but functional). Dashboard works.

**setresuid fails:** FATAL log; child exits. Dashboard unavailable.

**Seccomp install fails:** FATAL log; child exits. Dashboard
unavailable.

**Syscall not whitelisted:** kernel kills the child with
SIGSYS. Parent detects via `waitpid`; logs and respawns (max 3
times, then gives up).

**Pipe write fails (parent dies):** child detects EOF; exits
cleanly. Respawned on next agent restart.

### 13.8 eBPF Failures

**BPF load fails (verifier rejection):** error message with
actionable remediation. Falls back to `/proc/net/dev` entropy
mode. No kernel-level observability.

**BPF load fails (EPERM):** error message indicates
`unprivileged_bpf_disabled` value. Falls back to
`/proc/net/dev` entropy mode.

**Ring buffer overrun:** events are dropped on the floor;
counter incremented; visible in telemetry.

**Interface disappears:** XDP program remains attached but
receives no packets. No automatic reattach.

**BPF map full:** `bpf_map_update_elem` returns E2BIG; the
update is dropped. New blacklist entries are not added.

### 13.9 Crypto Failures

**OpenSSL not initialized:** static init in `main()` should
prevent this; if it fails, Ed25519 operations segfault.

**Key file missing:** generated on first run; persisted.

**Key file corrupted:** crash on startup; manual intervention
required (the key is the identity, cannot be guessed).

**Cert verification failure:** the connection is rejected; peer
remains UNTRUSTED.

**Cert expired:** OpenSSL handles this; the connection is
rejected with `SSL_R_CERTIFICATE_VERIFY_FAILED`.

**Signature decode error:** `verify` returns false; message
dropped.

---

## 14. Configuration System

All configuration is via environment variables. There is **no config
file**. This is intentional: the agent is designed to be deployed via
container orchestration (Docker, k8s, systemd) where env vars are
the canonical configuration mechanism.

### 14.1 Environment Variables

| Name | Default | Effect | Risk if changed |
|------|---------|--------|-----------------|
| `NEURO_WS_PORT` | derived from node id (9000-9040) | WebSocket port for dashboard | Conflict with other services; if wrong, dashboard unavailable. |
| `NEURO_PEERS` | (empty) | Initial peer list, comma-separated `ip:port` | Wrong IPs = no initial peers; node will discover them via broadcast. |
| `NEURO_PBF` | 10 | PBFT max rounds per window | Too low = thrashing; too high = memory growth. |
| `NEURO_PBFT_MAX` | 5 | PBFT max concurrent rounds | Too high = out-of-order commit; too low = underutilization. |
| `NEURO_PBFT_WINDOW` | (computed) | Sliding window in seconds | Affects throughput vs latency tradeoff. |
| `NEURO_XDP_IFACE` | first available | XDP attach target interface | Wrong name = XDP not attached; falls back to IPT/NFT. |
| `NEURO_TOKEN` | (empty) | IPC shared-secret token | **Required for production.** Empty = anyone with shell access can control the node. |

### 14.2 Default WebSocket Port Mapping

When `NEURO_WS_PORT` is not set, the port is derived from node id:

| Node id | Port |
|---------|------|
| ALPHA | 9000 |
| BRAVO | 9010 |
| CHARLIE | 9020 |
| DELTA | 9030 |
| ECHO | 9040 |
| Other | 9000 + (hash of id) % 1000 |

This avoids host-network port conflicts when running multiple nodes
on the same host (e.g., for testing).

### 14.3 PBFT Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `f` (Byzantine fault tolerance) | 1 | Max Byzantine peers. Total nodes = 3f+1 = 5. |
| `2f+1` (quorum) | 3 | Honest votes required to advance stages. |
| `VIEW_CHANGE_TIMEOUT_SEC` | 30 | Time before view change is triggered. |
| `ROUND_TTL_SEC` | 120 | Time before an idle round is evicted. |
| `MAX_SEQUENCE_GAP` | 100 | Max sequence ahead of local. |
| `MAX_MSG_HISTORY_PER_SENDER` | 10000 | Bounded history per sender. |
| `WINDOW_SEC` (computed) | `PBF * MAX` | Sliding window for rate calculations. |

### 14.4 Heartbeat Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Heartbeat interval | 2 seconds | Time between heartbeat ticks. |
| Discovery beacon interval | 5 seconds | Time between DISCOVERY broadcasts. |
| Telemetry gossip interval | 2 seconds (same as heartbeat) | Time between TELEMETRY broadcasts. |
| Eviction check interval | 30 seconds | Time between `evict_stale_rounds()` calls. |

### 14.5 Sandbox Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Bridge UID | 65534 (nobody) | UID for the sandboxed child. |
| Bridge GID | 65534 (nogroup) | GID for the sandboxed child. |
| chroot dir | `/var/empty` | Filesystem root for the child. |
| Log path | `/tmp/telemetry_bridge.log` | Log file inside the chroot. |
| Syscall whitelist | 65 syscalls | See TelemetryBridge section. |

### 14.6 IPC Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| Socket path | `/tmp/neuro_mesh_{id}.sock` | Per-node Unix domain socket. |
| Token (env) | `NEURO_TOKEN` | Shared secret for auth. |
| Rate limit | 10 commands/sec/UID | Per-UID rate limit. |
| Max clients | 5 concurrent | Max simultaneous IPC clients. |

### 14.7 Network Ports

| Port | Protocol | Default | Configurable |
|------|----------|---------|--------------|
| 9998 | UDP | Discovery beacon | Yes (compile-time) |
| 9999 | UDP | PBFT consensus | Yes (compile-time) |
| 10000 | TCP | PEX (peer exchange) | Yes (compile-time) |
| 10500 | TCP | mTLS (secure channel) | Yes (compile-time) |
| 9000-9044 | TCP | WebSocket (dashboard) | Yes (`NEURO_WS_PORT`) |

### 14.8 Recommended Production Values

```bash
NEURO_TOKEN=<32-byte-base64-secret>
NEURO_WS_PORT=<unique-per-node>
NEURO_PEERS=peer1:9999,peer2:9999,peer3:9999,peer4:9999
NEURO_XDP_IFACE=eth0
NEURO_PBF=20       # higher for production
NEURO_PBFT_MAX=10  # higher for production
```

### 14.9 Configuration Risk Matrix

| Misconfiguration | Risk | Mitigation |
|------------------|------|------------|
| Empty `NEURO_TOKEN` | Local privilege escalation | Refuse to start in production mode. |
| `NEURO_WS_PORT` conflict | Dashboard unavailable | Pre-check via `ss -tlnp`. |
| `NEURO_PEERS` with wrong IPs | Slow mesh formation | Discovery beacons will eventually find peers. |
| `NEURO_XDP_IFACE` on wrong interface | XDP not enforced | Logged clearly; userspace enforcement continues. |
| High `NEURO_PBF`/`NEURO_PBFT_MAX` | Memory growth | 120s TTL bounds the worst case. |
| Low `NEURO_PBF`/`NEURO_PBFT_MAX` | Consensus thrashing | Rate limiter backs off. |

---

## 15. Build System

### 15.1 Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| `clang++` | 18+ | C++20 compiler (also C++17 fallback via `-std=c++17`) |
| `clang` | 18+ | C compiler for eBPF programs |
| `bpftool` | 6.x | eBPF skeleton generation |
| `make` | GNU Make | Build orchestration |
| `ar`, `ld` | binutils | Static linking (for tests) |

### 15.2 Build Flags

**`CXXFLAGS_BASE`** (always applied):
- `-std=c++20`
- `-Wall -Wextra -Wpedantic -Wshadow -Werror`
- `-g` (debug symbols, kept in release)
- `-fno-omit-frame-pointer`

**Release mode** (`make`):
- `-O3 -DNDEBUG`

**Debug mode** (`make DEBUG=1`):
- `-O0 -DDEBUG`

**Sanitize mode** (`make SANITIZE=1`):
- `-O1 -fsanitize=address,undefined`

**Thread mode** (`make THREAD=1`):
- `-O1 -fsanitize=thread`

**Coverage mode** (`make COVERAGE=1`):
- `-O0 --coverage`

**Linter mode** (`make lint`):
- `clang-tidy` with project config.

### 15.3 Build Process

```
make [TARGET] [DEBUG=1] [SANITIZE=1] [THREAD=1] [COVERAGE=1] [PREFIX=/usr/local]
```

**Targets:**

| Target | Effect |
|--------|--------|
| `make` (or `make all`) | Build `bin/neuro_agent` |
| `make bin/inject_event` | Build the IPC inject tool |
| `make bin/test_crypto` | Build the crypto regression test |
| `make bin/register_attacker` | Build the TOFU key enrollment tool |
| `make tools` | Build all CLI tools |
| `make test` | Build + run unit tests |
| `make inst PREFIX=/opt/neuro-mesh` | Install to `$PREFIX/{bin,share,lib}` |
| `make lint` | Run clang-tidy on all sources |
| `make clean` | Remove `obj/`, `bin/`, generated skeletons |
| `make distclean` | Remove everything including `obj/sensor.skel.h` |

### 15.4 Compilation Flow

```
1. Compile uSockets C files
   third_party/uWebSockets/uSockets/src/*.c
   -> obj/usockets/*.o

2. Compile agent C++ files
   main.cpp, cell/*.cpp, consensus/*.cpp, crypto/*.cpp,
   enforcer/*.cpp, net/*.cpp, telemetry/*.cpp, attacks/*.cpp
   -> obj/*.o

3. Compile eBPF program
   kernel/sensor.bpf.c -> obj/sensor.bpf.o
   (with -target bpf -D__TARGET_ARCH_x86)

4. Generate eBPF skeleton
   bpftool gen skeleton obj/sensor.bpf.o -> kernel/sensor.skel.h

5. Compile NodeAgent.o (depends on sensor.skel.h)
   cell/NodeAgent.cpp -> obj/cell/NodeAgent.o

6. Link
   obj/main.o obj/cell/*.o obj/consensus/*.o ... -lbpf -lelf -lz
   -lssl -lcrypto -lpthread -lseccomp -lonnxruntime
   -> bin/neuro_agent
```

### 15.5 Packaging Flow

`make inst PREFIX=/opt/neuro-mesh` produces:
```
/opt/neuro-mesh/
  bin/
    neuro_agent
    inject_event
    test_crypto
    register_attacker
  share/neuro-mesh/
    kernel/sensor.bpf.c
    dashboard/  (full dashboard tree)
  lib/             (empty; static link only)
  etc/             (empty; config is env-based)
```

### 15.6 Build Dependencies

**System packages (Debian/Ubuntu):**
```
clang-18 libbpf-dev libelf-dev zlib1g-dev
libssl-dev bpftool nlohmann-json3-dev
libseccomp-dev nftables iproute2
libonnxruntime-dev
```

**Vendored (third_party/):**
- `uWebSockets/` - HTTP + WebSocket framework.

### 15.7 Cross-Compilation

Not currently supported. The eBPF object is `target bpf`, which is
architecture-independent but the eBPF loader code in libbpf is
architecture-specific (compiled into the agent binary). To support
a new architecture:

1. Add `__TARGET_ARCH_{arm64,riscv64,...}` to `kernel/sensor.bpf.c`.
2. Define the corresponding `pt_regs` struct.
3. Rebuild; libbpf will load the right skeleton.

### 15.8 Continuous Integration

The repository includes a CI workflow at
`.github/workflows/ci.yml` (referenced in README) that:

1. Builds with `make clean && make` on Ubuntu latest.
2. Runs `./bin/test_crypto`.
3. Runs lint with `make lint`.
4. Reports results as a status badge.

---

## 16. Deployment Guide

### 16.1 Local Deployment (Single Host)

For development, run multiple nodes on one host using different
node IDs and different WS ports:

```bash
# Build
make clean && make

# Launch 5 nodes in the background
for node in ALPHA BRAVO CHARLIE DELTA ECHO; do
    ./bin/neuro_agent $node > /tmp/agent_$node.log 2>&1 &
done

# Watch the dashboard
python3 -m http.server 8080 --directory dashboard/
# open http://localhost:8080
```

Each node uses the default ports (WS: 9000-9040, UDP: 9998-9999,
TCP: 10000, mTLS: 10500). All nodes on localhost share the same
ports, so the netns demo (Section 16.2) is required for proper
isolation testing.

### 16.2 Network Namespace Demo (Recommended)

The `tools/setup_demo_net.sh` script creates 5 Linux network
namespaces connected via a bridge. This is the recommended way
to test multi-node behavior on a single host.

```bash
sudo ./tools/setup_demo_net.sh
python3 orchestration/mesh_manager.py
sleep 30
./bin/inject_event --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL
```

The script:
1. Creates a bridge `br-neuro`.
2. Creates 5 netns: `ALPHA`, `BRAVO`, `CHARLIE`, `DELTA`, `ECHO`.
3. Adds veth pairs (`v-{ns}` and `vp-{ns}`) to each netns.
4. Assigns IPs from `192.168.50.0/24`.
5. Adds broadcast routes (required for UDP 255.255.255.255).
6. Enables IP forwarding and broadcast forwarding.
7. Tears down everything on `tools/teardown_demo_net.sh`.

**veth name length constraint:** Linux `IFNAMSIZ=16` (15 + null).
Names like `veth-CHARLIE-peer` are 16 chars and FAIL with
`Numerical result out of range`. The script uses `v-{id}` and
`vp-{id}` (7-8 chars) instead.

### 16.3 Container Deployment (Docker Compose)

```bash
docker compose -f docker-compose.yml build --no-cache
docker compose -f docker-compose.yml up -d
```

The `docker-compose.yml` defines 5 services (one per node) on
the same `neuro-mesh` network. Each service:

- Mounts the agent binary.
- Exposes a unique WebSocket port.
- Sets `NEURO_TOKEN` for IPC auth.
- Sets `NEURO_PEERS` to the other 4 nodes.

The dashboard is exposed on `http://localhost:8080` via the
included `ws_proxy.py` (a stateless WS bridge that connects to
whichever node is healthy).

### 16.4 Production Deployment (Multi-Host)

For a real multi-host cluster:

1. **Provision each host with the same image** (Debian 12+ recommended).
2. **Open firewall ports**:
   - UDP 9998-9999 (discovery + PBFT).
   - TCP 10000, 10500 (PEX + mTLS).
3. **Set `NEURO_TOKEN`** to a strong shared secret (use Vault or
   similar; never commit it).
4. **Set `NEURO_PEERS`** to the other nodes' IPs.
5. **Run as root** (required for eBPF, nftables, process suspension).
6. **Enable systemd unit** for restart-on-crash.
7. **Monitor** the WebSocket port for liveness.

### 16.5 Capacity Planning

| N | PBFT message complexity | Recommended CPU | Recommended RAM |
|---|-------------------------|------------------|------------------|
| 5 | 25 messages/round | 2 vCPU | 512 MB |
| 10 | 100 messages/round | 4 vCPU | 1 GB |
| 25 | 625 messages/round | 8 vCPU | 2 GB |
| 100 | 10000 messages/round | not recommended | not recommended |

For N > 25, consider hierarchical consensus (clusters of 5-10 nodes
with one aggregator per cluster).

### 16.6 Pre-Deployment Checklist

- [ ] All 5 (or N) nodes have the same `neuro_agent` binary.
- [ ] All nodes have the same `NEURO_TOKEN` env var.
- [ ] All nodes can reach each other on UDP 9998-9999 and TCP 10000, 10500.
- [ ] All nodes have `nft` or `iptables` installed.
- [ ] All nodes have `bpftool`, `libbpf`, `libelf`, `libseccomp` installed.
- [ ] All nodes have the `isolation_forest.onnx` model file.
- [ ] The dashboard can reach all nodes' WS ports (9000-9040).
- [ ] `NEURO_XDP_IFACE` is set to a real network interface.
- [ ] The OS user has permission to run as root (eBPF + nftables).

### 16.7 Post-Deployment Verification

```bash
# 1. All nodes should be in OPERATIONAL state
for h in host1 host2 host3 host4 host5; do
    curl http://$h:9000/health  # or check logs
done

# 2. Inject a test event
./bin/inject_event --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL

# 3. Verify all 4 other nodes applied the isolation
for h in host1 host2 host4 host5; do
    ssh $h "nft list chain inet neuro_chain input | grep -c drop"
done
# All should report >= 1

# 4. Verify the dashboard shows the mesh
curl -s http://host1:9000/ | grep -q "mesh" && echo OK
```

### 16.8 Upgrade Procedure

Neuro-Mesh does not support in-place upgrades. To upgrade:

1. Drain traffic from the cluster (operator decision).
2. Stop all 5 nodes.
3. Replace the binary.
4. Restart all 5 nodes.
5. Re-verify with the test event injection.

There is no rolling upgrade; the system is small enough that
drain-and-replace is fast.

### 16.9 Rollback Procedure

The persistent state (keys, certs, journal) is forward-compatible.
A rollback to an older binary is safe as long as the wire formats
have not changed. The major version bump in the V3 discovery
format is detected and downgraded gracefully to V2.

---

## 17. Operational Guide

### 17.1 Health Checks

**Process liveness:** systemd unit or process supervisor checks
that `neuro_agent` is running.

**WebSocket reachability:** poll `ws://node:9000/`; expect HTTP 101
upgrade response within 100ms.

**Peer count:** every node exports `active_peers` metric. Expected:
`N-1` (the node cannot count itself).

**PBFT progress:** `pbft_rounds_executed` should increase over
time. A stall indicates a stuck consensus.

**Telemetry queue:** `telemetry_queue_drops` should be 0 in normal
operation. Non-zero indicates a slow consumers or kernel backpressure.

### 17.2 Monitoring Integration

The agent exposes three integration points:

1. **WebSocket** (`ws://node:{port}/`): real-time JSON events.
   Suitable for in-cluster dashboards.

2. **JSON file** (`web/mesh_status.json`): polling-friendly snapshot.
   Suitable for external monitors (Prometheus, Datadog).

3. **Audit UDP**: structured log line per event. Suitable for
   log aggregators (Splunk, ELK).

**Prometheus integration example:**

```yaml
scrape_configs:
  - job_name: 'neuro_mesh'
    static_configs:
      - targets: ['node1:9000', 'node2:9000', ...]
    metrics_path: '/metrics'  # served by TelemetryExporter
```

### 17.3 Common Issues and Resolutions

| Symptom | Likely cause | Resolution |
|---------|--------------|------------|
| "eBPF sensor failed: ... unprivileged_bpf_disabled=2" | Kernel BPF lockdown | Run as root or use `--cap-add=CAP_BPF,CAP_PERFMON` or `--privileged` |
| "TelemetryBridge child spawned" then exits immediately | chroot or setresuid failed | Check `/var/empty` exists; run as root |
| "Failed to open/load eBPF skeleton" | libbpf version mismatch | Match `libbpf-dev` to kernel version |
| Dashboard shows "Disconnected" | WS port blocked or wrong port | Check firewall; verify `NEURO_WS_PORT` |
| "Certificate verify failed" | Cert pinning failed | Restart all nodes to refresh trust store |
| PBFT rounds stall at PRE_PREPARE | f+1 nodes missing | Check `active_peers` metric |
| Memory grows unbounded | PBFT rounds not evicting | Check for clock skew; verify `ROUND_TTL_SEC` |
| High CPU on idle | ONNX inference in tight loop | Verify `decay()` is being called |
| iptables/nftables rules accumulate | `reset_enforcement()` not called | Operator must issue `CMD:RESET` |

### 17.4 Diagnostics

**View live logs:**
```bash
tail -f /tmp/agent_ALPHA.log | grep -E "\[PBFT\]|\[ENFORCER\]|\[TLS\]"
```

**Inspect current state:**
```bash
./bin/inject_event --node ALPHA --target ALPHA --cmd QUERY
```

**Dump peer list:**
```bash
# IPC socket-based query (if implemented)
echo "CMD:QUERY_PEERS" | socat - UNIX-CONNECT:/tmp/neuro_mesh_ALPHA.sock
```

**Check enforcement rules:**
```bash
ssh ALPHA "nft list chain inet neuro_chain input"
```

**Check XDP program:**
```bash
ssh ALPHA "ip link show eth0 | grep xdp"
```

**Check BPF maps:**
```bash
ssh ALPHA "bpftool map show | grep neuro"
```

### 17.5 Log Interpretation

**Boot sequence (success):**
```
[BOOT] Neuro-Mesh V9.0 Node: ALPHA
[INIT] PolicyEnforcer: Enforcement backends probed. Available: iptables
[ENFORCER] Safe-listed node: ALPHA
[BOOT] TelemetryBridge child spawned (pid=N). WebSocket on :9000.
[TELEMETRY_BRIDGE] Child spawned (pid=N), starting sandbox sequence...
[SANDBOX] PR_SET_NO_NEW_PRIVS applied.
[TLS] Cert fingerprint: abc123...
[DEFENSE] Elite PBFT initialized with equivocation detection and timing obfuscation.
[TLS] Transport layer ready. Cert/key stored for ALPHA.
[AI] ONNX model loaded: isolation_forest.onnx (threshold=-0.05, outputs=2, score_idx=1)
[BOOT] ONNX InferenceEngine: OPERATIONAL
[EBPF] Sensor probes attached - execve/sendto/connect tracepoints live.
[TLS] Acceptor listening on port 10500
[DISCOVERY] Beaconing every 5s on UDP:9998 (TCP PEX port 10000)
[NETWORK] Broadcasted signed identity to local subnet.
[BOOT] Heartbeat pulse started (2s interval).
[BOOT] System fully operational. Awaiting P2P telemetry...
[IPC] Listening for commands on /tmp/neuro_mesh_ALPHA.sock
```

**Boot sequence (eBPF failure but otherwise healthy):**
```
...
[BOOT] ONNX InferenceEngine: OPERATIONAL
libbpf: Failed to bump RLIMIT_MEMLOCK (err = -1), you might need to do it explicitly!
libbpf: Error in bpf_object__probe_loading():Operation not permitted(1).
libbpf: failed to load object 'sensor_bpf'
[BOOT] eBPF sensor failed: Failed to open/load eBPF skeleton - kernel has
       unprivileged_bpf_disabled=2 and we are not root. Run as root, grant
       CAP_BPF+CAP_PERFMON, or use --privileged in Docker. Falling back to
       /proc/net/dev entropy.
...
[BOOT] System fully operational. Awaiting P2P telemetry...
```

**PBFT round (success):**
```
[PBFT] Initiating consensus round N: target=ALPHA evidence=entropy_spike
[PBFT] PREPARE broadcast: 1/3 votes
[PBFT] PREPARE broadcast: 2/3 votes
[PBFT] PREPARE broadcast: 3/3 votes - advancing to COMMIT
[PBFT] COMMIT broadcast: 1/3 votes
[PBFT] COMMIT broadcast: 2/3 votes
[PBFT] COMMIT broadcast: 3/3 votes - advancing to EXECUTED
[ENFORCER] Final Quorum Reached! Target ALPHA - executing MitigationEngine response.
[ENFORCER] Zero-Trust Rule Applied: Dropping all traffic from 192.168.50.2 [nftables]
[ENFORCER] Rule count: 1
```

**PBFT round (failure, equivocation):**
```
[PBFT] Equivocation detected: BRAVO sent two conflicting PREPARE messages for round N
[PBFT] Trust score for BRAVO decreased: 100 -> 80
[SECURITY] Possible Byzantine behavior from BRAVO; flagged for review
```

### 17.6 Performance Tuning

**For high event rate (1M+ events/sec):**
- Increase ring buffer size (currently 256KB):
  change `max_entries` in `sensor.bpf.c`.
- Increase telemetry queue size (currently 5000):
  change `m_max_size` in `NodeAgent.hpp`.
- Use batch ONNX inference (not yet implemented; future work).

**For low latency (<10ms PBFT round):**
- Reduce heartbeat interval from 2s to 200ms.
- Reduce view-change timeout from 30s to 5s.
- Use unicast UDP instead of broadcast (already done in real
  deployments).

**For high peer count (N > 25):**
- Use hierarchical consensus (clusters of 5-10).
- Consider HotStuff (linear message complexity) over PBFT.

---

## 18. Security Review Notes

This section is for security auditors. It is deliberately explicit
about what the system does and does not protect against.

### 18.1 Trust Assumptions

The system assumes:

1. The kernel is trusted. A kernel-level rootkit can defeat
   the entire system. The eBPF verifier provides some protection,
   but a malicious kernel can simply ignore eBPF programs.
2. The OpenSSL library is trusted. A backdoored OpenSSL
   breaks signatures and TLS. Use the system package manager's
   OpenSSL or compile from official source.
3. The hardware is trusted. Side-channel attacks (Spectre,
   Rowhammer, etc.) are out of scope.
4. The local filesystem is trusted for state. Keys and certs
   in `~/.neuro_mesh/` are protected only by file permissions.
   An attacker with read access to that directory can impersonate
   the node.
5. DNS is not used. All peers are identified by node_id + IP.
   There is no DNS attack surface.
6. The build toolchain is trusted. A backdoored compiler or
   bpftool can insert backdoors.

### 18.2 Security Boundaries

- Kernel to userspace: ring buffer is the only channel;
  userspace cannot mutate kernel state without CAP_BPF.
- Parent to TelemetryBridge child: pipe only; no shared memory;
  child has chroot + seccomp.
- Parent to iptables/nftables children: argv-as-`vector<string>`;
  no shell; one-shot, no persistent state.
- Node to network: all PBFT messages signed; all TCP mTLS.
- User to IPC socket: shared-secret token + UID rate limit +
  `SO_PEERCRED` validation.

### 18.3 Areas Requiring Special Care

1. Key persistence (`~/.neuro_mesh/keys/{id}.key`).
   - The file is mode 0600 owned by the agent's user.
   - If the agent runs as root, the key is root-owned.
   - Backup procedures MUST include the key directory; without
     it, the node loses its identity.

2. Trust store (in-memory OpenSSL store).
   - Populated from V3 discovery beacons at runtime.
   - Not persisted; an attacker who steals the trust store gets
     nothing across restarts.
   - A compromised node can poison the trust store of any peer
     that connects to it via mTLS. Mitigated by V3 cert PEM
     binding to the Ed25519 identity key (the attacker would
     need both the cert and the identity key).

3. PBFT stage binding.
   - The signature binds `(stage || target || evidence || view || sequence)`.
   - A PREPARE signature cannot be replayed as COMMIT.
   - A COMMIT for view V cannot be replayed in view V+1.
   - This is the **strongest property** of the system; a code
     change that removes any of these bindings is a critical
     vulnerability.

4. eBPF verifier.
   - All eBPF programs must pass the in-kernel verifier.
   - A program that the verifier accepts is guaranteed not to
     crash the kernel.
   - A program that the verifier rejects fails at load time;
     no runtime risk.
   - A bug in the verifier (e.g., CVE-2021-3490) compromises
     this guarantee; the system is only as strong as the
     kernel's verifier.

5. Seccomp-BPF.
   - 65 syscalls whitelisted; default-kill on others.
   - A bug in libseccomp that fails to install a syscall could
     leave the child with full syscall access.
   - Mitigated by testing in CI (TODO: add a test that asserts
     the seccomp filter is active).

6. fork() + execv() in enforcer.
   - argv is `vector<string>`; no shell.
   - A bug that allows `c_str()` instead of `data()` could allow
     null-byte truncation. The codebase enforces `data()/size()`
     everywhere (ADR-002).

### 18.4 Known Risks

1. Sybil attacks. An attacker can spin up many nodes with
   many Ed25519 keys and overwhelm the consensus. Mitigated by
   N=5 hard cap in the current design; would require a PKI for
   larger deployments.

2. eBPF bypass. A rootkit can hide from eBPF probes by
   modifying syscall table or using direct hardware I/O.
   Mitigated by userspace `/proc/net/dev` entropy fallback,
   but detection quality degrades.

3. Replay at the application layer. A signed message can
   be replayed at the TCP layer if the application does not
   check for duplicates. The IPC and mTLS paths do check
   sequence numbers.

4. ML evasion. A sophisticated attacker can craft payloads
   that fool the ONNX model. Mitigated by PBFT (attacker must
   fool 2f+1 of N nodes, not just one).

5. Single-tenant assumption. The current design assumes all
   5 nodes are owned by the same operator. A multi-tenant
   deployment would need additional isolation.

6. No automatic recovery from a key compromise. If a node's
   Ed25519 key is stolen, the attacker can impersonate the node
   indefinitely. Operator must manually delete the key file and
   restart the node; this invalidates the identity, requiring
   re-TOFU with all peers.

7. View change deadlock in pathological cases. If `f+1`
   nodes simultaneously trigger view change, the protocol can
   take 2-3 view changes to stabilize. Mitigated by
   `VIEW_CHANGE_TIMEOUT_SEC=30`.

8. No rate limit on the IPC socket's token. Brute-forcing
   the token is theoretically possible; mitigated by the
   per-UID rate limit (10 cmd/sec) and the short token
   generation window.

9. WebSocket has no authentication. Any client that can
   reach the WS port can subscribe. Acceptable in LAN; not for
   public deployment.

10. Audit UDP is unauthenticated. A remote attacker can
    inject fake log lines. The audit log is for monitoring,
    not security-critical decisions.

### 18.5 Security Properties Summary

| Property | Guaranteed? | Mechanism |
|----------|-------------|-----------|
| Authentication | YES | Ed25519 signatures on all PBFT messages; TLS 1.3 mTLS. |
| Authorization | YES (additive only) | Safe list + PBFT consensus. |
| Confidentiality (in transit) | YES (PBFT over TLS) | TLS 1.3 for TCP. PBFT over UDP is plaintext. |
| Confidentiality (at rest) | NO | Telemetry is plaintext; keys are 0600. |
| Integrity (in transit) | YES | Ed25519 signatures + TCP checksums. |
| Integrity (at rest) | PARTIAL | Journal is append-only; not tamper-evident. |
| Non-repudiation | YES | Ed25519 signatures are non-repudiable. |
| Replay protection | YES | Signature binds (view, sequence, stage). |
| Forward secrecy (TLS) | YES | TLS 1.3 with X25519 / P-256. |
| Forward secrecy (PBFT) | NO | UDP is plaintext; no PFS at the consensus layer. |
| Availability (DoS) | PARTIAL | Rate limits on receiver side; no ingress filtering. |
| Accountability | YES | All messages signed; journal records all decisions. |
| Auditability | YES | Structured logs to UDP + journal. |

### 18.6 Recommendations for Auditors

1. Verify the signature binding in `consensus/PBFT.hpp::verify_message()`.
   The fields bound MUST include `(stage, target, evidence, view, sequence)`.
   Removal of any of these is a critical vulnerability.

2. Verify the safe list in `enforcer/PolicyEnforcer.cpp::isolate_node()`.
   The `is_safe()` check MUST be called before any backend action.

3. Verify the fork+execv pattern in
   `enforcer/PolicyEnforcer.cpp::fork_exec_wait()`. argv MUST
   be `vector<string>`; `system()` MUST NOT be used.

4. Verify the seccomp filter in
   `telemetry/TelemetryBridge.cpp::seccomp_filter_install()`.
   The default action MUST be `SECCOMP_RET_KILL_PROCESS`. The
   whitelist MUST NOT include `execve` after sandboxing.

5. Verify the key persistence in
   `crypto/KeyManager.cpp::load_or_generate()`. The file mode
   MUST be 0600. The write MUST be atomic (write-to-temp +
   rename).

6. Verify the trust store population in
   `net/TransportLayer.cpp::trust_peer_cert()`. The cert MUST
   be added only after V3 discovery verifies the signature
   over the cert PEM.

7. Verify the IPC token check in
   `main.cpp::ipc_handler()`. The check MUST be constant-time.
   Per-UID rate limit MUST be enforced.

8. Verify the PBFT vote count in
   `consensus/PBFT.hpp::on_message()`. The advance MUST require
   2f+1 distinct senders; not just 2f+1 messages (a single
   sender cannot count twice).

## 19. Contributor Guide

### 19.1 Coding Standards

**Compiler:** `clang++ -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror`.
The codebase must build cleanly with no warnings. A change that
introduces a warning is rejected at code review.

**Naming:**
- Types (classes, structs, enums): `PascalCase`.
- Functions: `snake_case`.
- Variables (local): `snake_case`.
- Member variables: `m_snake_case` prefix.
- Constants: `UPPER_SNAKE_CASE` or `kPascalCase`.
- Namespaces: `lowercase`.

**Headers:**
- All public APIs in `.hpp` files.
- All implementations in `.cpp` files.
- Header guards: `#pragma once`.
- Includes: project-relative, e.g. `#include "crypto/CryptoCore.hpp"`.
- Avoid deep include chains; prefer forward declarations.

**Error handling:**
- Hot path: use `Result<T, E>` (see common/Result.hpp).
- Initialization: throw exceptions (acceptable once per process).
- Never silently ignore errors; log and return failure.

**Threading:**
- `std::lock_guard<std::mutex>` for short critical sections.
- `std::unique_lock<std::mutex>` if condition variables are needed.
- `std::shared_mutex` for read-heavy access (PolicyEnforcer).
- No `std::recursive_mutex` (ever).
- Document the threading contract in class comments.

**Memory:**
- RAII everywhere. No raw `new`/`delete`.
- `std::unique_ptr` for ownership; `std::shared_ptr` only when
  truly shared.
- `UniqueFD` for file descriptors.

**Crypto:**
- Never use `c_str()` for binary data. Use `data.data()` / `data.size()`.
- Never roll your own crypto. Use OpenSSL EVP.
- Every signature MUST bind multiple fields (see ADR-002).

**eBPF:**
- All BPF programs MUST pass the in-kernel verifier.
- Use `bpf_probe_read_user` and `bpf_probe_read_kernel` for
  safe memory access; no raw dereferences.
- Bound all `bpf_ringbuf_reserve` sizes; check return value.

### 19.2 Architecture Principles

1. Zero-trust. No node is trusted; every message is verified.
2. Cryptographic binding. Signatures bind all relevant fields
   to prevent replay.
3. Defense in depth. Multiple layers (eBPF + userspace + seccomp
   + chroot + safe list).
4. Fail safely. When in doubt, log and continue with reduced
   functionality. Never crash silently.
5. Auditability. Every action produces a structured log line.
6. Operator-first. Errors include actionable remediation, not
   just "failed".

### 19.3 Safe Modification Practices

**Before changing the PBFT state machine:**
- Read ADR-001 and ADR-002.
- Run the test suite: `./bin/test_crypto`.
- Run the e2e test: netns demo + inject event.
- Manually verify by tailing logs during the test.

**Before changing the eBPF programs:**
- Verify the new program passes the verifier:
  `bpftool gen skeleton obj/sensor.bpf.o`.
- Test on a non-production host.
- Verify ring buffer size is appropriate.
- Verify the maps are correctly typed and sized.

**Before changing the sandbox:**
- Verify seccomp whitelist covers all syscalls used by uWebSockets.
- Test in Docker with `--privileged` and without.
- Verify the child process can complete a full request/response cycle.
- Verify the parent liveness check still works (passive EOF).

**Before changing the enforcer:**
- Verify `is_safe()` and `is_loopback()` checks are still in place.
- Verify `fork_exec_wait` is still used; no `system()` calls.
- Test with adversarial evidence_json (null bytes, command
  metacharacters, oversized strings).

**Before changing the crypto:**
- Verify the signature binding includes all relevant fields.
- Verify key persistence is atomic.
- Verify the trust store is populated only after V3 verification.
- Test with corrupted key files.

**Before changing the network code:**
- Verify wire format compatibility (V2 vs V3).
- Verify signature verification happens BEFORE any state mutation.
- Verify rate limits are in place.
- Test with packet loss simulation.

### 19.4 Testing Requirements

Every PR must include:

1. Unit test for the new behavior (or extension of an existing test).
2. Integration test if the change crosses a component boundary.
3. Documentation update if the public API changes.
4. ADR update if the design changes.

### 19.5 Review Process

1. Open a PR with a clear description.
2. Wait for CI to pass (build, lint, test).
3. Wait for 2 maintainer approvals.
4. Squash and merge with a Conventional Commits message.

### 19.6 Release Process

1. Update version in `main.cpp` (currently `V9.0`).
2. Update `CHANGELOG.md` (if present).
3. Tag the commit: `git tag v9.x.y`.
4. Build release artifacts: `make clean && make && make inst PREFIX=dist/v9.x.y`.
5. Publish artifacts to GitHub Releases.
6. Announce on the mailing list / Slack.

### 19.7 Deprecation Policy

- Deprecated APIs are marked `[[deprecated("message")]]`.
- A deprecated API is removed in the next major version bump.
- Major version bumps are rare (the current API has been stable
  since v8.0).

### 19.8 Communication

- **Issues**: GitHub Issues for bugs and feature requests.
- **Discussions**: GitHub Discussions for design questions.
- **Security**: private email (see README) for security issues.
- **Real-time**: project Slack (invite via maintainer).

---

## 20. File & Directory Reference

### 20.1 Top-Level Files

| File | Purpose | Lines |
|------|---------|-------|
| `main.cpp` | Entry point; composes all subsystems | 711 |
| `Makefile` | Build orchestration | 381 |
| `docker-compose.yml` | 5-node container orchestration | ~100 |
| `mesh_dashboard.sh` | tmux grid launcher | ~30 |
| `README.md` | User-facing documentation | 587 |
| `LICENSE` | MIT license | 21 |
| `PROJECT_DEEP_DOCUMENTATION.md` | This file | ~3500 |

### 20.2 kernel/

| File | Purpose | Lines |
|------|---------|-------|
| `sensor.bpf.c` | Main eBPF program: 4 kprobes + 1 XDP | 195 |
| `neuro_bpf.c` | (legacy) XDP filter | - |
| `vmlinux.h` | Kernel type headers (auto-generated by bpftool) | - |
| `sensor.skel.h` | Libbpf skeleton (auto-generated by bpftool) | 1114 |

### 20.3 cell/

| File | Purpose | Lines |
|------|---------|-------|
| `NodeAgent.hpp` | `NodeAgent`, `KernelEventData`, `TelemetryQueue` | 108 |
| `NodeAgent.cpp` | eBPF load, ring buffer drain, kprobe/XDP attach | 197 |
| `InferenceEngine.hpp` | `InferenceEngine` (ONNX wrapper) | 73 |
| `InferenceEngine.cpp` | Entropy + ONNX inference | 167 |

### 20.4 consensus/

| File | Purpose | Lines |
|------|---------|-------|
| `PBFT.hpp` | PBFT state machine, equivocation detection, timeout eviction | 761 |
| `MeshNode.hpp` | `MeshNode`, `Peer`, `P2PMessage` | 162 |
| `MeshNode.cpp` | UDP transport, V2/V3 discovery, PBFT broadcast, telemetry gossip | 1983 |
| `PeerManager.hpp` | `PeerManager`, peer state machine | 146 |
| `PeerManager.cpp` | Dual-path TOFU, IP resolution, eviction | 377 |

### 20.5 crypto/

| File | Purpose | Lines |
|------|---------|-------|
| `CryptoCore.hpp` | `IdentityCore` (Ed25519 wrapper) | 43 |
| `CryptoCore.cpp` | Ed25519 keygen, sign, verify (OpenSSL EVP) | 124 |
| `KeyManager.hpp` | `KeyManager` (persistent key storage) | 198 |
| `KeyManager.cpp` | Load/generate, atomic write, 0600 permissions | 949 |
| `CertificateAuthority.hpp` | `CertificateAuthority` (X.509 wrapper) | 159 |
| `CertificateAuthority.cpp` | Self-signed X.509v3 generation | 427 |
| `ProofChain.hpp` | `ProofChain` (hash-linked evidence chain) | 261 |

### 20.6 net/

| File | Purpose | Lines |
|------|---------|-------|
| `TransportLayer.hpp` | `TransportLayer`, `Connection` | 180 |
| `TransportLayer.cpp` | mTLS 1.3, cert pinning, TOFU enrollment | 667 |

### 20.7 enforcer/

| File | Purpose | Lines |
|------|---------|-------|
| `PolicyEnforcer.hpp` | `PolicyEnforcer`, `EnforcementBackend` enum | 121 |
| `PolicyEnforcer.cpp` | Multi-backend isolation, safe list, fork+execv | 782 |
| `MitigationEngine.hpp` | `MitigationEngine` (PBFT response orchestrator) | 42 |
| `MitigationEngine.cpp` | PBFT EXECUTED callback, telemetry emission | 297 |

### 20.8 telemetry/

| File | Purpose | Lines |
|------|---------|-------|
| `TelemetryBridge.hpp` | `TelemetryBridge`, `Config` | 73 |
| `TelemetryBridge.cpp` | Sandboxed WebSocket server, seccomp, chroot | 593 |
| `Observability.hpp` | `MetricsRegistry`, counter/gauge/histogram | 312 |
| `Observability.cpp` | Lock-free metrics, JSON snapshot | 840 |
| `AuditLogger.hpp` | `AuditLogger` (static UDP logger) | 22 |
| `AuditLogger.cpp` | UDP socket RAII, structured logs | 106 |
| `TelemetryExporter.hpp` | `TelemetryExporter` (POSIX-locked JSON) | 60 |

### 20.9 common/

| File | Purpose | Lines |
|------|---------|-------|
| `UniqueFD.hpp` | RAII file descriptor wrapper | 27 |
| `Result.hpp` | `Result<T, E>` Rust-style error type | 83 |
| `Base64.hpp` | Base64 encode/decode | 85 |
| `StateJournal.hpp` | Append-only log for crash recovery | 186 |

### 20.10 attacks/

| File | Purpose | Lines |
|------|---------|-------|
| `AttackSimulator.hpp` | `AttackSimulator` (adversarial load gen) | 241 |
| `AttackSimulator.cpp` | UDP flood, port scan, execve storm | 573 |

### 20.11 orchestration/

| File | Purpose |
|------|---------|
| `mesh_manager.py` | Process manager (Python) |
| `ws_proxy.py` | Stateless WebSocket bridge (Docker/WSL2) |
| `control_server.py` | Legacy centralized aggregator (deprecated) |
| `anomaly_classifier.py` | Legacy ML inference (deprecated) |

### 20.12 tools/

| File | Purpose |
|------|---------|
| `inject_event.cpp` | IPC command injection tool |
| `test_crypto.cpp` | Crypto regression suite |
| `attack_injector.cpp` | Adversarial UDP flood simulator |
| `register_attacker.cpp` | TOFU key enrollment tool |
| `traffic_generator.py` | Load generator |
| `benchmark_mesh.py` | Mesh-level benchmark |
| `setup_demo_net.sh` | Network namespace topology setup |
| `teardown_demo_net.sh` | Topology teardown |

### 20.13 dashboard/

| File | Purpose |
|------|---------|
| `index.html` | Main dashboard HTML |
| `app.js` | Dashboard logic (Canvas + WebSocket) |
| `style.css` | Dashboard styles |
| `dashboard_raw.html` | Single-file export for distribution |

### 20.14 docs/

| File | Purpose |
|------|---------|
| `adr/0001-pbft-consensus-over-udp.md` | ADR: PBFT over UDP |
| `adr/0002-ed25519-signature-binding-cross-stage-replay.md` | ADR: signature binding |
| `adr/0003-fork-exec-iptables-over-system.md` | ADR: fork+execv pattern |
| `adr/0004-dual-path-tofu-trust-model.md` | ADR: TOFU dual-path |
| `adr/0005-telemetrybridge-sandbox-architecture.md` | ADR: sandbox architecture |
| `benchmarks/2026-06-01-pbft-latency.md` | PBFT round-trip latency |
| `KNOWN_LIMITATIONS.md` | Known limitations and risks |
| `THREAT_MODEL.md` | Detailed threat model |
| `architecture.svg` | Architecture diagram |

### 20.15 third_party/

| File | Purpose |
|------|---------|
| `uWebSockets/` | HTTP + WebSocket framework (vendored) |

### 20.16 _archive_old/

46 archived files from earlier iterations. **Do not use for new
development.** Contains monolithic clients, ML model experiments,
standalone HTML dashboards, etc.

### 20.17 File Relationship Diagram

```
main.cpp
  |
  +-- cell/NodeAgent (eBPF + ring buffer)
  |     |
  |     +-- kernel/sensor.skel.h (generated)
  |     +-- common/UniqueFD
  |
  +-- cell/InferenceEngine (ONNX)
  |     |
  |     +-- onnxruntime_cxx_api
  |
  +-- consensus/MeshNode (UDP + PBFT)
  |     |
  |     +-- consensus/PBFT (state machine)
  |     |     |
  |     |     +-- crypto/CryptoCore (Ed25519)
  |     |
  |     +-- consensus/PeerManager
  |     |
  |     +-- net/TransportLayer (mTLS)
  |     |     |
  |     |     +-- crypto/CryptoCore
  |     |     +-- crypto/KeyManager
  |     |     +-- crypto/CertificateAuthority
  |     |
  |     +-- crypto/CryptoCore
  |     +-- common/Base64
  |
  +-- enforcer/PolicyEnforcer
  |     |
  |     +-- enforcer/MitigationEngine
  |     +-- consensus/PeerManager
  |     +-- common/UniqueFD
  |
  +-- telemetry/TelemetryBridge (sandboxed)
  |     |
  |     +-- common/UniqueFD
  |     +-- common/Result
  |     +-- uWebSockets
  |
  +-- telemetry/Observability (metrics)
  +-- telemetry/AuditLogger (UDP)
  +-- telemetry/TelemetryExporter (POSIX-locked JSON)
  |
  +-- common/StateJournal (crash recovery)
  +-- common/Result (error type)
  +-- common/UniqueFD (RAII fd)
```

The dependency graph is a DAG; no cycles.

---

## 21. Glossary

**ADR** — Architecture Decision Record. A short document capturing
a significant design decision, its context, and its consequences.

**Backend (enforcement)** — A network isolation mechanism (nftables,
iptables, eBPF blocklist, process suspension).

**BPF** — Berkeley Packet Filter. In Linux, this refers to the
extended BPF (eBPF) virtual machine that runs sandboxed programs
in the kernel without a kernel module.

**Byzantine fault** — A fault model where a component may behave
arbitrarily (lie, equivocate, omit, collude) as long as it does
not break the cryptographic assumptions (Ed25519, SHA-256).

**Cert pinning** — Binding a TLS cert to a peer's identity at
the application layer (rather than relying on a CA chain). In
Neuro-Mesh, the binding is via the Ed25519-signed V3 discovery
beacon.

**Chroot** — POSIX `chroot(2)` syscall that changes the apparent
filesystem root for a process. Used in the TelemetryBridge sandbox.

**Consensus** — Agreement among a set of nodes on a single value
or sequence of values. In Neuro-Mesh, the consensus algorithm
is a variant of PBFT (Castro-Liskov 1999).

**DROP rule** — A firewall rule that silently discards matching
packets. Used to isolate banned peers.

**eBPF** — Extended BPF. The Linux kernel's in-kernel virtual
machine for running sandboxed programs without a kernel module.

**Ed25519** — A modern elliptic-curve signature scheme (RFC 8032).
Fast, small signatures (64 bytes), small keys (32 bytes), strong
security. Used for all Neuro-Mesh signatures.

**Equivocation** — A Byzantine behavior where a node signs two
conflicting messages for the same logical event. Detected by
storing both signatures and comparing.

**Evidence** — A signed JSON payload describing a detected
anomaly. Carried in PBFT messages.

**Final Quorum** — The point in a PBFT round where 2f+1 honest
votes have been received for the EXECUTED stage, triggering
enforcement.

**Fork+execv** — The POSIX pattern of `fork()` followed by
`execv()` to run a child program with explicit argv. Avoids shell
injection because argv is `vector<string>`, not a shell string.

**Heartbeat** — A periodic tick of the main loop (default 2s)
that polls eBPF, runs inference, drives consensus, and flushes
telemetry.

**IPC socket** — Unix domain socket at `/tmp/neuro_mesh_{id}.sock`
for operator commands. Authenticated with a shared-secret token.

**Isolation** — Network-level blocking of a peer's traffic via
firewall rules. The mesh's primary mitigation response.

**kprobe** — A Linux kernel tracing mechanism that fires on
entry to a kernel function (e.g., `sys_execve`).

**Libbpf** — The C library for loading and managing eBPF
programs. Provides CO-RE (Compile Once, Run Everywhere) and
the skeleton API.

**MPSC** — Multi-Producer Single-Consumer. The concurrency
pattern used by `TelemetryQueue<T>`.

**mTLS** — Mutual TLS. Both client and server present X.509
certificates during the TLS handshake.

**Nftables** — The modern netfilter firewall in Linux.
Replaces iptables for new deployments.

**Node ID** — A short string (e.g., `ALPHA`) that uniquely
identifies a node in the mesh. Used as the DNS-less, IP-less
identifier.

**ONNX** — Open Neural Network Exchange. A format for ML
models. Neuro-Mesh uses an isolation forest model in this format.

**O_CLOEXEC** — A `open(2)` flag that closes the FD on
`execve`. Used to prevent FD leakage into child processes.

**PBFT** — Practical Byzantine Fault Tolerance. The consensus
algorithm at the heart of Neuro-Mesh. Castro and Liskov, 1999.

**PEM** — Privacy-Enhanced Mail. A base64-encoded format for
X.509 certs and Ed25519 public keys.

**PEX** — Peer Exchange. The TCP port (10000) used during mesh
formation to exchange peer lists.

**Pipeline** — The end-to-end path from kernel eBPF event to
firewall DROP. Includes ring buffer, telemetry queue, ONNX
inference, PBFT, and enforcer.

**Proposer** — The node that initiates a PBFT round. Determined
by `sequence % total_nodes`.

**Result<T, E>** — A Rust-style error type. Either a value
or an error, never both.

**Ring buffer** — A lock-free, fixed-size, single-producer
single-consumer queue. Used in eBPF for kernel-to-userspace
event delivery.

**Safe list** — A local-only set of node IDs that may never
be isolated, even by PBFT consensus. Additive only.

**Sandbox** — A collection of mechanisms (chroot, seccomp-BPF,
setresuid) that limit what a process can do.

**Seccomp-BPF** — Secure Computing mode using BPF filters.
Used in the TelemetryBridge child to whitelist 65 syscalls.

**Sequence number** — A monotonic counter in PBFT messages
that prevents replay.

**Signature binding** — The property that a signature covers
multiple fields, preventing replay across stages, views, or
sequences.

**Stage (PBFT)** — One of `IDLE`, `PRE_PREPARE`, `PREPARE`,
`COMMIT`, `EXECUTED`, `BAN_PEER`. The state machine transitions
through these in order.

**Telemetry** — Structured JSON describing a node's state
(metrics, peer list, current consensus view). Broadcast to
all peers and to the dashboard.

**Telemetry bridge** — The sandboxed child process that bridges
the agent's internal telemetry to WebSocket subscribers
(browsers).

**TLS 1.3** — The latest version of TLS. Provides forward
secrecy by default and uses modern cipher suites.

**TOFU** — Trust On First Use. The first encounter with a
peer establishes trust (with a cryptographic check). The
trust is preserved across reconnections.

**View** — A counter in PBFT that increments on view change
(when a round stalls).

**View change** — The PBFT protocol for recovering from a
stalled round. Triggered by `VIEW_CHANGE_TIMEOUT_SEC=30`.

**Wire format** — The byte-level format of a message. The
V3 discovery wire format is
`DISCOVERY|id|tcp|tls|ts|b64pub|tls_fpr|b64cert|sig`.

**XDP** — eXpress Data Path. A Linux kernel hook for packet
processing at the earliest point in the network stack. Used
for high-performance DROP rules.

**Zero-trust** — The security philosophy that no node is
trusted by default; every interaction is cryptographically
verified.

---

## Appendix A: ADR Summaries

### ADR-001: PBFT Consensus over UDP

**Decision:** Use a simplified PBFT variant over UDP broadcast on
localhost (port 9999) for the 5-node default deployment.

**Context:** TCP adds handshake overhead and head-of-line blocking.
For small message sizes (consensus votes) and a known small peer
set, UDP is sufficient. Broadcast simplifies mesh formation.

**Consequences:**
- (+) Lower latency than TCP.
- (+) No connection state.
- (-) No delivery guarantees; must rely on view change timeout.
- (-) Hard cap on message size (~65 KB).

### ADR-002: Ed25519 Signature Binding Across Stages

**Decision:** PBFT message signatures bind `(stage, target,
evidence_hash, view, sequence)`.

**Context:** Without binding, a PREPARE signature could be
replayed as a COMMIT, breaking the safety property.

**Consequences:**
- (+) Cross-stage replay is cryptographically impossible.
- (+) Cross-view replay is cryptographically impossible.
- (-) Slightly larger signatures (already 64 bytes; no change).

### ADR-003: fork+execv() for iptables/nftables over system()

**Decision:** Use `fork()` + `execv()` with `vector<string>`
argv, never `system()`.

**Context:** `system()` invokes `/bin/sh -c <string>`, which
is vulnerable to shell metacharacter injection. The
evidence_json (carried in PBFT messages) is attacker-controlled;
a single `;` could compromise the host.

**Consequences:**
- (+) No shell metacharacter risk.
- (+) Explicit argv visibility in code review.
- (-) More verbose than `system()`.

### ADR-004: Dual-Path TOFU Trust Model

**Decision:** A peer is trusted only after both UDP discovery
and TCP PEX confirm matching identity. V3 discovery includes
the full X.509 cert PEM, signed by the Ed25519 identity key.

**Context:** Single-path TOFU is vulnerable to a MITM that
controls one channel. Dual-path requires the attacker to
control both channels.

**Consequences:**
- (+) Stronger TOFU than single-path.
- (+) Cert PEM is cryptographically pinned.
- (-) Larger UDP packets (~620B cert PEM).
- (-) V2 compatibility requires graceful degradation.

### ADR-005: TelemetryBridge Sandbox Architecture

**Decision:** The dashboard-facing WebSocket server runs in a
forked child with chroot + setresuid + 65-syscall seccomp-BPF
default-kill. The parent writes JSON to a pipe; the child
reads and broadcasts.

**Context:** The dashboard is a browser; an XSS in the
dashboard (or a malicious operator on the LAN) could
otherwise gain access to the agent's privileges.

**Consequences:**
- (+) Defense in depth: chroot, setresuid, seccomp.
- (+) Crashes in the bridge don't affect the agent.
- (-) Debugging is harder (the child is sandboxed).

---

## Appendix B: Build & Run Quick Reference

```bash
# Build
make clean && make

# Run a single node
./bin/neuro_agent ALPHA

# Run the netns demo
sudo ./tools/setup_demo_net.sh
python3 orchestration/mesh_manager.py

# Inject a test event
./bin/inject_event --node CHARLIE --target ALPHA \
  --event entropy_spike --verdict CRITICAL

# Run the crypto test suite
./bin/test_crypto

# Open the dashboard
python3 -m http.server 8080 --directory dashboard/
# open http://localhost:8080

# Issue an IPC command
echo "CMD:RESET" | NEURO_TOKEN=secret socat - UNIX-CONNECT:/tmp/neuro_mesh_ALPHA.sock

# View logs
tail -f /tmp/agent_*.log | grep -E "\[PBFT\]|\[ENFORCER\]"

# Run an attack simulation
./bin/attack_injector --target 192.168.50.2 --duration 30 --threads 16

# Run a benchmark
python3 tools/benchmark_mesh.py --nodes 5 --duration 60
```

---

## Appendix C: Wire Format Reference

### V3 Discovery Beacon (UDP, 9 tokens)
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<unix_ts>|<b64pub>|<tls_fpr>|<b64cert>|<b64sig>
```
Signature binds: `(id || tcp_port || tls_port || unix_ts || tls_fpr || b64cert)`

### V2 Discovery Beacon (UDP, 8 tokens, legacy)
```
DISCOVERY|<id>|<tcp_port>|<tls_port>|<unix_ts>|<b64pub>|<tls_fpr>|<b64sig>
```
Signature binds: `(id || tcp_port || tls_port || unix_ts || tls_fpr)`

### PBFT Message (UDP)
```
PBFT|<stage>|<sender_id>|<target_id>|<view>|<sequence>|<b64evidence>|<b64sig>
```
Signature binds: `(stage || sender_id || target_id || view || sequence || sha256(evidence))`

### Telemetry Gossip (UDP)
```
TELEMETRY|<node_id>|<b64json>|<b64sig>
```
Signature binds: `(node_id || b64json)`

### BAN_PEER Gossip (UDP)
```
BAN_PEER|<target_id>|<b64sig>
```
Signature binds: `(target_id)`

### IPC Command (Unix domain socket)
```
AUTH|<token>\n
CMD:INJECT|<target_id>|<evidence_json>\n
CMD:ISOLATE|<target_id>\n
CMD:RESET\n
CMD:SHUTDOWN\n
```

### IPC Response
```
ACK:INJECT\n
ACK:ISOLATE\n
ACK:RESET\n
ERR:<message>\n
```

---

*End of document.*

*Maintained by the Neuro-Mesh contributors.*
*For corrections or additions, open a PR against `PROJECT_DEEP_DOCUMENTATION.md`.*
