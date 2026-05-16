# Neuro-Mesh Architecture

## System Context

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Environment                      │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│  │  Node α  │◄──►│  Node β  │◄──►│  Node γ  │               │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘               │
│       │               │               │                      │
│       └───────────────┼───────────────┘                      │
│                       │                                      │
│                 ┌─────┴──────┐                               │
│                 │   Node δ   │                               │
│                 └────────────┘                               │
│                                                              │
│  Each node:                                                  │
│  • Runs eBPF kernel probes                                   │
│  • Participates in PBFT consensus                            │
│  • Enforces network isolation policies                       │
│  • Serves telemetry via WebSocket                            │
└─────────────────────────────────────────────────────────────┘
```

## Container Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Neuro-Mesh Node                        │
│                                                               │
│  ┌─────────────────┐    ┌─────────────────────────────────┐  │
│  │   Cell Layer    │    │       Consensus Layer           │  │
│  │                 │    │                                 │  │
│  │ ┌─────────────┐ │    │ ┌───────────┐ ┌───────────────┐ │  │
│  │ │ NodeAgent   │ │    │ │ MeshNode  │ │ PBFTConsensus │ │  │
│  │ │ (eBPF +     │ │    │ │ (P2P UDP  │ │ (BFT state    │ │  │
│  │ │  ring buf)  │ │    │ │  + TLS)   │ │  machine)     │ │  │
│  │ └──────┬──────┘ │    │ └─────┬─────┘ └───────┬───────┘ │  │
│  │        │        │    │       │               │         │  │
│  │ ┌──────┴──────┐ │    │       └───────┬───────┘         │  │
│  │ │InferenceEng │ │    │               │                 │  │
│  │ │(ONNX +      │ │    │      ┌────────┴────────┐        │  │
│  │ │ entropy)    │ │    │      │ TelemetryGossip │        │  │
│  │ └──────┬──────┘ │    │      └────────┬────────┘        │  │
│  │        │        │    │               │                 │  │
│  └────────┼────────┘    └───────────────┼─────────────────┘  │
│           │                             │                     │
│           ▼                             ▼                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                  Enforcement Layer                       │  │
│  │                                                          │  │
│  │  ┌──────────────────┐    ┌────────────────────────────┐  │  │
│  │  │ MitigationEngine │───►│    PolicyEnforcer          │  │  │
│  │  │ (JSON parser,    │    │ (iptables/nftables/eBPF    │  │  │
│  │  │  action dispatch)│    │  cascade, SIGSTOP)         │  │  │
│  │  └──────────────────┘    └────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   Telemetry Layer                         │  │
│  │                                                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │  │
│  │  │TelemetryBridge│  │ AuditLogger  │  │ Observability  │  │  │
│  │  │(WebSocket +   │  │ (UDP JSON    │  │ (metrics,      │  │  │
│  │  │ seccomp sandbox│  │  emitter)    │  │  tracing)      │  │  │
│  │  └──────────────┘  └──────────────┘  └────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Event Detection

```
eBPF tracepoint (kernel)
    │
    ▼
Ring buffer (kernel → userspace)
    │
    ▼
NodeAgent::poll_ring_buffer() (continuous drain loop)
    │
    ▼
TelemetryQueue (MPSC, bounded, drops oldest on overflow)
    │
    ▼
InferenceEngine::analyze() (ONNX IsolationForest)
    │
    ├── score >= threshold → normal (decay applied)
    └── score < threshold  → anomaly → initiate_consensus()
```

### 2. PBFT Consensus

```
Node detects anomaly
    │
    ▼
broadcast_pbft_stage("PRE_PREPARE", target, evidence)
    │
    ├── Sign: Ed25519(stage + target + evidence)
    ├── UDP broadcast to all peers
    └── Advance local PBFT state machine
    │
    ▼
Peers receive PRE_PREPARE
    │
    ├── Verify signature
    ├── Check TOFU trust
    ├── Vote PREPARE (sign + broadcast)
    └── If quorum(2f+1) PREPARE votes → COMMIT
    │
    ▼
Peers receive COMMIT votes
    │
    ├── Verify signatures
    └── If quorum COMMIT votes → EXECUTED
    │
    ▼
EXECUTED → MitigationEngine::dispatch()
    │
    ├── Parse evidence JSON
    ├── Validate schema
    └── Execute: SIGKILL / iptables DROP / nftables DROP
```

### 3. Telemetry Gossip

```
Every HEARTBEAT_INTERVAL:
    │
    ▼
Build telemetry JSON:
  {node_id, entropy, cpu, ram, peers, status, timestamp}
    │
    ▼
Unicast to all known peers (UDP 9998)
    │
    ▼
Each peer:
  ├── Store in local telemetry map
  └── Forward to TelemetryBridge (WebSocket broadcast)
    │
    ▼
Dashboard receives full mesh view via ANY node's WebSocket
```

## Module Dependencies

```
main.cpp
├── PolicyEnforcer (enforcer/)
│   ├── MitigationEngine (enforcer/)
│   │   └── PolicyEnforcer (circular → resolved by forward decl)
│   └── libbpf, iptables, nftables
├── MeshNode (consensus/)
│   ├── PBFTConsensus (consensus/PBFT.hpp)
│   │   └── IdentityCore (crypto/)
│   ├── TransportLayer (net/)
│   │   ├── TLSContext (net/)
│   │   └── PeerDiscovery (net/)
│   ├── KeyManager (crypto/)
│   │   └── OpenSSL (X509, PEM, EVP)
│   ├── StateJournal (common/)
│   │   └── SHA-256 (crypto/)
│   └── Base64 (common/)
├── TelemetryBridge (telemetry/)
│   ├── uWebSockets (third_party/)
│   └── seccomp
├── InferenceEngine (cell/)
│   └── ONNX Runtime
├── NodeAgent (cell/)
│   └── libbpf (eBPF skeleton)
├── AuditLogger (telemetry/)
│   └── UniqueFD (common/)
└── Observability (telemetry/)
    └── SHA-256 (crypto/)
```

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9998 | UDP | Peer discovery beacons + telemetry gossip |
| 9999 | UDP | PBFT consensus messages |
| 9000-9040 | TCP | TelemetryBridge WebSocket (per node) |
| 9100+ | TCP | TLS peer-to-peer connections |
| 50052 | UDP | Audit logger (optional) |
| 9100 | TCP | Prometheus metrics (optional) |

## Security Boundaries

```
┌─────────────────────────────────────────────────┐
│                  Host Kernel                      │
│  ┌───────────────────────────────────────────┐  │
│  │           eBPF Verifier                    │  │
│  │  (probes verified before loading)          │  │
│  └───────────────────┬───────────────────────┘  │
│                      │ ring buffer               │
│  ┌───────────────────▼───────────────────────┐  │
│  │          Userspace Process                 │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │       Main Node Process             │  │  │
│  │  │  (CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN)│  │  │
│  │  └──────────────────┬──────────────────┘  │  │
│  │                     │ fork                │  │
│  │  ┌──────────────────▼──────────────────┐  │  │
│  │  │    TelemetryBridge (sandboxed)      │  │  │
│  │  │  chroot + seccomp + uid drop        │  │  │
│  │  │  (nobody, no capabilities)          │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Configuration

Neuro-Mesh is configured via environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEURO_NODE_ID` | (required) | Unique node identifier |
| `NEURO_WS_PORT` | 9000 | TelemetryBridge WebSocket port |
| `NEURO_TLS_PORT` | 9100 | TLS peer-to-peer port |
| `NEURO_DISCOVERY_PORT` | 9998 | UDP discovery/gossip port |
| `NEURO_CONSENSUS_PORT` | 9999 | UDP PBFT consensus port |
| `NEURO_WEBHOOK_URL` | (empty) | Alert webhook URL |
| `NEURO_KEYSTORE_PATH` | `./keystore_<id>` | Key storage directory |
| `NEURO_SANDBOX_UID` | 65534 | Sandbox user ID |
| `NEURO_SANDBOX_GID` | 65534 | Sandbox group ID |
| `NEURO_CHROOT_PATH` | `/var/empty` | Sandbox chroot path |

## Build Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| `bin/neuro_agent` | Binary | Main node executable |
| `bin/inject_event` | Binary | IPC event injection CLI |
| `bin/test_crypto` | Binary | Cryptographic unit tests |
| `bin/test_pbft` | Binary | PBFT consensus unit tests |
| `bin/test_enforcer` | Binary | Policy enforcement unit tests |
| `bin/test_meshnode` | Binary | Mesh node unit tests |
| `bin/test_inference` | Binary | Inference engine unit tests |
| `kernel/sensor.skel.h` | Generated | eBPF skeleton header |
| `isolation_forest.onnx` | Generated | ML anomaly detection model |
