# Threat Model — Neuro-Mesh

Per-component STRIDE analysis of the decentralized P2P security mesh.

## Trust Boundaries

```
[Kernel eBPF probes] ← T1 → [NodeAgent process]
[NodeAgent process]  ← T2 → [Peer mesh (UDP/TLS)]
[TelemetryBridge]    ← T3 → [Dashboard browser]
[IPC socket]         ← T4 → [External operator tools]
```

## T1: eBPF Sensor → NodeAgent

| Threat | Risk | Mitigation |
|--------|------|------------|
| S - Spoofing kernel events | **Medium** | Ring buffer is kernel-owned, not forgeable from userspace |
| T - Tampering event data in transit | **Low** | Events are raw structs in mmap'd ring buffer; no userspace interception |
| R - Repudiation of detected anomalies | **Low** | ProofChain cryptographically records every consensus event with Ed25519 signatures |
| I - Information disclosure via eBPF maps | **Medium** | Maps are read-only from userspace; no secret keys stored in eBPF |
| D - DoS via ring buffer overflow | **Low** | Tight `while(ring_buffer__poll()>0)` drain loop prevents kernel-side loss |
| E - Elevation via malicious eBPF program | **Low** | eBPF verifier ensures no loops, bounded execution; signed BPF program |

## T2: NodeAgent ↔ Peer Mesh (Consensus + Gossip)

| Threat | Risk | Mitigation |
|--------|------|------------|
| S - Spoofed peer identity | **Medium** | Ed25519 key binding on every PBFT message; dual-path TOFU (beacon + ANNOUNCE must agree) |
| T - Tampered PBFT votes in transit | **Medium** | Ed25519 signature binds (stage + target + evidence); cross-stage replay prevented |
| R - Repudiation of consensus decisions | **Low** | ProofChain provides cryptographic audit trail of every CONSENSUS_REACHED event |
| I - Information disclosure via telemetry gossip | **Medium** | Telemetry is public by design (non-sensitive CPU/mem/entropy); peer_list is operational metadata |
| D - DoS via PBFT message flood | **Low** | Per-source-IP rate limiting on discovery port; per-sender PBFT rate limiting; seen-message deduplication |
| E - Elevation via malicious consensus | **Low** | PBFT quorum (2f+1 from n=3f+1 peers) requires supermajority; single node cannot unilaterally isolate |

## T3: TelemetryBridge ↔ Dashboard

| Threat | Risk | Mitigation |
|--------|------|------------|
| S - Spoofed telemetry feed | **Low** | WebSocket is localhost-only; connect to any node for full mesh view |
| T - Tampered telemetry in transit | **Low** | Dashboard connects directly to node IP; no intermediaries in production |
| R - Repudiation of displayed events | **Low** | Event feed shows live data; historical audit via ProofChain export |
| I - Information disclosure via WebSocket | **Low** | Telemetry ports are host-network; no sensitive data in telemetry JSON |
| D - DoS via WebSocket connection flood | **Medium** | uWebSockets connection limit; seccomp filter restricts child process syscalls |
| E - Elevation via TelemetryBridge compromise | **Low** | Child runs under chroot + nobody uid + seccomp-bpf (56 whitelisted syscalls); parent isolates write-end of pipe |

## T4: IPC Socket ↔ Operator Tools

| Threat | Risk | Mitigation |
|--------|------|------------|
| S - Spoofed IPC commands | **Medium** | Optional `NEURO_IPC_TOKEN` shared-secret authentication handshake |
| T - Tampered inject/isolate commands | **Medium** | Commands validated for legal targets; safe-list prevents self-isolation |
| R - Repudiation of operator actions | **Low** | All INJECT/ISOLATE/RESET commands logged in AuditLogger |
| I - Information disclosure via IPC socket | **Low** | Unix domain socket at `/tmp/neuro_mesh_{id}.sock` with `umask 077` permissions |
| D - DoS via IPC command flood | **Medium** | Per-UID rate limiting; max 256 UIDs tracked with LRU eviction |
| E - Elevation via IPC socket | **Low** | Token authentication; commands execute as the same process, no privilege escalation |

## Residual Risks

1. **TOFU key continuity**: First-seen public key is trusted permanently. Manually revocable via `unpin_peer_key()` but no automated rotation. Risk window: attacker must compromise a node before its first ANNOUNCE and maintain impersonation.
2. **Equivocation window**: A node that votes both PREPARE and COMMIT for conflicting targets within the same round is detected and trust-scored, but the detection is post-hoc — mitigation may have already executed. Trust scoring degrades future rounds.
3. **Seccomp completeness**: The 56-whitelist syscall policy was built by observing runtime syscalls. A uWebSockets update adding new syscalls could break the sandbox until the profile is updated.
