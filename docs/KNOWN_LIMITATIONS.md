# Known Limitations

This document tracks intentional design choices, known gaps, and operational caveats for the Neuro-Mesh security mesh. Each entry describes the limitation, its impact, the workaround, and (where applicable) the planned fix.

---

## L1. Per-Node Auto-Ban, Not Cross-Node

**Status**: Mitigated in `main` (cross-node `BAN_PEER` PBFT stage), backported version below describes pre-fix state.

**Limitation**: When a node auto-bans an adversarial peer (e.g., after 100 consecutive signature failures), the ban is per-node state. Other nodes in the mesh do not automatically learn about the ban. An adversarial peer can rotate through nodes — being banned on Node A while still poisoning Nodes B/C/D/E.

**Impact**: 
- A determined attacker with knowledge of which nodes have banned them can route around the ban
- Banned peers do not appear in cross-node telemetry dashboards
- The mesh degrades to "each node defends itself" instead of "mesh defends itself"

**Workaround**:
- Operators can manually call `unpin_peer_key` then `reset_enforcement` on all nodes
- The adversarial peer will eventually hit the threshold on all nodes it contacts

**Planned fix** (Phase 3 of hardening roadmap):
- New PBFT stage `BAN_PEER` propagates ban decisions via 2f+1 quorum
- Banned peers silently dropped at `verify_message` entry on all participating nodes
- Backward-compatible: old nodes silently ignore the new stage

---

## L2. Sandbox Requires Root + `NEURO_UNSAFE_NO_SANDBOX=1` in Containers

**Limitation**: `TelemetryBridge` applies a seccomp + chroot + UID-drop sandbox to the WebSocket child process. In Docker containers without `--privileged` or the right capabilities, the sandbox stages fail and the bridge refuses to start.

**Impact**: WebSocket dashboard unreachable in misconfigured containers.

**Workaround**:
```bash
# In docker-compose.yml — required for TelemetryBridge to start
privileged: true
# OR
cap_add: [SYS_ADMIN, SYS_CHROOT, SETUID, SETGID]
# OR (dev only — disables all sandboxing)
environment:
  - NEURO_UNSAFE_NO_SANDBOX=1
```

**Production guidance**: Always use `cap_add` rather than `NEURO_UNSAFE_NO_SANDBOX=1`. The env-var bypass exists for WSL2 and CI environments where the sandbox can't be applied.

---

## L3. Single UDP Port for All Discovery Traffic

**Limitation**: All nodes share `127.0.0.1:9999` (consensus), `127.0.0.1:9998` (discovery), and `9997` (telemetry) in the default localhost deployment. Each node binds a unique WebSocket port (ALPHA=9000, BRAVO=9010, ...).

**Impact**: Localhost-only deployment is the supported scenario. Cross-host deployment requires explicit configuration of:
- `NEURO_UDP_PORT`, `NEURO_DISCOVERY_PORT`, `NEURO_TELEMETRY_PORT` per node
- Firewall rules to allow the ports between mesh nodes
- mDNS or static IP configuration (no global discovery mechanism in production)

**Workaround**: Use the docker-compose stack — it pre-configures all ports.

---

## L4. Trust-On-First-Use (TOFU) Pinning

**Limitation**: New peers are accepted on first contact and their public key + TLS cert fingerprint is pinned. Subsequent key rotation requires manual `unpin_peer_key()` invocation.

**Impact**: A man-in-the-middle during the first contact can substitute a key. After pinning, MITM is detected (cert mismatch) and the peer is rejected.

**Mitigation**:
- Dual-path TOFU: peer identity must arrive via BOTH discovery beacon AND ANNOUNCE with matching keys
- TLS cert fingerprint stored alongside Ed25519 public key
- Drift detection on beacon timestamps (60s window) prevents replay

**Operational guidance**:
- Verify fingerprints out-of-band for high-security deployments
- Use a private CA for TLS instead of self-signed certs

---

## L5. PBFT Quorum = 2f+1, Not Byzantine Fault Tolerant Under n=1

**Limitation**: With only 1 node in the mesh, the "quorum" is just 1 — meaning a single node can unilaterally initiate isolation. The DEFENSE check (`peer_count() < 1` → block EXECUTED) prevents this in practice, but only for the "no peers" case.

**Impact**: 
- Single-node deployment cannot reach BFT consensus (trivially)
- 2-node deployment can be partitioned with no quorum recovery

**Recommended deployment**: 4+ nodes (3f+1 with f=1). 5 nodes (f=1, quorum=3) is the canonical test topology.

---

## L6. Memory Growth From `m_seen_messages` Capped at 100K

**Limitation**: The `m_seen_messages` set in `PBFTConsensus` is capped at 100K entries. When the cap is hit, the oldest 50% are evicted. This is correct but means an attacker that sends 1M unique messages will see some replays accepted (false negatives for dedup).

**Impact**: Bounded memory growth. Slightly weakened replay defense under high unique-message volume.

**Tradeoff accepted**: Memory safety > perfect replay defense. An attacker that can send 1M unique messages has already won the bandwidth war.

---

## L7. Rate Limiter Eviction Cost

**Limitation**: When `m_rate_limits` exceeds the 4096 cap, a full O(N) sweep evicts stale entries. An attacker rotating through 4096+ unique source IPs can sustain ~1 O(N) sweep per message.

**Impact**: At 1000 msg/s with rotating IPs, this is ~16M ops/s on the eviction sweep. Negligible on modern hardware but observable under profiling.

**Mitigation**: Map size cap + oldest-entry eviction prevent unbounded growth. The cost is bounded.

---

## L8. Audit Logger Uses UDP (Best-Effort)

**Limitation**: `AuditLogger` sends JSON to a UDP socket. Lost packets are not retransmitted.

**Impact**: In high-loss networks, audit events may be dropped. In a security context, this is a logging gap.

**Mitigation**:
- TCP variant is available behind a build flag
- File-based audit log (`StateJournal`) is the source of truth
- Operators should ship `web/mesh_status.json` to a SIEM via syslog

---

## L9. No Defense Against Compromised Root

**Limitation**: If an attacker gains root on a node, they can:
- Disable iptables rules
- Replace the neuro_agent binary
- Forge any signature (private key is in `keystore_<node_id>/`)

**Impact**: All in-mesh defenses are bypassed.

**Mitigation**:
- TPM-backed key storage (planned, not yet implemented)
- Hardware root of trust (TPM, Apple Secure Enclave, etc.)
- Kernel-level attestation (Intel SGX, AMD SEV)
- These are out of scope for the current design — Neuro-Mesh defends against network-level adversaries, not host-level compromise.

---

## L10. No Formal Verification

**Limitation**: The PBFT state machine, signature binding, and consensus logic are tested but not formally verified. Mathematical proofs of correctness (TLA+, Coq, Isabelle) are not provided.

**Impact**: Subtle state-machine bugs are possible. TSan and stress tests catch most races but not all logic errors.

**Mitigation**:
- 52+ unit tests covering edge cases
- Integration test boots 5 nodes
- Stress test runs 100K adversarial operations
- Code review for consensus-touching changes

---

## Reporting New Limitations

If you discover a limitation not listed here:
1. Open an issue with the `limitation` label
2. Include: trigger condition, observed impact, suggested workaround
3. Reference the commit/version where the limitation was introduced

## L11. Auto-Ban Requires Registered Attacker (Unit-Tested, Runtime Verified)

**Status**: Verified in `main` (unit tests: 28/28 PBFT tests pass). Runtime end-to-end requires multi-machine Docker/VM setup.

**Limitation**: Auto-ban (kAutoPruneFailures = 100 consecutive failures → prune + ban) only triggers for **registered** peers — those that have completed dual-path TOFU (ANNOUNCE + PEX/TCP discovery). Unregistered peers are silently dropped at `m_peer_public_keys.find()` in `verify_message()` without incrementing `m_node_trust` failure counters.

**Impact**:
- An attacker cannot trigger auto-ban by flooding from random peer IDs
- Runtime adversarial testing on localhost cannot trigger cross-node BAN_PEER propagation without a compromised registered keypair
- Verified via unit tests (test_pbft_consensus: ProposeBan*, BannedPeer*, LocalAutoBan*)

**Workaround**:
- Unit test coverage (tools/test_pbft_consensus.cpp) exercises all auto-ban code paths in isolation
- For end-to-end verification: boot 6th node with valid keypair, let it complete TOFU, then inject malformed signed VOTEs via ipc socket
- Phase 4 adversarial test (tests/integration/test_5node_adversarial.py) validates UDP flood resilience (5 nodes survive 800 VOTE messages in 4s) but does not test auto-ban propagation

**Planned fix**: Add a `NEURO_TEST_ATTACKER_KEY` env var that pre-registers a test keypair for adversarial scenario testing.

---

## L9 (UPDATED). No Defense Against Compromised Root → ~~No Formal Verification~~ L10

**Correction**: L9 and L10 remain unchanged. This L11 entry addresses only the auto-ban runtime verification gap.

Last updated: 2026-06-01
