# ADR-0004: Dual-Path TOFU Trust Model

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Neuro-Mesh architecture team  

## Context

The mesh operates without a Certificate Authority (CA) or public key infrastructure (PKI). Peers discover each other via broadcast ANNOUNCE messages and periodic discovery beacons. A single discovery path could be exploited by a MITM attacker presenting a different key on each path.

## Decision

Use dual-path Trust-On-First-Use (TOFU): a peer's Ed25519 public key must be confirmed via BOTH the broadcast ANNOUNCE message and the periodic discovery beacon before it is trusted. Both paths must present the same key. Pre-provisioned keys (via `NEURO_PEER_KEYS` env var) bypass TOFU entirely and are verified on arrival.

## Alternatives Considered

- **CA-based PKI**: Requires running a CA server and distributing certificates to all nodes. Rejected — violates zero-infrastructure design goal.
- **Single-path TOFU**: Trust first ANNOUNCE. Rejected — a MITM on a single UDP broadcast could spoof identity.
- **Web of Trust**: Nodes vouch for each other's keys. Rejected — requires pre-existing trust relationships.

## Consequences

- **Positive**: Automatic trust establishment without any infrastructure.
- **Positive**: Dual-path confirmation raises the bar for MITM attacks — attacker must intercept both broadcast paths simultaneously.
- **Negative**: First-seen key is trusted permanently. Manual revocation via `unpin_peer_key()` is supported, but no automated rotation protocol exists. Tracked as P2 post-competition enhancement.
- **Negative**: Initial discovery latency increases (beacon + ANNOUNCE both needed), but acceptable for a mesh with sub-10s heartbeat cycles.
