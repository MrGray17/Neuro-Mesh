# ADR-0002: Ed25519 Signature Binding for Cross-Stage Replay Prevention

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Neuro-Mesh architecture team  

## Context

PBFT messages pass through multiple stages (PRE_PREPARE, PREPARE, COMMIT). Without cryptographic binding, a attacker could re-use a valid PRE_PREPARE signature as a PREPARE vote, bypassing the consensus protocol.

## Decision

Every Ed25519 signature binds `(stage_str + sender_id + target_id + evidence_json + prev_message_hash + sequence_number + view)` together. The stage string is explicitly included in the signed blob, making cross-stage replay impossible.

## Alternatives Considered

- **Sign-only evidence**: A signature over `(target + evidence)` is replayable across stages. Rejected — trivial bypass.
- **Nonce-based**: Requires a global nonce distributor (centralized). Rejected — violates decentralization goal.
- **Separate key per stage**: Would require 4 Ed25519 keypairs per node. Rejected — key management overhead.

## Consequences

- **Positive**: Cross-stage replay is provably prevented by design — the signature algorithmically binds stage identity.
- **Positive**: Same signing function (`sign_message`) works for all stages; no code duplication.
- **Negative**: Signature verification must reconstruct the exact same blob — any field ordering mismatch causes verification failures. Mitigated by static `compute_message_hash()` which canonicalizes ordering.
