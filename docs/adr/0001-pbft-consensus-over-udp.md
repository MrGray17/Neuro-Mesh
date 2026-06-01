# ADR-0001: PBFT Consensus over UDP Broadcast

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Neuro-Mesh architecture team  

## Context

The mesh requires Byzantine fault tolerance for decentralized anomaly verification. Nodes must reach agreement on whether to isolate a peer without a central coordinator.

## Decision

Use Practical Byzantine Fault Tolerance (PBFT) with three-phase commit (PRE_PREPARE → PREPARE → COMMIT → EXECUTED) over UDP broadcast to `127.0.0.1:9999`. All nodes run on localhost; discovery is implicit via broadcast.

## Alternatives Considered

- **Raft/Paxos**: Only tolerates crash faults, not Byzantine (malicious) behavior. Rejected — security mesh must handle compromised nodes that lie.
- **Tendermint/HotStuff**: Requires stable leader election and view changes. Over-engineered for a 5-node mesh. Rejected — complexity cost exceeds benefit.
- **PBFT over TCP unicast**: Reliable but introduces connection state management per peer. Rejected — UDP broadcast is simpler for localhost mesh and allows implicit peer discovery.

## Consequences

- **Positive**: Quorum of 2f+1 from n=3f+1 nodes prevents a single malicious node from forcing isolation.
- **Positive**: UDP broadcast eliminates explicit peer connection management.
- **Negative**: UDP message loss on high-load systems; mitigated by PBFT round TTL (120s) and retry via heartbeat-initated rounds.
- **Negative**: View change protocol is conceptually designed but not implemented — stale rounds are simply expired.
