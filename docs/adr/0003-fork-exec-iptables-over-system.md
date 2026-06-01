# ADR-0003: fork+exec iptables over system()

**Status**: Accepted  
**Date**: 2024  
**Deciders**: Neuro-Mesh architecture team  

## Context

Network isolation of compromised peers requires executing iptables commands. The naive approach — `system("iptables -A FORWARD -s IP -j DROP")` — concatenates user-controlled data (IP addresses) into a shell command string, creating a shell injection vector.

## Decision

Use `fork()` + `execv()` to call iptables with arguments passed as separate `argv[]` entries. No shell is involved. The argument vector is:
```
argv = {"iptables", "-A", "FORWARD", "-s", target_ip, "-j", "DROP", nullptr}
```

## Alternatives Considered

- **Netlink/NFLOG**: Direct kernel-level netfilter manipulation. Most secure but requires root, libnetfilter_queue, and complex socket programming. Rejected — operational complexity exceeds benefit for a 5-node mesh.
- **nftables**: Modern replacement for iptables with better handle-based rule management. Considered as an addition, not replacement — both backends are probed on startup.
- **system()**: Single-line convenience. Rejected — shell injection is an unacceptable risk for attacker-controlled IP addresses.

## Consequences

- **Positive**: Shell injection is structurally impossible — no shell process is created.
- **Positive**: `execv()` path resolution follows `$PATH`, compatible with any Linux distribution.
- **Negative**: fork+exec has higher overhead than system() but is non-blocking at OS level (no wait).
- **Negative**: iptables rules persist after process exit; cleanup is handled by `PolicyEnforcer` on shutdown.
