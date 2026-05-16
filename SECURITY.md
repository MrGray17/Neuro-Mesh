# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

We take the security of Neuro-Mesh seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email your findings to the project maintainers (see repository contacts).
3. Include:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours of receiving your report
- **Initial assessment**: Within 5 business days
- **Fix deployment**: Within 30 days for critical vulnerabilities
- **Public disclosure**: After fix is deployed and users have had time to update

### Scope

**In-scope for security reports:**
- eBPF probe vulnerabilities (kernel memory access, privilege escalation)
- PBFT consensus bypasses (signature forgery, replay attacks, equivocation)
- TLS/encryption weaknesses
- Sandbox escape (seccomp, chroot, uid drop bypasses)
- Remote code execution
- Denial of service vectors
- Information disclosure

**Out of scope:**
- Issues in `_archive_old/` (deprecated code)
- Issues in `third_party/` (report to upstream)
- Social engineering attacks
- Physical security attacks

## Security Architecture

### Threat Model

Neuro-Mesh operates under the following threat assumptions:

| Threat | Mitigation |
|--------|-----------|
| Spoofed PBFT votes | Ed25519 signatures on every message |
| Cross-stage replay attacks | Signature binds `(stage + target + evidence)` |
| MITM on peer connections | TOFU key pinning + TLS mTLS |
| Privilege escalation | Seccomp-BPF sandbox + uid drop + chroot |
| Shell injection | `fork`+`exec` for all system commands |
| Buffer overflow | C++20, `-Werror`, ASan in CI |
| Kernel exploit via eBPF | Verified eBPF programs, restricted helpers |
| Consensus manipulation | PBFT requires 2f+1 honest nodes |
| Audit log tampering | SHA-256 chained entries, sequence numbers |

### Security Controls

1. **Cryptographic Identity**: Each node has an Ed25519 keypair, generated at first boot
2. **Trust-on-First-Use (TOFU)**: Peer keys are pinned on first verified contact
3. **PBFT Consensus**: Byzantine fault tolerance — tolerates up to f = (n-1)/3 faulty nodes
4. **Sandboxed WebSocket**: TelemetryBridge runs in a chroot with seccomp-BPF and dropped UID
5. **Safe List**: Critical nodes can never be isolated, even by consensus
6. **Rate Limiting**: Consensus cooldown prevents isolation floods
7. **Signature Binding**: Prevents reusing a PRE_PREPARE signature as a COMMIT

### Known Limitations

- TOFU is vulnerable to initial MITM (key must be verified out-of-band for first contact)
- eBPF probes require `CAP_BPF` / `CAP_PERFMON` capabilities
- PBFT assumes synchronous network (bounded message delay)
- Local root can bypass all userspace security controls
- iptables enforcement requires `CAP_NET_ADMIN`
