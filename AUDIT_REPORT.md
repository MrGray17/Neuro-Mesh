# Neuro-Mesh Audit — Verified Findings Only

After re-reading the actual source code to verify every claim, here are the **real bugs** (not design opinions, not theoretical attacks):

## CONFIRMED BUGS

### 1. eBPF Isolation Broken (HIGH)
**Files:** `enforcer/PolicyEnforcer.cpp:270`, `kernel/sensor.bpf.c:56`, `Makefile`

`PolicyEnforcer::apply_ebpf_drop()` writes to a pinned map at `/sys/fs/bpf/neuro_mesh/neuro_blocklist`. The loaded XDP program (`xdp_neuro_mesh_dropper` from `sensor.bpf.c`) reads from a **different** map called `xdp_blacklist` (defined as a static BPF map in the ELF). Meanwhile `neuro_bpf.c`, which defines `neuro_blocklist` as a static map and a matching XDP program, is **never compiled or loaded** (no Makefile target). Two independent eBPF stacks that don't talk to each other — writes go to one map, reads come from another. The eBPF backend reports success but drops zero packets.

**Fix:** Make PolicyEnforcer write to the `xdp_blacklist` map FD obtained from the loaded skeleton, or compile + attach `neuro_bpf.c`.

---

### 2. `block_ip_address` Bypasses Safe List (HIGH)
**Files:** `enforcer/PolicyEnforcer.cpp:425`, `enforcer/MitigationEngine.cpp:302-319`

`block_ip_address()` checks `is_valid_ip()` and `is_loopback()` only — it never calls `is_safe()`. The safe list check only exists in `isolate_target()`. Both functions are called from `MitigationEngine::execute_response()`, with `block_ip_address(src_ip)` called first. If the evidence JSON contains a safe-listed node's non-loopback IP as `src_ip`, that IP gets blocked.

**Fix:** Add safe-list lookup by resolved IP in `block_ip_address()`.

---

### 3. XSS in Dashboard via `data.hash` (HIGH)
**File:** `dashboard/index.html:1062`

```js
feed.innerHTML = '<div class="feed-item"><span class="feed-category">' + category
    + '</span> <span class="feed-time">' + timeStr + '</span> '
    + '<span class="feed-hash">' + shortHash + '</span> '  // UNSAFE
    + '<span class="feed-message">' + escapeHtml(message) + '</span></div>';
```

`message` is HTML-escaped via `escapeHtml()` but `shortHash` (from `data.hash`) is not. An attacker sending `{"hash":"<img src=x onerror=alert(1)>"}` via WebSocket executes arbitrary JS in the dashboard. `data.consensus_hash` at line 1331 has the same problem.

**Fix:** Wrap `shortHash` in `escapeHtml()`.

---

### 4. TELEMETRY Gossip Unauthenticated (MEDIUM)
**File:** `consensus/MeshNode.cpp:880-900`

```cpp
void MeshNode::process_telemetry_gossip(const std::string& msg, const std::string& /*sender_ip*/) {
    // Format: TELEMETRY|<node_id>|<json>
    size_t first_delim = msg.find('|');
    ...
    std::string peer_id = msg.substr(first_delim + 1, second_delim - first_delim - 1);
    ...
    m_peer_manager.set_peer_telemetry(peer_id, json);
```

No signature verification on TELEMETRY. Any process on the network can inject `TELEMETRY|ANY_NODE|{...}` and it will be stored and forwarded to the dashboard. Impact is limited to display spoofing (doesn't trigger PBFT or isolation).

**Fix:** Add Ed25519 signature to TELEMETRY, or at minimum reject from unverified peers.

---

### 5. Unix Socket World-Accessible (MEDIUM)
**File:** `main.cpp:276-290`

IPC socket created at `/tmp/neuro_mesh_{node_id}.sock` with no `chmod()` after `bind()`. Default umask (typically 022) makes it world-writable. Any local user can send CMD:INJECT, CMD:ISOLATE, CMD:SHUTDOWN.

**Fix:** `chmod(socket_path, 0600)` after `bind()`.

---

### 6. IPC Evidence Truncation (MEDIUM)
**File:** `main.cpp:377-378`

```cpp
char buf[256];       // 255 usable bytes
ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
```

Evidence validation allows up to 65536 bytes (line 397), but the read buffer is 256. JSON evidence gets silently truncated, producing malformed JSON downstream.

**Fix:** Match buffer size to validation limit, or read in a loop until newline/EOF.

---

### 7. Dashboard/Services Have Zero Authentication (MEDIUM)
**Files:** `dashboard/index.html`, `orchestration/control_server.py`, `orchestration/ws_proxy.py`

All WebSocket endpoints accept connections from any origin, any client. No token, no origin check, no TLS. Full telemetry readable by any process that can reach the port.

**Fix:** Add origin checking + shared token auth.

---

### 8. `NEURO_PEERS` `std::stoi` Crash on Bad Input (MEDIUM)
**File:** `main.cpp:544`

```cpp
int port = std::stoi(entry.substr(colon + 1));  // throws if non-numeric
```

No try-catch. Malformed `NEURO_PEERS` env var terminates the process before any threads start.

**Fix:** Wrap in try-catch or use `std::strtol`.

---

### 9. `heartbeat_thread` Starts Before `mesh.start()` (MEDIUM)
**File:** `main.cpp:589-596`

Heartbeat thread begins executing immediately after creation, before `MeshNode::start()` launches the listener threads. Early heartbeat messages (PBFT broadcasts, telemetry gossip) are sent into a void — no peer is listening yet. No crash risk (all members initialized in constructor), but wasted work.

**Fix:** Move heartbeat thread creation to after `mesh.start()`.

---

### 10. Partial `CertificateAuthority` Implementation (MEDIUM)
**File:** `CertificateAuthority.cpp`

Methods like `create_root_ca()`, `sign_csr()`, `verify_certificate()`, `verify_chain()` return `nullopt` or `false`. Any code path relying on CA operations silently fails.

**Fix:** Either implement or remove the stubs.

---

### 11. AttackSimulator Does Real I/O (MEDIUM-HIGH depending on deployment)
**File:** `attacks/AttackSimulator.cpp:191-221`

`simulate_network_attack()` performs real TCP `connect()` and UDP `sendto()` against `target_ip:target_port`. In production/staging, this is a real attack, not a simulation.

**Fix:** Gate real I/O behind a confirmation flag or remove from production builds.

---

### 12. Docker Compose Overprivileged (MEDIUM)
**File:** `docker-compose.yml`

`network_mode: host` + capabilities `SYS_ADMIN, BPF, NET_ADMIN, PERFMON`. A compromised container has host-network access and root-equivalent kernel access. This is architecturally required (eBPF + iptables), but the blast radius of any container compromise is the entire host.

**Fix:** Add resource limits, document the risk, consider user-namespace remapping.

---

## NOT BUGS (items I overstated or got wrong)

| Previously claimed | Verdict |
|---|---|
| `prev_message_hash` not in sig → chain broken | **Overstated.** Changing it breaks chain verification. You need the right sig + right chain hash. Not exploitable in practice. |
| `sender_id` not in sig → cross-node rebinding | **Overstated.** Sig verifies against key looked up by sender_id. Rebinding requires identical tuple from 2 nodes. |
| Dual-format sigs → downgrade | **Wrong.** Ed25519 sigs are content-specific. New sigs can't verify old blobs. |
| No leader auth → any node can trigger isolation | **Overstated.** Still needs quorum (3+ other votes). Rate-limited. Safe list provides backup. |
| `suspend_process(0)` → group STOP | **Gated.** MitigationEngine's `validate_pid` rejects 0 and 1 before calling. Direct calls to suspend_process would be vulnerable, but that's not the normal path. |
| Soft-fail sandbox layers | **Design choice.** Graceful degradation is explicit project philosophy. `no_new_privs` fails hard; chroot/uid/seccomp are best-effort. Works correctly when /var/empty exists and privileges allow. |

## REAL ISSUES COUNT: 12 confirmed bugs (3 HIGH, 9 MEDIUM)

Plus the telemetry/gossip/auth hardening items which are design gaps, not runtime bugs.
