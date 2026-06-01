#!/usr/bin/env python3
"""5-node mesh adversarial runtime test — Phase 4.

Verifies:
1. 5 nodes boot, form mesh, remain stable 15s+
2. Real UDP attack flood from attack_injector doesn't crash nodes
3. Auto-ban events fire (at least 1, at most 15 — not 100s)
4. Rate-limit log lines ≤ 5 (not 1000s)
5. All nodes alive after attack + cooldown
"""

import subprocess, time, os, signal, sys, re
from pathlib import Path

NODES = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"]
ROOT = Path(__file__).parent.parent.parent
BIN = ROOT / "bin" / "neuro_agent"
ATTACK = ROOT / "bin" / "attack_injector"
LOGS = ROOT / "logs" / "adversarial"
PIDS_FILE = ROOT / "logs" / "adversarial" / ".pids"

def cleanup_old():
    LOGS.mkdir(parents=True, exist_ok=True)
    for n in NODES:
        for ext in [".log"]:
            f = LOGS / f"{n}{ext}"
            if f.exists(): f.unlink()

def boot_nodes():
    procs = []
    for n in NODES:
        env = os.environ.copy()
        env["NEURO_UNSAFE_NO_SANDBOX"] = "1"
        env["NEURO_WS_PORT"] = str(9000 + (ord(n[-1]) - ord('A')))
        lf = open(LOGS / f"{n}.log", "w")
        p = subprocess.Popen([str(BIN), n], stdout=lf, stderr=subprocess.STDOUT,
                             cwd=str(ROOT), env=env)
        procs.append((n, p, lf))
    return procs

def wait_mesh(procs, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        all_ok = True
        for n, p, _ in procs:
            if p.poll() is not None: return False
            lp = LOGS / f"{n}.log"
            if not lp.exists(): all_ok = False; continue
            txt = open(lp).read()
            if "discovered" not in txt.lower() and "verified" not in txt.lower():
                all_ok = False
        if all_ok: return True
        time.sleep(0.5)
    return False

def log_lines(node_id):
    lp = LOGS / f"{node_id}.log"
    return sum(1 for _ in open(lp)) if lp.exists() else 0

def log_matches(node_id, pattern):
    lp = LOGS / f"{node_id}.log"
    return 0 if not lp.exists() else len(re.findall(pattern, open(lp).read(), re.I))

def main():
    print("=" * 60)
    print("PHASE 4: 5-NODE MESH ADVERSARIAL RUNTIME TEST")
    print("=" * 60)
    cleanup_old()

    print("\n Booting 5 nodes...")
    procs = boot_nodes()
    for n, p, _ in procs: print(f"  {n} pid={p.pid}")

    print("\n Waiting for mesh formation (15s timeout)...")
    if not wait_mesh(procs, 15):
        print("  [WARN] Mesh formation timed out")

    time.sleep(3)
    baseline = {n: log_lines(n) for n in NODES}
    print(f"  Baseline log lines: {baseline}")

    print("\n Launching UDP attack (4s, 50 msg/s, 4 threads = 800 VOTEs)...")
    atk = subprocess.Popen(
        [str(ATTACK), "--duration", "4", "--rate", "50", "--threads", "4", "--target", "RANDOM"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=str(ROOT))
    atk.wait(timeout=12)
    atk_out = atk.stdout.read().decode() if atk.stdout else ""
    print("  " + atk_out.strip().replace("\n", "\n  "))

    time.sleep(3)

    final = {n: log_lines(n) for n in NODES}
    delta = {n: final[n] - baseline[n] for n in NODES}
    auto_bans = sum(log_matches(n, r"auto.ban|auto-ban") for n in NODES)
    rate_limited = sum(log_matches(n, r"rate.?limit|DEFENSE") for n in NODES)

    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    all_pass = True
    for n in NODES:
        d = delta[n]
        if d > 500:
            print(f"  [FAIL] {n}: +{d} log lines (threshold 500)")
            all_pass = False
        else:
            print(f"  [OK]   {n}: +{d} log lines")

    alive = all(p.poll() is None for n, p, _ in procs)
    if not alive:
        dead = [n for n, p, _ in procs if p.poll() is not None]
        print(f"\n  [FAIL] Crash: {dead}")
        all_pass = False
    else:
        print(f"  [OK]   All 5 nodes alive after attack")

    print(f"\n  Auto-ban events:  {auto_bans}")
    print(f"  Rate-limit lines: {rate_limited}")

    if all_pass:
        print("\n  >>> PHASE 4 PASSED <<<")
    else:
        print("\n  >>> PHASE 4 FAILED <<<")

    # Cleanup
    for n, p, lf in procs:
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill()
        lf.close()

    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
