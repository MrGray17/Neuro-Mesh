#!/usr/bin/env python3
"""Neuro-Mesh PBFT Consensus Benchmark Suite (Docker-aware).

Measures:
  Metric A — Latency: delta-t from simulate_threat injection to EXECUTED journal entry.
  Metric B — Resources: CPU ticks and RSS memory delta during a consensus round.

Requires agents to be running via docker-compose. Zero external dependencies.
"""
import subprocess, time, json, os, argparse
from datetime import datetime

CONTAINERS = {
    "ALPHA":   "neuro_alpha",
    "BRAVO":   "neuro_bravo",
    "CHARLIE": "neuro_charlie",
}

JOURNAL_PATHS = {
    "ALPHA":   "./journal_ALPHA.log",
    "BRAVO":   "./journal_BRAVO.log",
    "CHARLIE": "./journal_CHARLIE.log",
}


def read_journal(path: str) -> list:
    """Read a journal.log file, returning parsed JSON entries."""
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def read_journal_since(path: str, since_seq: int) -> list:
    """Read journal entries with seq > since_seq."""
    all_entries = read_journal(path)
    return [e for e in all_entries if e.get("seq", 0) > since_seq]


def get_last_journal_seq(path: str) -> int:
    entries = read_journal(path)
    return entries[-1]["seq"] if entries else 0


def get_container_stats(container: str):
    """Return (cpu_ticks, rss_kb) from container's /proc/1/stat or (0, 0)."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "cat", "/proc/1/stat"],
            capture_output=True, text=True, timeout=5
        )
        fields = result.stdout.split()
        utime = int(fields[13]) if len(fields) > 13 else 0
        stime = int(fields[14]) if len(fields) > 14 else 0
        rss_pages = int(fields[23]) if len(fields) > 23 else 0
        return utime + stime, rss_pages * 4
    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError, ValueError):
        return 0, 0


def snapshot_all_stats():
    """Return {node_id: (cpu_ticks, rss_kb)} for all containers."""
    stats = {}
    for node_id, container in CONTAINERS.items():
        stats[node_id] = get_container_stats(container)
    return stats


def run_simulate_threat(target: str, event: str, verdict: str, tag: str = ""):
    """Inject a threat via a fresh container with host networking."""
    cmd = ["docker", "run", "--rm", "--network=host",
           "--entrypoint", "/app/simulate_threat", "neuro_mesh:titan",
           "--target", target, "--event", event, "--verdict", verdict]
    if tag:
        cmd.extend(["--tag", tag])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def run_single_benchmark(run_id: int, target: str, event: str, verdict: str) -> dict:
    """Run one consensus benchmark iteration. Returns a results dict."""
    result = {
        "run": run_id,
        "target": target,
        "delta_ms": None,
        "executed_seq": None,
        "cpu_before": {},
        "cpu_after": {},
        "mem_before_kb": {},
        "mem_after_kb": {},
    }

    # Snapshot pre-injection resource usage
    before_stats = snapshot_all_stats()
    for nid, (cpu, mem) in before_stats.items():
        result["cpu_before"][nid] = cpu
        result["mem_before_kb"][nid] = mem

    # Snapshot journal positions
    last_seqs = {nid: get_last_journal_seq(path) for nid, path in JOURNAL_PATHS.items()}

    # Record injection time
    t_inject = time.time()

    # Run simulate_threat in a fresh container with host networking
    ok = run_simulate_threat(target, event, verdict, tag=f"run{run_id}")
    if not ok:
        result["delta_ms"] = "SIM_FAILED"
        return result

    # Poll journals for EXECUTED entry
    t_executed = None
    poll_timeout = 30
    start = time.time()
    while time.time() - start < poll_timeout:
        for nid, path in JOURNAL_PATHS.items():
            since = last_seqs.get(nid, 0)
            new_entries = read_journal_since(path, since)
            for e in new_entries:
                if e.get("stage") == "EXECUTED" and e.get("target") == target:
                    t_executed = time.time()
                    result["executed_seq"] = e.get("seq")
                    break
            if t_executed:
                break
        if t_executed:
            break
        time.sleep(0.1)

    if t_executed:
        result["delta_ms"] = round((t_executed - t_inject) * 1000, 2)
    else:
        result["delta_ms"] = "TIMEOUT"

    # Snapshot post-injection resource usage
    time.sleep(0.5)  # let enforcement settle
    after_stats = snapshot_all_stats()
    for nid, (cpu, mem) in after_stats.items():
        result["cpu_after"][nid] = cpu
        result["mem_after_kb"][nid] = mem

    return result


def format_markdown(all_results: list):
    """Generate a Markdown report."""
    lines = []
    lines.append("# Neuro-Mesh PBFT Consensus Benchmark Results")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # --- Metric A: Latency ---
    lines.append("## Metric A: Consensus Latency (Injection -> EXECUTED)")
    lines.append("")
    lines.append("| Run | Target | Delta (ms) | Executed Seq |")
    lines.append("|-----|--------|------------|--------------|")

    deltas = []
    for r in all_results:
        delta = r["delta_ms"]
        seq = r.get("executed_seq", "-")
        lines.append(f"| {r['run']} | {r['target']} | {delta} | {seq} |")
        if isinstance(delta, (int, float)):
            deltas.append(delta)

    if deltas:
        avg = sum(deltas) / len(deltas)
        lat_min = min(deltas)
        lat_max = max(deltas)
        lines.append(f"| **Stats** | | **avg: {avg:.2f}** | min: {lat_min:.2f} / max: {lat_max:.2f} |")

    lines.append("")

    # --- Metric B: Resources ---
    lines.append("## Metric B: Resource Delta During Consensus Round")
    lines.append("")
    lines.append("| Run | Node | CPU Before | CPU After | CPU Delta | Mem Before (KB) | Mem After | Mem Delta (KB) |")
    lines.append("|-----|------|-----------|-----------|-----------|-----------------|-----------|----------------|")

    for r in all_results:
        all_nodes = sorted(set(list(r["cpu_before"].keys()) + list(r["cpu_after"].keys())))
        for nid in all_nodes:
            cb = r["cpu_before"].get(nid, 0)
            ca = r["cpu_after"].get(nid, 0)
            mb = r["mem_before_kb"].get(nid, 0)
            ma = r["mem_after_kb"].get(nid, 0)
            cd = ca - cb
            md = ma - mb
            lines.append(f"| {r['run']} | {nid} | {cb} | {ca} | {cd} | {mb} | {ma} | {md} |")

    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Neuro-Mesh PBFT Consensus Benchmark")
    parser.add_argument("--runs", type=int, default=3, help="Number of benchmark iterations")
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--target", default="ALPHA", help="Target node for threat injection")
    parser.add_argument("--event", default="lateral_movement", help="Event type")
    parser.add_argument("--verdict", default="THREAT", help="Verdict severity")
    args = parser.parse_args()

    all_results = []
    for i in range(args.runs):
        print(f"\n{'='*60}")
        print(f"[RUN {i+1}/{args.runs}] Injecting {args.event}/{args.verdict} -> {args.target}")
        print(f"{'='*60}")
        result = run_single_benchmark(i + 1, args.target, args.event, args.verdict)
        all_results.append(result)
        print(f"  Delta: {result['delta_ms']} ms  |  Executed seq: {result.get('executed_seq', 'N/A')}")
        if i < args.runs - 1:
            time.sleep(2)

    if args.output == "markdown":
        print("\n" + format_markdown(all_results))
    else:
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
