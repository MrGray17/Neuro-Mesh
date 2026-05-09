#!/usr/bin/env python3
"""Integration test: verifies the full entropy pipeline end-to-end.

Data path: eBPF tracepoint → NodeAgent ring buffer → InferenceEngine::analyze()
→ heartbeat_loop entropy → UDP:9998 → control_server → WebSocket:9001 → dashboard

Usage:
    python3 tools/test_entropy_pipeline.py
"""

import asyncio
import json
import subprocess
import sys
import time
import websockets

WS_URL = "ws://localhost:9001"
INJECT_TIMEOUT = 15  # seconds to wait for entropy spike after injection


async def collect_entropy(duration_s: float) -> list[float]:
    """Collect entropy values from the WebSocket for `duration_s` seconds."""
    values: list[float] = []
    async with websockets.connect(WS_URL) as ws:
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                data = json.loads(msg)
                if data.get("event") == "heartbeat":
                    values.append(float(data.get("entropy", 0.0)))
            except asyncio.TimeoutError:
                pass
    return values


def inject_event(node: str, target: str) -> bool:
    """Run inject_event inside a Docker container. Returns True on success."""
    proc = subprocess.run(
        ["docker", "exec", f"neuro_{node.lower()}",
         "/app/inject_event", "--node", node, "--target", target],
        capture_output=True, text=True, timeout=10,
    )
    return "ACK:INJECT" in proc.stdout


async def main():
    print("=" * 60)
    print("Neuro-Mesh Entropy Pipeline Integration Test")
    print("=" * 60)

    # ---- Step 1: Baseline ----
    print("\n[1/4] Collecting baseline entropy (4s)...")
    baseline = await collect_entropy(4.0)
    if not baseline:
        print("FAIL: No heartbeat events received. Is the mesh running?")
        sys.exit(1)

    avg_baseline = sum(baseline) / len(baseline)
    max_baseline = max(baseline)
    print(f"  Samples: {len(baseline)}, avg={avg_baseline:.4f}, max={max_baseline:.4f}")

    if avg_baseline > 0.1:
        print(f"  WARNING: Baseline entropy is unusually high ({avg_baseline:.4f}).")

    # ---- Step 2: Inject ----
    print("\n[2/4] Injecting demo event (CHARLIE → ALPHA)...")
    if not inject_event("CHARLIE", "ALPHA"):
        print("FAIL: inject_event failed or no ACK received.")
        sys.exit(1)
    print("  ACK received.")

    # ---- Step 3: Spike detection ----
    print(f"\n[3/4] Monitoring for entropy spike (up to {INJECT_TIMEOUT}s)...")
    spike_values = []
    deadline = time.monotonic() + INJECT_TIMEOUT
    spike_found = False

    async with websockets.connect(WS_URL) as ws:
        while time.monotonic() < deadline:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=2.0)
                data = json.loads(msg)
                if data.get("event") == "heartbeat":
                    entropy = float(data.get("entropy", 0.0))
                    spike_values.append(entropy)
                    if entropy > 0.8:
                        spike_found = True
                        print(f"  SPIKE DETECTED: node={data.get('node')} entropy={entropy:.4f} threat={data.get('threat')}")
            except asyncio.TimeoutError:
                pass

    max_spike = max(spike_values) if spike_values else 0.0
    print(f"  Samples during window: {len(spike_values)}, max={max_spike:.4f}")

    # ---- Step 4: Verdict ----
    print("\n[4/4] Verdict:")
    if spike_found:
        print("  PASS: Entropy spike > 0.8 detected after injection.")
    else:
        print(f"  FAIL: No entropy spike detected (max={max_spike:.4f}).")
        print("  Check: docker logs neuro_charlie | grep -E 'EBPF|DEMO|HEARTBEAT'")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Pipeline verified: eBPF → ONNX → UDP → WS → Dashboard")
    print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
