#!/usr/bin/env python3
"""traffic_generator.py — Traffic generator for Neuro-Mesh eBPF validation.

Generates a multi-threaded UDP flood + TCP port scan against a
target node to trigger the eBPF entropy sensor and PBFT consensus cascade.

Usage:
    python3 tools/traffic_generator.py --target 127.0.0.1 --duration 15
    python3 tools/traffic_generator.py --target 192.168.65.3 --duration 30 --threads 8
"""

import argparse
import random
import socket
import sys
import threading
import time

STOP = threading.Event()


def udp_flood(target: str, port_range: range, pkt_size: int = 1400) -> None:
    """Send random UDP datagrams as fast as possible."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    junk = bytearray(random.getrandbits(8) for _ in range(pkt_size))
    while not STOP.is_set():
        port = random.choice(port_range)
        try:
            sock.sendto(junk, (target, port))
        except OSError:
            pass


def tcp_scan(target: str, port_range: range, timeout: float = 0.3) -> None:
    """Aggressive TCP connect() scan cycling through the port range."""
    while not STOP.is_set():
        port = random.choice(port_range)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            # Send a tiny payload to look like an exploit attempt
            try:
                sock.sendall(b"\x90\x90\x90/bin/sh\x00")
            except OSError:
                pass
            sock.close()
        except (OSError, TimeoutError):
            pass


def banner(target: str, duration: int, threads: int) -> None:
    print(f"[TRAFFIC] Strike launched!")
    print(f"        Target   : {target}")
    print(f"        Duration : {duration}s")
    print(f"        Threads  : {threads}")
    print(f"        UDP flood: ports 1-65535, 1400B payloads")
    print(f"        TCP scan : ports 1-65535, aggressive connect()")
    print(f"[TRAFFIC] Press Ctrl+C to abort early.\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Network traffic generator for Neuro-Mesh eBPF validation")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--duration", type=int, default=15, help="Attack duration in seconds (default: 15)")
    parser.add_argument("--threads", type=int, default=6, help="Worker threads (default: 6)")
    parser.add_argument("--udp-ratio", type=float, default=0.6, help="Fraction of threads doing UDP flood (default: 0.6)")
    args = parser.parse_args()

    banner(args.target, args.duration, args.threads)

    port_range = range(1, 65536)
    udp_count = max(1, int(args.threads * args.udp_ratio))
    tcp_count = max(1, args.threads - udp_count)

    workers: list[threading.Thread] = []

    for _ in range(udp_count):
        t = threading.Thread(target=udp_flood, args=(args.target, port_range), daemon=True)
        workers.append(t)

    # Shuffle TCP ports to avoid sequential scan pattern
    tcp_ports = list(port_range)
    random.shuffle(tcp_ports)
    tcp_ports = tcp_ports  # keep shuffled list; each scanner gets the same shuffle

    for _ in range(tcp_count):
        t = threading.Thread(target=tcp_scan, args=(args.target, tcp_ports), daemon=True)
        workers.append(t)

    print(f"[TRAFFIC] Spawning {udp_count} UDP flooders + {tcp_count} TCP scanners...")
    for t in workers:
        t.start()

    start = time.monotonic()
    try:
        while time.monotonic() - start < args.duration:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[TRAFFIC] Aborted by user.")
    finally:
        STOP.set()
        for t in workers:
            t.join(timeout=2)
        elapsed = time.monotonic() - start
        print(f"[TRAFFIC] Strike complete. Ran {elapsed:.1f}s. Check the dashboard for eBPF entropy spikes.")


if __name__ == "__main__":
    main()
