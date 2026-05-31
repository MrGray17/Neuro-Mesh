#!/usr/bin/env python3
"""APT attack chain simulator for Neuro-Mesh.
Injects MITRE ATT&CK scenarios into a live mesh cluster.

Usage:
  python3 tools/attack_runner.py list
  python3 tools/attack_runner.py run lateral_movement
  python3 tools/attack_runner.py run random --steps 5
  python3 tools/attack_runner.py replay /tmp/recording_*.json
"""

import argparse
import json
import random
import subprocess
import time
from dataclasses import dataclass
from dataclasses import field
from enum import Enum

INJECT_TOOL = "/app/inject_event"
DOCKER_PREFIX = "neuro_"
IPC_SOCK_TEMPLATE = "/tmp/neuro_mesh_{}.sock"


def inject_via_socket(node_id, target, event, verdict):
    """Inject via Unix domain socket — works without Docker."""
    import json
    import socket

    sock_path = IPC_SOCK_TEMPLATE.format(node_id.upper())
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(sock_path)
        # Build evidence JSON mimicking a real anomaly event
        evidence = json.dumps(
            {
                "event": event,
                "verdict": verdict,
                "target_id": target,
                "source": "attack_runner",
                "timestamp_us": int(time.time() * 1e6),
            }
        )
        cmd = "CMD:INJECT {} {}".format(target, evidence) + "\n"
        sock.sendall(cmd.encode())
        response = sock.recv(4096).decode()
        sock.close()
        return True, response[:80]
    except Exception as e:
        return False, str(e)


class Phase(Enum):
    ACCESS = "initial_access"
    EXEC = "execution"
    PERSIST = "persistence"
    PRIV_ESC = "privilege_escalation"
    EVASION = "defense_evasion"
    CRED = "credential_access"
    DISCOVERY = "discovery"
    LATERAL = "lateral_movement"
    C2 = "command_and_control"
    IMPACT = "impact"


@dataclass
class Step:
    phase: Phase
    target: str
    event: str
    verdict: str = "CRITICAL"
    delay_ms: int = 500
    desc: str = ""
    tags: list = field(default_factory=list)


EVENTS = [
    "entropy_spike",
    "recon_scan",
    "port_scan",
    "remote_exec",
    "credential_dump",
    "lateral_movement",
    "encryption",
    "data_exfil",
    "dns_tunnel",
    "beacon_http",
    "phishing_link",
    "dropper",
    "priv_esc",
    "kill_defender",
    "wmi_exec",
    "ssh_keys",
    "signed_binary",
    "backdoor",
    "service_install",
    "network_discovery",
    "container_escape",
]

NODES = ["ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"]

SCENARIOS = {
    "lateral_movement": {
        "name": "Lateral Movement (T1021)",
        "mitre": "T1021",
        "steps": [
            Step(Phase.ACCESS, "CHARLIE", "recon_scan", "WARNING", 0, "Initial recon"),
            Step(
                Phase.DISCOVERY,
                "CHARLIE",
                "port_scan",
                "WARNING",
                2000,
                "Port sweep on subnet",
            ),
            Step(
                Phase.EXEC,
                "CHARLIE",
                "remote_exec",
                "CRITICAL",
                3000,
                "Remote exec attempt",
            ),
            Step(
                Phase.LATERAL,
                "BRAVO",
                "credential_dump",
                "CRITICAL",
                2000,
                "Credential theft",
            ),
            Step(
                Phase.IMPACT,
                "ALPHA",
                "entropy_spike",
                "CRITICAL",
                3000,
                "Data exfiltration",
            ),
        ],
    },
    "ransomware": {
        "name": "Ransomware (T1486)",
        "mitre": "T1486",
        "steps": [
            Step(
                Phase.ACCESS,
                "CHARLIE",
                "phishing_link",
                "WARNING",
                0,
                "Phishing link clicked",
            ),
            Step(
                Phase.EXEC,
                "CHARLIE",
                "dropper",
                "WARNING",
                3000,
                "Dropper downloads payload",
            ),
            Step(
                Phase.PRIV_ESC,
                "CHARLIE",
                "priv_esc",
                "CRITICAL",
                2000,
                "Privilege escalation",
            ),
            Step(
                Phase.EVASION,
                "CHARLIE",
                "kill_defender",
                "CRITICAL",
                1000,
                "Security agent killed",
            ),
            Step(
                Phase.LATERAL,
                "CHARLIE",
                "wmi_exec",
                "CRITICAL",
                3000,
                "WMI exec to BRAVO",
            ),
            Step(
                Phase.IMPACT,
                "BRAVO",
                "encryption",
                "CRITICAL",
                5000,
                "File encryption detected",
            ),
        ],
    },
    "c2_beacon": {
        "name": "C2 Beacon (T1071)",
        "mitre": "T1071",
        "steps": [
            Step(
                Phase.C2, "DELTA", "dns_tunnel", "WARNING", 0, "DNS tunneling detected"
            ),
            Step(
                Phase.C2,
                "DELTA",
                "beacon_http",
                "CRITICAL",
                2000,
                "HTTP beacon every 60s",
            ),
            Step(
                Phase.IMPACT,
                "ECHO",
                "data_exfil",
                "CRITICAL",
                2000,
                "Large data exfiltration",
            ),
        ],
    },
    "supply_chain": {
        "name": "Supply Chain (T1195)",
        "mitre": "T1195",
        "steps": [
            Step(
                Phase.ACCESS,
                "BRAVO",
                "signed_binary",
                "WARNING",
                0,
                "Signed vendor binary",
            ),
            Step(
                Phase.EXEC, "BRAVO", "backdoor", "CRITICAL", 5000, "Backdoor executed"
            ),
            Step(
                Phase.PERSIST,
                "BRAVO",
                "service_install",
                "CRITICAL",
                2000,
                "Service persistence",
            ),
            Step(
                Phase.DISCOVERY,
                "BRAVO",
                "network_discovery",
                "WARNING",
                3000,
                "Network discovery",
            ),
            Step(Phase.LATERAL, "BRAVO", "ssh_keys", "CRITICAL", 4000, "SSH key theft"),
            Step(
                Phase.LATERAL,
                "ALPHA",
                "container_escape",
                "CRITICAL",
                3000,
                "Container escape",
            ),
        ],
    },
}


def inject(node, target, event, verdict):
    """Inject an event via IPC socket (preferred) or Docker exec (fallback)."""
    # Try IPC socket first — non-Docker, works on host
    ok, resp = inject_via_socket(node, target, event, verdict)
    if ok:
        return ok, resp
    # Fallback: Docker exec
    nl = node.lower()
    if not nl.startswith("neuro_"):
        nl = DOCKER_PREFIX + nl
    try:
        r = subprocess.run(
            [
                "docker",
                "exec",
                nl,
                INJECT_TOOL,
                "--node",
                target,
                "--target",
                target,
                "--event",
                event,
                "--verdict",
                verdict,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.returncode == 0, r.stdout.strip()[:80]
    except Exception:
        return False, "FAIL"


def run_scenario(name, override_node=None):
    """Run a named attack scenario against the mesh."""
    sc = SCENARIOS.get(name)
    if not sc:
        print("Unknown:", name)
        return
    print("\n" + "=" * 60)
    print("  RUNNING:", sc["name"], "(" + sc["mitre"] + ")")
    print("=" * 60)
    recording = []
    for i, s in enumerate(sc["steps"]):
        node = override_node or s.target
        print(
            "  [{}/{}] {} - {}:{} [{}]".format(
                i + 1, len(sc["steps"]), s.desc, node, s.event, s.verdict
            )
        )
        time.sleep(s.delay_ms / 1000.0)
        ok, out = inject(node, s.target, s.event, s.verdict)
        print("       -> " + ("OK" if ok else "FAIL") + "  " + out)
        recording.append(
            {
                "phase": s.phase.value,
                "target": s.target,
                "event": s.event,
                "verdict": s.verdict,
                "delay_ms": s.delay_ms,
                "desc": s.desc,
                "ts": time.time(),
                "success": ok,
            }
        )
    path = "/tmp/recording_" + name + "_" + str(int(time.time())) + ".json"
    with open(path, "w") as f:
        json.dump(recording, f, indent=2)
    print("  [+] Recording saved:", path)
    return path


def run_random(steps=5, node=None):
    """Run a random attack chain against the mesh."""
    node = node or random.choice(NODES)
    print("\n" + "=" * 60)
    print("  RANDOM ATTACK ({} steps)".format(steps))
    print("=" * 60)
    for i in range(steps):
        phase = random.choice(list(Phase))
        event = random.choice(EVENTS)
        target = random.choice(NODES)
        print("  [{}/{}] {} -> {}:{}".format(i + 1, steps, phase.value, target, event))
        time.sleep(random.uniform(0.5, 2.0))
        inject(node, target, event, "CRITICAL")


def replay(path):
    """Replay a recording from disk."""
    with open(path) as f:
        steps = json.load(f)
    print("Replaying {} steps from {}".format(len(steps), path))
    for s in steps:
        t = s.get("target", "ALPHA")
        e = s.get("event", "entropy_spike")
        v = s.get("verdict", "CRITICAL")
        d = float(s.get("delay_ms", 500)) / 1000.0
        print("  ", s.get("desc", "step"), "->", t + ":" + e)
        time.sleep(d)
        inject(t, t, e, v)
    print("[+] Replay complete")


def list_scenarios():
    """List all available attack scenarios."""
    print("Available Attack Scenarios:\n" + "=" * 60)
    for k, v in SCENARIOS.items():
        print("  {:20s}  {:30s}  ({:d} steps)".format(k, v["name"], len(v["steps"])))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["list", "run", "replay", "random"])
    p.add_argument("arg", nargs="?")
    p.add_argument("--node")
    p.add_argument("--steps", type=int, default=5)
    a = p.parse_args()
    if a.cmd == "list":
        list_scenarios()
    elif a.cmd == "run":
        run_scenario(a.arg, a.node)
    elif a.cmd == "replay":
        replay(a.arg)
    elif a.cmd == "random":
        run_random(a.steps, a.node)
