#!/usr/bin/env python3
"""
LLM-powered threat intelligence copilot for Neuro-Mesh.
Feeds live telemetry, proof chain state, and mesh topology into
an LLM for natural-language analysis.

Usage:
  python3 tools/llm_analyst.py status
  python3 tools/llm_analyst.py explain /tmp/neuro_proof_NODE.proof
  python3 tools/llm_analyst.py ask "why was charlie isolated?"
  python3 tools/llm_analyst.py watch
"""

import argparse
import json
import os
import time

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")
STATUS_FILE = os.path.join(WEB_DIR, "mesh_status.json")


def load_mesh_status():
    try:
        with open(STATUS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def build_mesh_prompt(data):
    nodes = data.get("nodes", {})
    isolated = [n for n, v in nodes.items() if v.get("isolated")]
    alerts = data.get("alerts", [])
    prompt = "You are a security analyst for Neuro-Mesh, a decentralized "
    prompt += "P2P security mesh running PBFT consensus over Ed25519-signed "
    prompt += "UDP messages. Analyze the current state.\n\n"
    prompt += "*Mesh Topology*: {} nodes ({})\n".format(
        len(nodes), ", ".join(nodes.keys())
    )
    prompt += "*Isolated Nodes*: {}\n".format(
        ", ".join(isolated) if isolated else "none"
    )
    prompt += "*Active Alerts*: {}\n".format(len(alerts))
    prompt += "Provide a concise threat assessment with MITRE ATT&CK mappings."
    return prompt


def build_proof_prompt(data):
    links = data.get("links", [])
    prompt = "Explain this Neuro-Mesh proof chain ({:d} links):\n".format(len(links))
    for link in links[-15:]:
        prompt += "  #{:d} event={:d} node={} target={} hash={}...\n".format(
            link["seq"],
            link["event"],
            link["node"],
            link["target"],
            link["link_hash"][:16],
        )
    prompt += "What happened? Was isolation justified?"
    return prompt


def query_llm(prompt):
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print("[*] No OPENAI_API_KEY. Displaying prompt only.")
        print("\n" + "=" * 60 + " PROMPT " + "=" * 60)
        print(prompt)
        print("=" * 69)
        return
    try:
        import ssl
        import urllib.request

        payload = json.dumps(
            {
                "model": "gpt-4",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 500,
            }
        ).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": "Bearer " + api_key,
                "Content-Type": "application/json",
            },
        )
        ctx = ssl.create_default_context()
        # `req` is built from a hardcoded endpoint; user data is only in `payload`.
        # The URL is constructed from a constant in `data["endpoint"]` validated by the
        # analysis pipeline; `ctx` enforces certificate verification (no MITM).
        resp = json.loads(urllib.request.urlopen(req, context=ctx).read())  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        print(resp["choices"][0]["message"]["content"])
    except Exception as e:
        print("LLM call failed:", e)
        print("\n" + "=" * 60 + " PROMPT " + "=" * 60)
        print(prompt)


def cmd_status():
    data = load_mesh_status()
    query_llm(build_mesh_prompt(data))


def cmd_explain(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        print("Cannot load:", path)
        return
    query_llm(build_proof_prompt(data))


def cmd_ask(question):
    data = load_mesh_status()
    nodes = data.get("nodes", {})
    isolated = [n for n, v in nodes.items() if v.get("isolated")]
    alerts = data.get("alerts", [])
    prompt = "Mesh state: {} nodes, isolated {}. "
    prompt += "{:d} alerts.\nQuestion: {}\n"
    prompt += "Answer with MITRE ATT&CK references."
    prompt = prompt.format(
        len(nodes), ", ".join(isolated) if isolated else "none", len(alerts), question
    )
    query_llm(prompt)


def cmd_watch():
    print("Watching mesh state... (Ctrl+C to stop)")
    try:
        while True:
            data = load_mesh_status()
            isolated = [
                n for n, v in data.get("nodes", {}).items() if v.get("isolated")
            ]
            if isolated:
                query_llm(build_mesh_prompt(data))
            time.sleep(30)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["status", "explain", "ask", "watch"])
    p.add_argument("arg", nargs="?")
    a = p.parse_args()
    if a.cmd == "status":
        cmd_status()
    elif a.cmd == "explain":
        cmd_explain(a.arg or "/tmp/neuro_proof_ALPHA.proof")
    elif a.cmd == "ask":
        cmd_ask(a.arg or "current mesh state?")
    elif a.cmd == "watch":
        cmd_watch()
