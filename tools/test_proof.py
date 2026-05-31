#!/usr/bin/env python3
"""
Neuro-Mesh proof chain verifier.
Loads a .proof file and verifies the hash chain integrity.

Usage:
  python3 tools/test_proof.py /tmp/neuro_proof_ALPHA.proof
"""

import hashlib
import json
import sys


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def verify_proof_file(path):
    with open(path) as f:
        data = json.load(f)

    links = data.get("links", [])
    node = data.get("node_id", "unknown")
    print("Proof Chain: {} ({:d} links)".format(node, len(links)))

    errors = []
    for i, link in enumerate(links):
        seq = link["seq"]
        canonical = "|".join(
            [
                str(link["seq"]),
                str(link["event"]),
                link["node"],
                link["target"],
                link["data_hash"],
                link["parent_hash"],
            ]
        )
        expected = sha256_hex(canonical)
        if expected != link["link_hash"]:
            errors.append(
                "  LINK {:d}: hash mismatch (expected {} != {})".format(
                    seq, expected[:16], link["link_hash"][:16]
                )
            )
        if i > 0:
            prev = links[i - 1]["link_hash"]
            if link["parent_hash"] != prev:
                errors.append("  LINK {:d}: parent mismatch".format(seq))
    if errors:
        print("FAILED:")
        for e in errors:
            print(e)
        return False
    else:
        print("ALL {:d} LINKS VERIFIED".format(len(links)))
        if links:
            print("  Root hash:", sha256_hex(links[-1]["link_hash"])[:32])
        return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tools/test_proof.py <proof_file>")
        sys.exit(1)
    ok = verify_proof_file(sys.argv[1])
    sys.exit(0 if ok else 1)
