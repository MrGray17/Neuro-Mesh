# Performance Baseline — 2026-06-01

Captured via `bin/test_pbft_perf` (single-threaded PBFT state machine, no network).

## Environment

- **Machine**: Linux x86_64
- **Compiler**: clang++ -std=c++20 -O3 -DNDEBUG
- **Crypto**: OpenSSL Ed25519
- **Topology**: All nodes in-process (no UDP)

## Latency Per Round

Latency measures the wall-clock time for a complete PRE_PREPARE → all PREPARE votes (n signatures + n verifications) cycle.

| Nodes | Quorum | Avg Latency (μs) | Throughput (rounds/s) |
|-------|--------|------------------|------------------------|
| 3     | 1      | 1,926            | ~520                   |
| 4     | 3      | 3,305            | ~303                   |
| 5     | 3      | 5,290            | ~189                   |
| 7     | 5      | 10,981           | ~91                    |

## Observations

1. **Linear-ish scaling**: Latency grows roughly linearly with n (the n PREPARE messages per round dominate).
2. **Signature verification cost**: Each round requires 1 sign + n verifications. Verification is ~30μs per Ed25519 signature on this hardware.
3. **Quorum size** (f) has a smaller impact than total node count — what matters is the number of messages, not the quorum threshold.

## Notes for Future Benchmarks

- This measures the **in-process** PBFT state machine only. Real-mesh latency will be higher due to UDP broadcast/unicast.
- For end-to-end latency, use `tools/benchmark_mesh.py` against a running docker-compose stack.
- The above numbers are dominated by Ed25519 verification cost. Replacing with a faster signature scheme (e.g., BLS) would reduce them by ~5-10x.

## Reproduction

```bash
make bin/test_pbft_perf
./bin/test_pbft_perf
```

Expected output (numbers will vary by hardware):
```
PERF: PBFT consensus latency baseline
PERF: machine=linux arch=x86_64
PERF: nodes=3 rounds=50 avg_latency_us=~2000
PERF: nodes=4 rounds=50 avg_latency_us=~3000
PERF: nodes=5 rounds=50 avg_latency_us=~5000
PERF: nodes=7 rounds=50 avg_latency_us=~10000
```
