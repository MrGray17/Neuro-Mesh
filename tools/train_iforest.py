"""Train an Isolation Forest on synthetic eBPF features and export to ONNX.

Generates a 5-feature model:
  [payload_entropy, payload_len, comm_entropy, null_ratio, printable_ratio]

Usage:
  python3 tools/train_iforest.py [--output isolation_forest.onnx] [--samples 10000]
"""

import argparse

import numpy as np
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import IsolationForest


def generate_synthetic_data(n_samples: int = 10000, contamination: float = 0.05):
    """Generate synthetic eBPF event features with injected anomalies.

    Normal samples mimic typical kernel events (low entropy, short payloads,
    ASCII comm names). Anomalies mimic suspicious high-entropy or binary-heavy
    events for proof-of-concept model calibration.
    """
    rng = np.random.default_rng(42)

    n_normal = int(n_samples * (1 - contamination))
    n_anomaly = n_samples - n_normal

    normal_payload_entropy = rng.uniform(0.5, 3.5, n_normal)
    normal_payload_len = rng.integers(4, 128, n_normal).astype(np.float32)
    normal_comm_entropy = rng.uniform(1.0, 3.0, n_normal)
    normal_null_ratio = rng.uniform(0.0, 0.05, n_normal)
    normal_printable = rng.uniform(0.85, 1.0, n_normal)

    x_normal = np.column_stack(
        [
            normal_payload_entropy,
            normal_payload_len,
            normal_comm_entropy,
            normal_null_ratio,
            normal_printable,
        ]
    )

    anom_payload_entropy = rng.uniform(3.5, 8.0, n_anomaly)
    anom_payload_len = rng.integers(128, 256, n_anomaly).astype(np.float32)
    anom_comm_entropy = rng.uniform(0.0, 4.5, n_anomaly)
    anom_null_ratio = rng.uniform(0.0, 0.6, n_anomaly)
    anom_printable = rng.uniform(0.1, 0.7, n_anomaly)

    x_anomaly = np.column_stack(
        [
            anom_payload_entropy,
            anom_payload_len,
            anom_comm_entropy,
            anom_null_ratio,
            anom_printable,
        ]
    )

    return np.vstack([x_normal, x_anomaly]).astype(np.float32)


def main():
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest for eBPF anomaly detection"
    )
    parser.add_argument(
        "--output", default="isolation_forest.onnx", help="Output ONNX model path"
    )
    parser.add_argument(
        "--samples", type=int, default=10000, help="Number of synthetic samples"
    )
    parser.add_argument(
        "--contamination", type=float, default=0.05, help="Expected anomaly ratio"
    )
    args = parser.parse_args()

    if args.samples < 100:
        parser.error("--samples must be at least 100")
    if not 0.0 < args.contamination < 0.5:
        parser.error("--contamination must be between 0 and 0.5")

    features = generate_synthetic_data(args.samples, args.contamination)

    print(
        f"[TRAIN] Training IsolationForest on {args.samples} samples "
        f"(features={features.shape[1]}, contamination={args.contamination})"
    )

    model = IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(features)

    scores = model.decision_function(features)
    print(f"[TRAIN] Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"[TRAIN] Score mean: {scores.mean():.4f}")
    print(f"[TRAIN] Score std:  {scores.std():.4f}")

    anomaly_count = int((scores < 0).sum())
    print(f"[TRAIN] Samples with score < 0 (anomalous): {anomaly_count}/{args.samples}")

    initial_type = [("float_input", FloatTensorType([1, 5]))]

    print("[EXPORT] Converting to ONNX...")
    onx = to_onnx(
        model,
        initial_types=initial_type,
        target_opset={"": 15, "ai.onnx.ml": 3},
    )

    serialized = onx.SerializeToString()
    with open(args.output, "wb") as file_handle:
        file_handle.write(serialized)

    print(f"[EXPORT] Model saved to {args.output} ({len(serialized)} bytes)")

    for index, output in enumerate(onx.graph.output):
        name = output.name
        shape = [dimension.dim_value for dimension in output.type.tensor_type.shape.dim]
        print(f"[VERIFY] Output[{index}]: name='{name}', shape={shape}")


if __name__ == "__main__":
    main()
