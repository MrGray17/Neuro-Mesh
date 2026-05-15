#pragma once
#include <atomic>
#include <string>
#include <vector>
#include <memory>
#include <onnxruntime_cxx_api.h>

namespace neuro_mesh::ai {

class InferenceEngine {
public:
    // model_path: path to isolation_forest.onnx
    // threshold:  score below this value → anomalous (default -0.05 for IsolationForest)
    //             more negative = more conservative
    InferenceEngine(const std::string& model_path, float threshold = -0.05f);

    // Returns true when an anomaly is detected.
    // Called from the eBPF telemetry loop — must not allocate on the heap.
    bool analyze(const std::string& comm, const std::string& payload);

    bool is_operational() const noexcept;

    // Last anomaly score from analyze() — thread-safe, read by heartbeat loop
    float last_score() const noexcept { return m_last_score.load(std::memory_order_relaxed); }
    const char* last_threat() const noexcept {
        return m_last_score.load(std::memory_order_relaxed) < m_threshold ? "CRITICAL" : "NONE";
    }

    // Decay the anomaly score toward 0 (normal) by `factor` each call.
    // Called from heartbeat loop when no eBPF events arrive, preventing
    // sticky CRITICAL state after the anomalous traffic stops.
    void decay(float factor = 0.5f) noexcept {
        float current = m_last_score.load(std::memory_order_relaxed);
        if (current < 0.0f) {
            m_last_score.store(current * (1.0f - factor), std::memory_order_relaxed);
        }
    }

    // Static utility for testing - compute Shannon entropy
    static double compute_entropy(const char* data, size_t len) noexcept;

private:
    // Extract 5 features into the pre-allocated m_input buffer
    void extract_features(const std::string& comm, const std::string& payload) noexcept;

    Ort::Env m_env;
    Ort::SessionOptions m_session_opts;
    std::unique_ptr<Ort::Session> m_session;
    Ort::MemoryInfo m_memory_info;

    // Pre-allocated — zero heap allocations in analyze()
    std::vector<float> m_input;            // [5] feature vector
    std::vector<int64_t> m_input_shape;    // [1, 5]
    std::string m_output_name;             // name of the score output tensor

    float m_threshold;
    bool m_loaded;
    std::atomic<float> m_last_score{0.0f};
};

} // namespace neuro_mesh::ai
