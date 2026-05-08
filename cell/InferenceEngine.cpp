#include "cell/InferenceEngine.hpp"
#include <cmath>
#include <iostream>
#include <stdexcept>

namespace neuro_mesh::ai {

InferenceEngine::InferenceEngine(const std::string& model_path, float threshold)
    : m_env(ORT_LOGGING_LEVEL_WARNING, "neuro_mesh"),
      m_memory_info(Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)),
      m_input(5, 0.0f),
      m_input_shape({1, 5}),
      m_threshold(threshold),
      m_loaded(false)
{
    m_session_opts.SetIntraOpNumThreads(1);
    m_session_opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);

    try {
        m_session = std::make_unique<Ort::Session>(m_env, model_path.c_str(), m_session_opts);

        size_t n_inputs = m_session->GetInputCount();
        size_t n_outputs = m_session->GetOutputCount();
        if (n_inputs != 1) {
            throw std::runtime_error(
                "Model input mismatch: expected 1, got " + std::to_string(n_inputs));
        }
        if (n_outputs < 1) {
            throw std::runtime_error("Model has no outputs");
        }

        // IsolationForest ONNX exports both 'label' and 'scores'.
        // Find the 'scores' output index (decision_function values).
        int score_idx = 0;
        {
            Ort::AllocatorWithDefaultOptions alloc;
            for (size_t i = 0; i < n_outputs; ++i) {
                auto name_ptr = m_session->GetOutputNameAllocated(i, alloc);
                if (std::string(name_ptr.get()) == "scores") {
                    score_idx = static_cast<int>(i);
                }
            }
        }

        // Store the score output name for use in analyze()
        {
            Ort::AllocatorWithDefaultOptions alloc;
            auto name_ptr = m_session->GetOutputNameAllocated(score_idx, alloc);
            m_output_name = name_ptr.get();
        }

        m_loaded = true;
        std::cout << "[AI] ONNX model loaded: " << model_path
                  << " (threshold=" << m_threshold
                  << ", outputs=" << n_outputs
                  << ", score_idx=" << score_idx << ")" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[AI] FATAL: Failed to load ONNX model '" << model_path
                  << "': " << e.what() << std::endl;
        throw;
    }
}

bool InferenceEngine::analyze(const std::string& comm, const std::string& payload) {
    if (!m_loaded) return false;

    // 1. Extract features into pre-allocated m_input (zero heap alloc)
    extract_features(comm, payload);

    // 2. Create input tensor pointing to pre-allocated memory
    const char* input_names[] = {"float_input"};
    auto input_tensor = Ort::Value::CreateTensor<float>(
        m_memory_info,
        m_input.data(),
        m_input.size(),
        m_input_shape.data(),
        m_input_shape.size());

    // 3. Run inference
    const char* output_names[] = {m_output_name.c_str()};
    auto outputs = m_session->Run(
        Ort::RunOptions{nullptr},
        input_names, &input_tensor, 1,
        output_names, 1);

    // 4. Extract anomaly score
    float* scores = outputs[0].GetTensorMutableData<float>();
    float score = scores[0];

    m_last_score.store(score, std::memory_order_relaxed);
    return score < m_threshold;
}

bool InferenceEngine::is_operational() const noexcept {
    return m_loaded;
}

double InferenceEngine::compute_entropy(const char* data, size_t len) noexcept {
    if (len == 0) return 0.0;

    int freq[256] = {0};  // stack allocation, no heap
    for (size_t i = 0; i < len; ++i) {
        freq[static_cast<unsigned char>(data[i])]++;
    }

    double entropy = 0.0;
    double inv_len = 1.0 / static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) * inv_len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

void InferenceEngine::extract_features(const std::string& comm, const std::string& payload) noexcept {
    // Feature 0: payload entropy
    m_input[0] = static_cast<float>(compute_entropy(payload.data(), payload.size()));

    // Feature 1: payload length
    m_input[1] = static_cast<float>(payload.size());

    // Feature 2: comm entropy
    m_input[2] = static_cast<float>(compute_entropy(comm.data(), comm.size()));

    // Feature 3: null byte ratio in payload
    size_t nulls = 0;
    for (char c : payload) {
        if (c == '\0') ++nulls;
    }
    m_input[3] = payload.empty() ? 0.0f : static_cast<float>(nulls) / static_cast<float>(payload.size());

    // Feature 4: printable ASCII ratio in payload
    size_t printable = 0;
    for (char c : payload) {
        if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) <= 0x7E) {
            ++printable;
        }
    }
    m_input[4] = payload.empty() ? 0.0f : static_cast<float>(printable) / static_cast<float>(payload.size());
}

} // namespace neuro_mesh::ai
