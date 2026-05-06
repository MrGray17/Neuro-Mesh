#include "cell/InferenceEngine.hpp"
#include <cmath>
#include <map>
#include <iostream>

namespace neuro_mesh::ai {

InferenceEngine::InferenceEngine(size_t window_size)
    : m_window_size(window_size), m_mean(0.0), m_stddev(0.0) {}

bool InferenceEngine::analyze(const std::string& comm, const std::string& payload) {
    double entropy = calculate_entropy(payload);

    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        if (m_blacklist.find(comm) != m_blacklist.end()) {
            return true;
        }
    }

    update_baseline(entropy);

    std::lock_guard<std::mutex> lock(m_state_mutex);
    if (m_entropy_history.size() > 10 && entropy > m_mean + 3.0 * m_stddev) {
        std::cout << "[AI] Anomaly: " << comm << " entropy=" << entropy
                  << " baseline_mean=" << m_mean << " stddev=" << m_stddev << std::endl;
        m_blacklist.insert(comm);
        return true;
    }
    return false;
}

bool InferenceEngine::is_operational() const noexcept {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_entropy_history.size() >= m_window_size / 2;
}

double InferenceEngine::calculate_entropy(const std::string& data) const {
    if (data.empty()) return 0.0;
    std::map<char, int> frequencies;
    for (char c : data) frequencies[c]++;
    double entropy = 0.0;
    int len = data.length();
    for (const auto& [c, count] : frequencies) {
        double p = static_cast<double>(count) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

void InferenceEngine::update_baseline(double new_value) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_entropy_history.push_back(new_value);
    if (m_entropy_history.size() > m_window_size) {
        m_entropy_history.pop_front();
    }

    double sum = 0.0;
    for (double v : m_entropy_history) sum += v;
    m_mean = sum / m_entropy_history.size();

    double sq_sum = 0.0;
    for (double v : m_entropy_history) sq_sum += (v - m_mean) * (v - m_mean);
    m_stddev = std::sqrt(sq_sum / m_entropy_history.size());
}

} // namespace neuro_mesh::ai
