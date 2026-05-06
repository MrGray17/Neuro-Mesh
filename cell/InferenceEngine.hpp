#pragma once
#include <string>
#include <deque>
#include <unordered_set>
#include <mutex>

namespace neuro_mesh::ai {

class InferenceEngine {
public:
    explicit InferenceEngine(size_t window_size);
    
    bool analyze(const std::string& comm, const std::string& payload);
    
    // 🛡️ THE FIX: Mechanical usage for the MeshNode
    bool is_operational() const noexcept;

private:
    double calculate_entropy(const std::string& data) const;
    void update_baseline(double new_value);

    size_t m_window_size;
    double m_mean;
    double m_stddev;
    
    std::deque<double> m_entropy_history;
    std::unordered_set<std::string> m_blacklist;
    mutable std::mutex m_state_mutex;
};

} // namespace neuro_mesh::ai
