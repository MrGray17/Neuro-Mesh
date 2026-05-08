// ============================================================
// NEURO-MESH : NODE AGENT (LOCK-FREE EDITION)
// ============================================================
#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "cell/InferenceEngine.hpp"
#include "consensus/MeshNode.hpp"
#include "enforcer/PolicyEnforcer.hpp"

struct ring_buffer;
struct sensor_bpf;

namespace neuro_mesh::core {

// Domain Entity
struct KernelEventData {
    uint32_t pid;
    uint32_t event_type;
    char comm[16];
    char payload[256];
};

// Thread-safe Multi-Producer Single-Consumer Queue
template<typename T>
class TelemetryQueue {
public:
    void push(T event) noexcept {
        std::lock_guard<std::mutex> lock(m_mux);
        if (m_queue.size() < m_max_size) {
            m_queue.push(std::move(event));
            m_cv.notify_one();
        } else {
            // Ring-buffer semantics: drop oldest to make room, track loss
            m_queue.pop();
            m_queue.push(std::move(event));
            m_drops++;
        }
    }

    bool pop(T& out, std::atomic<bool>& running) noexcept {
        std::unique_lock<std::mutex> lock(m_mux);
        m_cv.wait_for(lock, std::chrono::milliseconds(50), [&]{
            return !m_queue.empty() || !running.load();
        });
        if (m_queue.empty()) return false;
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    [[nodiscard]] size_t drops() const noexcept {
        std::lock_guard<std::mutex> lock(m_mux);
        return m_drops;
    }

private:
    std::queue<T> m_queue;
    mutable std::mutex m_mux;
    std::condition_variable m_cv;
    static constexpr size_t m_max_size = 5000;
    size_t m_drops = 0;
};

class NodeAgent {
public:
    struct Result {
        std::unique_ptr<NodeAgent> cell;
        std::string error;
    };

    static Result create(const std::string& node_id);
    ~NodeAgent();

    void run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* reset_flag) noexcept;
    void trigger_shutdown() noexcept;
    void reset_cell() noexcept;

private:
    explicit NodeAgent(std::string id);
    std::string load_and_attach_ebpf();
    static int handle_ringbuf_event(void *ctx, void *data, size_t size);
    
    void telemetry_loop() noexcept;

    std::string m_node_id;
    std::atomic<bool> m_running{true};
    std::thread m_telemetry_thread;

    TelemetryQueue<KernelEventData> m_internal_queue;

    ai::InferenceEngine m_inference;
    PolicyEnforcer m_enforcer;
    MeshNode m_mesh_node;

    sensor_bpf* m_skel = nullptr;
    ring_buffer* m_ringbuf = nullptr;

    std::atomic<std::chrono::steady_clock::time_point> m_immunity_until{std::chrono::steady_clock::now()};
};

} // namespace neuro_mesh::core
