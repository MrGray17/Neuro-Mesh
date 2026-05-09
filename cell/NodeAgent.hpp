// ============================================================
// NEURO-MESH : NODE AGENT — eBPF SENSOR MANAGER
// ============================================================
// Owns the eBPF skeleton, ring buffer, and thread-safe event queue.
// The canonical telemetry path (heartbeat_loop in main.cpp) polls
// events via poll_events() and feeds them to the shared InferenceEngine.
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
#include <vector>

struct ring_buffer;
struct sensor_bpf;

namespace neuro_mesh::core {

// Domain Entity — must match struct KernelEvent in kernel/sensor.bpf.c
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
            m_queue.pop();
            m_queue.push(std::move(event));
            m_drops++;
        }
    }

    bool pop(T& out) noexcept {
        std::unique_lock<std::mutex> lock(m_mux);
        if (m_queue.empty()) return false;
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    bool empty() const noexcept {
        std::lock_guard<std::mutex> lock(m_mux);
        return m_queue.empty();
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
        std::unique_ptr<NodeAgent> agent;
        std::string error;
    };

    // Load eBPF skeleton, attach probes, create ring buffer.
    // Returns nullptr + error on failure.
    static Result create(const std::string& node_id);

    ~NodeAgent();

    // ---- eBPF event polling (called from heartbeat_loop) ----

    // Drain the ring buffer and return all pending events.
    // Call this on each heartbeat tick before computing entropy.
    std::vector<KernelEventData> poll_events();

    // True if eBPF probes are loaded and operational
    bool is_operational() const noexcept { return m_skel != nullptr && m_ringbuf != nullptr; }

private:
    explicit NodeAgent(std::string id);

    std::string load_and_attach_ebpf();
    static int handle_ringbuf_event(void *ctx, void *data, size_t size);

    std::string m_node_id;
    TelemetryQueue<KernelEventData> m_queue;

    sensor_bpf*   m_skel    = nullptr;
    ring_buffer*  m_ringbuf = nullptr;
    bool          m_loaded  = false;
};

} // namespace neuro_mesh::core
