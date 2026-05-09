#include "cell/NodeAgent.hpp"
#include "kernel/sensor.skel.h"
#include <iostream>
#include <bpf/libbpf.h>

static_assert(sizeof(neuro_mesh::core::KernelEventData) == 280,
              "KernelEventData size mismatch between C++ and eBPF — struct layout must be identical");

namespace neuro_mesh::core {

NodeAgent::NodeAgent(std::string id)
    : m_node_id(std::move(id))
{}

NodeAgent::~NodeAgent() {
    if (m_ringbuf) {
        ring_buffer__free(m_ringbuf);
        m_ringbuf = nullptr;
    }
    if (m_skel) {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;
    }
}

NodeAgent::Result NodeAgent::create(const std::string& node_id) {
    auto agent = std::unique_ptr<NodeAgent>(new NodeAgent(node_id));
    std::string err = agent->load_and_attach_ebpf();
    if (!err.empty()) {
        return {nullptr, err};
    }
    agent->m_loaded = true;
    std::cout << "[EBPF] Sensor probes attached — execve/sendto/connect tracepoints live." << std::endl;
    return {std::move(agent), ""};
}

std::string NodeAgent::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "Failed to open/load eBPF skeleton";

    if (sensor_bpf__attach(m_skel) != 0) {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;
        return "Failed to attach eBPF probes";
    }

    m_ringbuf = ring_buffer__new(
        bpf_map__fd(m_skel->maps.telemetry_ringbuf),
        handle_ringbuf_event, this, nullptr);
    if (!m_ringbuf) {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;
        return "Ring buffer creation failed";
    }

    return "";
}

std::vector<KernelEventData> NodeAgent::poll_events() {
    std::vector<KernelEventData> events;

    // Drain the eBPF ring buffer into the queue (non-blocking)
    if (m_ringbuf) {
        while (ring_buffer__poll(m_ringbuf, 0) > 0) {
            // handle_ringbuf_event pushes into m_queue
        }
    }

    // Drain the queue
    KernelEventData event;
    while (m_queue.pop(event)) {
        events.push_back(std::move(event));
    }

    return events;
}

int NodeAgent::handle_ringbuf_event(void *ctx, void *data, size_t) {
    auto* self = static_cast<NodeAgent*>(ctx);
    self->m_queue.push(*static_cast<KernelEventData*>(data));
    return 0;
}

} // namespace neuro_mesh::core
