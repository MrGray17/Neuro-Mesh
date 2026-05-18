#include "cell/NodeAgent.hpp"
#include "kernel/sensor.skel.h"
#include <iostream>
#include <sys/stat.h>
#include <net/if.h>
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

    // Attach kprobes manually (tracepoints don't need an interface).
    // SEC("kprobe/...") programs attach via bpf_program__attach_kprobe.
    struct { const char* name; struct bpf_program* prog; struct bpf_link** link; } kprobes[] = {
        {"trace_execve",     m_skel->progs.trace_execve,     &m_skel->links.trace_execve},
        {"trace_sendto",     m_skel->progs.trace_sendto,     &m_skel->links.trace_sendto},
        {"trace_sendmsg",    m_skel->progs.trace_sendmsg,    &m_skel->links.trace_sendmsg},
        {"trace_connect",    m_skel->progs.trace_connect,    &m_skel->links.trace_connect},
    };
    for (auto& kp : kprobes) {
        *kp.link = bpf_program__attach(kp.prog);
        if (!*kp.link) {
            sensor_bpf__destroy(m_skel);
            m_skel = nullptr;
            return std::string("Failed to attach ") + kp.name;
        }
    }

    // Attach XDP to first available interface (eth0 → enp* → lo).
    // XDP requires an explicit ifindex — SEC("xdp") alone won't attach.
    struct { const char* name; int ifindex; } ifaces[] = {
        { "eth0", 0 }, { "lo", 0 },
    };
    for (auto& iface : ifaces) {
        iface.ifindex = if_nametoindex(iface.name);
    }
    for (auto& iface : ifaces) {
        if (iface.ifindex <= 0) continue;
        m_skel->links.xdp_neuro_mesh_dropper =
            bpf_program__attach_xdp(m_skel->progs.xdp_neuro_mesh_dropper, iface.ifindex);
        if (m_skel->links.xdp_neuro_mesh_dropper) {
            std::cout << "[EBPF] XDP dropper attached to " << iface.name
                      << " (ifindex=" << iface.ifindex << ")" << std::endl;
            break;
        }
    }
    if (!m_skel->links.xdp_neuro_mesh_dropper) {
        std::cerr << "[EBPF] Warning: could not attach XDP dropper — "
                  << "no suitable interface found. "
                  << "iptables/nftables enforcement will be used instead."
                  << std::endl;
    }

    m_ringbuf = ring_buffer__new(
        bpf_map__fd(m_skel->maps.telemetry_ringbuf),
        handle_ringbuf_event, this, nullptr);
    if (!m_ringbuf) {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;
        return "Ring buffer creation failed";
    }

    mkdir("/sys/fs/bpf/neuro_mesh", 0755);
    if (bpf_map__pin(m_skel->maps.xdp_blacklist, "/sys/fs/bpf/neuro_mesh/xdp_blacklist") != 0) {
        std::cerr << "[EBPF] Warning: could not pin xdp_blacklist map — eBPF enforcement unavailable."
                  << std::endl;
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
