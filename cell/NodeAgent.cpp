#include "cell/NodeAgent.hpp"
#include "kernel/sensor.skel.h"
#include <iostream>
#include <sys/stat.h>
#include <sys/resource.h>
#include <net/if.h>
#include <dirent.h>
#include <unordered_set>
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
    // Bump RLIMIT_MEMLOCK explicitly so libbpf's "Failed to bump RLIMIT_MEMLOCK"
    // warning is suppressed when we have privilege. Non-root users cannot raise
    // the soft limit above the hard limit (returns EPERM silently), but
    // pre-existing high limits still work.
    struct rlimit rl{};
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        const rlim_t desired = 64UL * 1024 * 1024;
        if (rl.rlim_cur < desired) {
            rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > desired) ? desired : rl.rlim_max;
            (void)setrlimit(RLIMIT_MEMLOCK, &rl);
        }
    }

    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) {
        // Produce an actionable error. The three common root causes:
        //   1. unprivileged_bpf_disabled=2 (kernel 5.8+ default) without CAP_BPF
        //   2. Container without --cap-add=CAP_BPF,CAP_PERFMON or --privileged
        //   3. RLIMIT_MEMLOCK < required (already addressed above; informational)
        std::string err = "Failed to open/load eBPF skeleton — ";
        if (getuid() != 0) {
            FILE* f = std::fopen("/proc/sys/kernel/unprivileged_bpf_disabled", "r");
            int unpriv = 0;
            if (f) { int _r = std::fscanf(f, "%d", &unpriv); (void)_r; std::fclose(f); }
            if (unpriv >= 1) {
                err += std::string("kernel has unprivileged_bpf_disabled=")
                     + std::to_string(unpriv)
                     + " and we are not root. Run as root, grant CAP_BPF+CAP_PERFMON, "
                       "or use --privileged in Docker. Falling back to /proc/net/dev entropy.";
            } else {
                err += std::string("bpf() syscall returned EPERM. Run as root or with "
                                   "--cap-add=CAP_BPF,CAP_PERFMON. "
                                   "Falling back to /proc/net/dev entropy.");
            }
        } else {
            err += std::string("bpf() syscall failed. Check dmesg for verifier errors. "
                               "Falling back to /proc/net/dev entropy.");
        }
        return err;
    }

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

    // Attach XDP to first available interface.
    // Priority: NEURO_XDP_IFACE env var → /sys/class/net/ scan → eth0 → lo.
    // XDP requires an explicit ifindex — SEC("xdp") alone won't attach.
    std::vector<const char*> iface_names;

    // Check for explicit interface override
    if (const char* env = std::getenv("NEURO_XDP_IFACE")) {
        iface_names.push_back(env);
    }

    // Scan /sys/class/net/ for all available interfaces
    if (auto* dir = opendir("/sys/class/net/")) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            iface_names.push_back(entry->d_name);
        }
        closedir(dir);
    }

    // Fallback to hardcoded defaults
    iface_names.push_back("eth0");
    iface_names.push_back("lo");

    // Deduplicate while preserving order
    std::vector<std::string> unique_ifaces;
    std::unordered_set<std::string> seen;
    for (const char* name : iface_names) {
        if (seen.insert(name).second) {
            unique_ifaces.push_back(name);
        }
    }

    for (const auto& name : unique_ifaces) {
        int ifindex = if_nametoindex(name.c_str());
        if (ifindex <= 0) continue;
        m_skel->links.xdp_neuro_mesh_dropper =
            bpf_program__attach_xdp(m_skel->progs.xdp_neuro_mesh_dropper, ifindex);
        if (m_skel->links.xdp_neuro_mesh_dropper) {
            std::cout << "[EBPF] XDP dropper attached to " << name
                      << " (ifindex=" << ifindex << ")" << std::endl;
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

    std::string map_dir = "/sys/fs/bpf/neuro_mesh_" + m_node_id;
    mkdir(map_dir.c_str(), 0755);
    std::string map_path = map_dir + "/xdp_blacklist";
    if (bpf_map__pin(m_skel->maps.xdp_blacklist, map_path.c_str()) != 0) {
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
