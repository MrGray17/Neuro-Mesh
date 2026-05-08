#include "cell/NodeAgent.hpp"
#include "kernel/sensor.skel.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <cstdlib>
#include <csignal>

static_assert(sizeof(neuro_mesh::core::KernelEventData) == 280,
              "KernelEventData size mismatch between C++ and eBPF — struct layout must be identical");

namespace neuro_mesh::core {

NodeAgent::NodeAgent(std::string id)
    : m_node_id(std::move(id)),
      m_inference("/app/isolation_forest.onnx", -0.05f),
      m_enforcer(),
      m_mesh_node(m_node_id, &m_enforcer, nullptr)
{
    m_enforcer.add_safe_node(m_node_id); // Never isolate ourselves
}

NodeAgent::~NodeAgent() { trigger_shutdown(); }

NodeAgent::Result NodeAgent::create(const std::string& node_id) {
    auto cell = std::unique_ptr<NodeAgent>(new NodeAgent(node_id));
    if (!cell->load_and_attach_ebpf().empty()) return {nullptr, "eBPF Error"};
    cell->m_telemetry_thread = std::thread(&NodeAgent::telemetry_loop, cell.get());
    return {std::move(cell), ""};
}

std::string NodeAgent::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "Fail";
    sensor_bpf__attach(m_skel);
    m_ringbuf = ring_buffer__new(bpf_map__fd(m_skel->maps.telemetry_ringbuf), handle_ringbuf_event, this, nullptr);
    if (!m_ringbuf) return "Ring buffer creation failed";
    return "";
}

void NodeAgent::telemetry_loop() noexcept {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in c2_addr{};
    c2_addr.sin_family = AF_INET;
    c2_addr.sin_port = htons(9998);
    inet_pton(AF_INET, "127.0.0.1", &c2_addr.sin_addr);

    KernelEventData event;
    auto agent_boot_time = std::chrono::steady_clock::now();
    static constexpr int SYSTEM_ARMING_DELAY_SEC = 45;

    while (m_running.load()) {
        auto now = std::chrono::steady_clock::now();
        int uptime_sec = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(now - agent_boot_time).count());
        bool system_armed = (uptime_sec >= SYSTEM_ARMING_DELAY_SEC);

        // Drain the eBPF ring buffer continuously (not just one 10ms poll)
        if (m_ringbuf) {
            while (ring_buffer__poll(m_ringbuf, 0) > 0) {
                // Keep draining until empty (non-blocking with timeout=0)
            }
        }

        // Log drops if any
        size_t drops = m_internal_queue.drops();
        if (drops > 0) {
            static size_t last_reported = 0;
            if (drops > last_reported) {
                std::cerr << "[WARN] TelemetryQueue: " << (drops - last_reported)
                          << " events dropped since last tick." << std::endl;
                last_reported = drops;
            }
        }

        bool threat_this_tick = false;
        std::string mitre_ids;  // accumulates distinct MITRE ATT&CK technique IDs
        while (m_internal_queue.pop(event, m_running)) {
            if (m_inference.analyze(event.comm, event.payload)) {
                if (system_armed) {
                    threat_this_tick = true;
                    m_enforcer.suspend_process(event.pid);
                }
                // Map eBPF event_type → MITRE ATT&CK technique ID
                const char* mitre = nullptr;
                switch (event.event_type) {
                    case 1: mitre = "T1059"; break;  // Command and Scripting Interpreter
                    case 2: mitre = "T1571"; break;  // Non-Standard Port
                    case 3: mitre = "T1021"; break;  // Remote Services
                    default: break;
                }
                if (mitre) {
                    if (mitre_ids.empty()) mitre_ids = std::string("\"") + mitre + "\"";
                    else if (mitre_ids.find(mitre) == std::string::npos)
                        mitre_ids += std::string(",\"") + mitre + "\"";
                }
            }
        }

        struct sysinfo memInfo; sysinfo(&memInfo);
        long ram = (memInfo.totalram - memInfo.freeram) / (1024 * 1024);
        double loads[1]; double cpu = (getloadavg(loads, 1) != -1) ? loads[0] : 0.0;

        std::string mitre_array = mitre_ids.empty() ? "[]" : ("[" + mitre_ids + "]");
        std::string json = "{\"ID\":\"" + m_node_id + "\",\"RAM_MB\":" + std::to_string(ram) +
                           ",\"CPU_LOAD\":" + std::to_string(cpu) +
                           ",\"PROCS\":1,\"NET_OUT\":0" +
                           ",\"KERNEL_ANOMALY\":\"" + std::string(threat_this_tick ? "TRUE" : "FALSE") + "\"" +
                           ",\"STATUS\":\"" + std::string(threat_this_tick ? "SELF_ISOLATED" : "STABLE") + "\"" +
                           ",\"mitre_attack\":" + mitre_array + "}";

        std::string payload = "TELEMETRY:" + json;
        sendto(udp_sock, payload.c_str(), payload.length(), 0, (struct sockaddr*)&c2_addr, sizeof(c2_addr));

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    close(udp_sock);
}

void NodeAgent::run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* reset_flag) noexcept {
    while (m_running.load() && !shutdown_flag->load()) {
        if (reset_flag && reset_flag->load()) {
            m_enforcer.reset_enforcement();
            reset_flag->store(false);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void NodeAgent::trigger_shutdown() noexcept {
    if (m_running.exchange(false)) {
        if (m_telemetry_thread.joinable()) m_telemetry_thread.join();
        if (m_ringbuf) {
            ring_buffer__free(m_ringbuf);
            m_ringbuf = nullptr;
        }
        if (m_skel) {
            sensor_bpf__destroy(m_skel);
            m_skel = nullptr;
        }
    }
}

void NodeAgent::reset_cell() noexcept {
    m_enforcer.reset_enforcement();
    std::cout << "[CELL] Enforcement reset." << std::endl;
}

int NodeAgent::handle_ringbuf_event(void *ctx, void *data, size_t) {
    auto* self = static_cast<NodeAgent*>(ctx);
    self->m_internal_queue.push(*(static_cast<KernelEventData*>(data)));
    return 0;
}

} // namespace neuro_mesh::core
