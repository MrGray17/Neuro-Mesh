#include "cell/SovereignCell.hpp"
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

SovereignCell::SovereignCell(std::string id)
    : m_node_id(std::move(id)), m_brain(100), m_jailer(), m_mesh_node(m_node_id, &m_jailer, nullptr)
{
    m_jailer.add_safe_node(m_node_id); // Never isolate ourselves
}

SovereignCell::~SovereignCell() { trigger_shutdown(); }

SovereignCell::Result SovereignCell::create(const std::string& node_id) {
    auto cell = std::unique_ptr<SovereignCell>(new SovereignCell(node_id));
    if (!cell->load_and_attach_ebpf().empty()) return {nullptr, "eBPF Error"};
    cell->m_telemetry_thread = std::thread(&SovereignCell::telemetry_loop, cell.get());
    return {std::move(cell), ""};
}

std::string SovereignCell::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "Fail";
    sensor_bpf__attach(m_skel);
    m_ringbuf = ring_buffer__new(bpf_map__fd(m_skel->maps.telemetry_ringbuf), handle_ringbuf_event, this, nullptr);
    if (!m_ringbuf) return "Ring buffer creation failed";
    return "";
}

void SovereignCell::telemetry_loop() noexcept {
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
        while (m_internal_queue.pop(event, m_running)) {
            if (m_brain.analyze(event.comm, event.payload)) {
                if (system_armed) {
                    threat_this_tick = true;
                    m_jailer.imprison(event.pid);
                }
            }
        }

        struct sysinfo memInfo; sysinfo(&memInfo);
        long ram = (memInfo.totalram - memInfo.freeram) / (1024 * 1024);
        double loads[1]; double cpu = (getloadavg(loads, 1) != -1) ? loads[0] : 0.0;

        std::string json = "{\"ID\":\"" + m_node_id + "\",\"RAM_MB\":" + std::to_string(ram) +
                           ",\"CPU_LOAD\":" + std::to_string(cpu) +
                           ",\"PROCS\":1,\"NET_OUT\":0" +
                           ",\"KERNEL_THREAT\":\"" + std::string(threat_this_tick ? "TRUE" : "FALSE") + "\"" +
                           ",\"STATUS\":\"" + std::string(threat_this_tick ? "SELF_ISOLATED" : "STABLE") + "\"}";

        std::string payload = "TELEMETRY:" + json;
        sendto(udp_sock, payload.c_str(), payload.length(), 0, (struct sockaddr*)&c2_addr, sizeof(c2_addr));

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    close(udp_sock);
}

void SovereignCell::run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* vaccine_flag) noexcept {
    while (m_running.load() && !shutdown_flag->load()) {
        if (vaccine_flag && vaccine_flag->load()) {
            m_jailer.eradicate_threats();
            vaccine_flag->store(false);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void SovereignCell::trigger_shutdown() noexcept {
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

void SovereignCell::vaccinate() noexcept {
    m_jailer.eradicate_threats();
    std::cout << "[CELL] Vaccine applied. Threats eradicated." << std::endl;
}

int SovereignCell::handle_ringbuf_event(void *ctx, void *data, size_t) {
    auto* self = static_cast<SovereignCell*>(ctx);
    self->m_internal_queue.push(*(static_cast<KernelEventData*>(data)));
    return 0;
}

} // namespace neuro_mesh::core
