#include "telemetry/AuditLogger.hpp"
#include "common/UniqueFD.hpp"
#include <iostream>
#include <chrono>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace neuro_mesh::telemetry {

static UniqueFD s_udp_socket; // RAII-managed static socket

void AuditLogger::initialize() {
    s_udp_socket = UniqueFD(socket(AF_INET, SOCK_DGRAM, 0));
}

void AuditLogger::emit_json(AuditLevel level, const std::string& component,
                            const std::string& action, const std::string& target,
                            const std::string& details) {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::string lvl_str;
    switch (level) {
        case AuditLevel::CRITICAL:       lvl_str = "CRITICAL"; break;
        case AuditLevel::DEFENSE_ACTION: lvl_str = "DEFENSE_ACTION"; break;
        case AuditLevel::WARNING:        lvl_str = "WARNING"; break;
        default:                         lvl_str = "INFO"; break;
    }

    std::string json = "{\"type\":\"EVENT\",\"timestamp\":" + std::to_string(ms) +
                       ",\"level\":\"" + lvl_str + "\"" +
                       ",\"component\":\"" + component + "\"" +
                       ",\"action\":\"" + action + "\"" +
                       ",\"target\":\"" + target + "\"" +
                       ",\"details\":\"" + details + "\"}";

    std::cout << json << std::endl;

    if (s_udp_socket.valid()) {
        struct sockaddr_in servaddr{};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(50052);
        inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
        sendto(s_udp_socket.get(), json.c_str(), json.length(), 0,
               (const struct sockaddr*)&servaddr, sizeof(servaddr));
    }
}

void AuditLogger::emit_metric(double cpu_percent, double ram_mb, int active_agents) {
    std::string json = "{\"type\":\"METRIC\",\"cpu\":" + std::to_string(cpu_percent) +
                       ",\"ram\":" + std::to_string(ram_mb) +
                       ",\"agents\":" + std::to_string(active_agents) + "}";

    if (s_udp_socket.valid()) {
        struct sockaddr_in servaddr{};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(50052);
        inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
        sendto(s_udp_socket.get(), json.c_str(), json.length(), 0,
               (const struct sockaddr*)&servaddr, sizeof(servaddr));
    }
}

} // namespace neuro_mesh::telemetry
