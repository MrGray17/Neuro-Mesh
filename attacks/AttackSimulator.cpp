#include "attacks/AttackSimulator.hpp"
#include <random>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <unordered_set>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace neuro_mesh::attacks {

namespace {

} // namespace

AttackOrchestrator::AttackOrchestrator() = default;
AttackOrchestrator::~AttackOrchestrator() = default;

void AttackOrchestrator::load_scenarios(const std::vector<AttackScenario>& scenarios) {
    m_scenarios = scenarios;
}

void AttackOrchestrator::register_atomic_attack(const AtomicAttack& attack) {
    m_atomic_attacks[attack.attack_id] = attack;
}

std::vector<AttackScenario> AttackOrchestrator::get_available_scenarios() const {
    return m_scenarios;
}

std::vector<AttackScenario> AttackOrchestrator::get_scenarios_by_phase(AttackPhase phase) const {
    std::vector<AttackScenario> result;
    for (const auto& s : m_scenarios) {
        if (s.phase == phase) result.push_back(s);
    }
    return result;
}

std::vector<AttackScenario> AttackOrchestrator::get_scenarios_by_technique(AttackTechnique technique) const {
    std::vector<AttackScenario> result;
    for (const auto& s : m_scenarios) {
        if (s.technique == technique) result.push_back(s);
    }
    return result;
}

AttackResult AttackOrchestrator::execute_scenario(const std::string& scenario_id) {
    AttackResult result;
    result.scenario_id = scenario_id;
    result.start_time = std::chrono::system_clock::now();
    result.execution_successful = false;

    auto it = std::find_if(m_scenarios.begin(), m_scenarios.end(),
        [&](const AttackScenario& s) { return s.scenario_id == scenario_id; });

    if (it == m_scenarios.end()) {
        result.error_message = "Scenario not found: " + scenario_id;
        result.detection = DetectionResult::ALLOWED;
        result.end_time = std::chrono::system_clock::now();
        if (m_detection_callback) m_detection_callback(result);
        m_results.push_back(result);
        return result;
    }

    bool attack_ok = execute_attack(*it, result);
    result.execution_successful = attack_ok;
    result.end_time = std::chrono::system_clock::now();

    if (!attack_ok && result.error_message.empty()) {
        result.error_message = "Attack execution failed";
    }

    if (m_detection_callback) m_detection_callback(result);
    m_results.push_back(result);
    return result;
}

std::vector<AttackResult> AttackOrchestrator::execute_campaign(const std::vector<std::string>& scenario_ids) {
    std::vector<AttackResult> results;
    for (const auto& id : scenario_ids) {
        results.push_back(execute_scenario(id));
    }
    return results;
}

DetectionMetrics AttackOrchestrator::calculate_metrics(const std::string& scenario_id) const {
    DetectionMetrics metrics{};
    metrics.total_attempts = 0;
    metrics.detected_count = 0;
    metrics.blocked_count = 0;
    metrics.allowed_count = 0;
    metrics.detection_rate_percent = 0.0;
    metrics.block_rate_percent = 0.0;

    std::chrono::milliseconds total_detection_time{0};
    int detected_with_time = 0;

    for (const auto& r : m_results) {
        if (r.scenario_id != scenario_id) continue;
        ++metrics.total_attempts;

        if (r.detection == DetectionResult::DETECTED) {
            ++metrics.detected_count;
            auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(r.end_time - r.start_time);
            total_detection_time += dt;
            ++detected_with_time;
        } else if (r.detection == DetectionResult::BLOCKED) {
            ++metrics.blocked_count;
        } else if (r.detection == DetectionResult::ALLOWED) {
            ++metrics.allowed_count;
        }
    }

    if (metrics.total_attempts > 0) {
        metrics.detection_rate_percent = 100.0 * static_cast<double>(metrics.detected_count) / metrics.total_attempts;
        metrics.block_rate_percent = 100.0 * static_cast<double>(metrics.blocked_count) / metrics.total_attempts;
    }

    if (detected_with_time > 0) {
        metrics.avg_detection_time = total_detection_time / detected_with_time;
    }

    return metrics;
}

std::vector<DetectionMetrics> AttackOrchestrator::calculate_all_metrics() const {
    std::unordered_set<std::string> scenario_ids;
    for (const auto& r : m_results) {
        scenario_ids.insert(r.scenario_id);
    }
    std::vector<DetectionMetrics> all;
    for (const auto& id : scenario_ids) {
        all.push_back(calculate_metrics(id));
    }
    return all;
}

void AttackOrchestrator::set_detection_callback(std::function<void(const AttackResult&)> callback) {
    m_detection_callback = std::move(callback);
}

void AttackOrchestrator::set_defense_callback(std::function<void(const std::string&, const std::string&)> callback) {
    m_defense_callback = std::move(callback);
}

double AttackOrchestrator::get_overall_detection_rate() const {
    return 0.0;
}

std::vector<std::string> AttackOrchestrator::get_undetected_techniques() const {
    return {};
}

bool AttackOrchestrator::execute_attack(const AttackScenario& scenario, AttackResult& result) {
    auto it = m_atomic_attacks.find(scenario.scenario_id);
    if (it == m_atomic_attacks.end()) {
        result.error_message = "No atomic attack registered for " + scenario.scenario_id;
        return false;
    }

    bool ok = false;
    try {
        ok = it->second.executor();
    } catch (const std::exception& e) {
        result.error_message = e.what();
        result.detection = DetectionResult::ALLOWED;
        return false;
    }

    if (ok && it->second.telemetry_generator) {
        result.telemetry_captured = it->second.telemetry_generator();
    }

    result.detection = ok ? DetectionResult::DETECTED : DetectionResult::ALLOWED;
    return ok;
}

std::map<std::string, std::string> AttackOrchestrator::capture_telemetry() {
    return {};
}

ThreatSimulator::ThreatSimulator() = default;
ThreatSimulator::~ThreatSimulator() = default;

bool ThreatSimulator::simulate_network_attack(const std::string& target_ip, int target_port,
                                               const std::string& attack_type) {
    std::vector<uint8_t> payload(1024, 0x41);
    if (attack_type == "syn_flood") {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(target_port));
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        struct timeval tv = {0, 100000};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
        return true;
    }
    if (attack_type == "udp_flood") {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return false;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(target_port));
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        sendto(sock, payload.data(), payload.size(), 0, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
        return true;
    }
    if (attack_type == "malicious_payload") {
        return send_malicious_packet(target_ip, target_port, payload);
    }
    return false;
}

bool ThreatSimulator::simulate_endpoint_attack(const std::string& target_process,
                                                 const std::string& attack_type) {
    if (m_process_injector && !target_process.empty()) {
        return m_process_injector(0, attack_type);
    }
    return false;
}

bool ThreatSimulator::simulate_lateral_movement(const std::string& source_node,
                                                  const std::string& target_node,
                                                  const std::string& technique) {
    if (m_network_injector) {
        std::string payload = "LATERAL|" + source_node + "|" + technique;
        std::vector<uint8_t> data(payload.begin(), payload.end());
        return m_network_injector(target_node, data);
    }
    return false;
}

bool ThreatSimulator::simulate_credential_theft(const std::string& target_user,
                                                 const std::string& method) {
    (void)target_user;
    (void)method;
    return false;
}

bool ThreatSimulator::simulate_data_exfiltration(const std::string& data_path,
                                                  const std::string& exfil_method) {
    (void)data_path;
    (void)exfil_method;
    return false;
}

bool ThreatSimulator::simulate_command_and_control(const std::string& c2_server,
                                                    const std::string& protocol) {
    if (m_network_injector && !c2_server.empty()) {
        std::string beacon = "C2_BEACON|" + protocol + "|" + c2_server;
        std::vector<uint8_t> data(beacon.begin(), beacon.end());
        return m_network_injector(c2_server, data);
    }
    return false;
}

void ThreatSimulator::set_network_injector(std::function<bool(const std::string&, const std::vector<uint8_t>&)> injector) {
    m_network_injector = std::move(injector);
}

void ThreatSimulator::set_process_injector(std::function<bool(pid_t, const std::string&)> injector) {
    m_process_injector = std::move(injector);
}

bool ThreatSimulator::send_malicious_packet(const std::string& target_ip, int port,
                                             const std::vector<uint8_t>& payload) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
    sendto(sock, payload.data(), payload.size(), 0, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return true;
}

bool ThreatSimulator::inject_malicious_process(pid_t target_pid, const std::string& payload_path) {
    (void)target_pid;
    (void)payload_path;
    return false;
}

std::vector<uint8_t> BypassTechniques::mutate_signature(const std::vector<uint8_t>& original) {
    if (original.empty()) return {};
    std::vector<uint8_t> mutated = original;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> byte_dist(0, 255);
    std::uniform_int_distribution<size_t> pos_dist(0, mutated.size() - 1);

    for (size_t i = 0; i < std::min(mutated.size() / 10, size_t(16)); ++i) {
        mutated[pos_dist(gen)] = static_cast<uint8_t>(byte_dist(gen));
    }

    if (mutated.size() > 3) {
        mutated[0] = original[0];
        mutated[mutated.size() - 1] = original[original.size() - 1];
    }

    return mutated;
}

std::vector<uint8_t> BypassTechniques::obfuscate_shellcode(const std::vector<uint8_t>& shellcode) {
    if (shellcode.empty()) return {};
    std::vector<uint8_t> obfuscated;
    obfuscated.reserve(shellcode.size() * 2 + 2);

    uint8_t key = 0xAA;
    std::random_device rd;
    key ^= static_cast<uint8_t>(rd() & 0xFF);

    obfuscated.push_back(key);
    for (size_t i = 0; i < shellcode.size(); ++i) {
        obfuscated.push_back(shellcode[i] ^ key);
        obfuscated.push_back(static_cast<uint8_t>(i % 256));
    }
    obfuscated.push_back(0xCC);

    return obfuscated;
}

std::string BypassTechniques::encode_payload(const std::string& payload, const std::string& encoding) {
    if (encoding == "base64") {
        static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        for (size_t i = 0; i < payload.size(); i += 3) {
            uint32_t n = static_cast<unsigned char>(payload[i]) << 16;
            if (i + 1 < payload.size()) n |= static_cast<unsigned char>(payload[i + 1]) << 8;
            if (i + 2 < payload.size()) n |= static_cast<unsigned char>(payload[i + 2]);
            result += table[(n >> 18) & 0x3F];
            result += table[(n >> 12) & 0x3F];
            result += (i + 1 < payload.size()) ? table[(n >> 6) & 0x3F] : '=';
            result += (i + 2 < payload.size()) ? table[n & 0x3F] : '=';
        }
        return result;
    }
    if (encoding == "hex") {
        std::ostringstream oss;
        for (unsigned char c : payload) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
        }
        return oss.str();
    }
    return payload;
}

std::string BypassTechniques::encrypt_payload(const std::string& payload, const std::string& key) {
    std::string encrypted;
    encrypted.reserve(payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        encrypted += payload[i] ^ key[i % key.size()];
        encrypted += static_cast<char>((i * 37 + 13) % 256);
    }
    return encrypted;
}

std::vector<std::string> BypassTechniques::generate_anti_debug_tricks() {
    return {
        "PTRACE_TRACEME check",
        "LD_PRELOAD hook detection",
        "/proc/self/status TracerPid inspection",
        "INT3 breakpoint scan",
        "Timing-based debugger detection (RDTSC)"
    };
}

std::vector<std::string> BypassTechniques::generate_anti_vm_tricks() {
    return {
        "CPUID hypervisor bit check",
        "VMware I/O port probe",
        "VirtualBox DMI product scan",
        "QEMU fw_cfg detection",
        "MAC address OUI enumeration"
    };
}

std::string BypassTechniques::create_persistence_legitimate(const std::string& payload_path) {
    return "systemd user unit: ~/.config/systemd/user/legit-service.service -> " + payload_path;
}

RedTeamPlaybook::RedTeamPlaybook() = default;
RedTeamPlaybook::~RedTeamPlaybook() = default;

void RedTeamPlaybook::add_phase(AttackPhase phase, const std::vector<std::string>& scenario_ids) {
    m_phases[phase] = scenario_ids;
}

std::vector<std::string> RedTeamPlaybook::get_phase_scenarios(AttackPhase phase) const {
    auto it = m_phases.find(phase);
    if (it != m_phases.end()) return it->second;
    return {};
}

bool RedTeamPlaybook::execute_playbook(const std::string&) {
    return !m_phases.empty();
}

bool RedTeamPlaybook::validate_playbook() const {
    return !m_phases.empty();
}

void RedTeamPlaybook::save_playbook(const std::string& path) {
    std::ofstream out(path);
    if (!out) return;
    out << "# Red Team Playbook: " << m_playbook_name << "\n";
    for (const auto& [phase, scenarios] : m_phases) {
        out << static_cast<int>(phase) << ":";
        for (size_t i = 0; i < scenarios.size(); ++i) {
            if (i > 0) out << ",";
            out << scenarios[i];
        }
        out << "\n";
    }
}

bool RedTeamPlaybook::load_playbook(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    m_phases.clear();
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        int phase_val = std::stoi(line.substr(0, colon));
        std::string rest = line.substr(colon + 1);
        std::vector<std::string> ids;
        std::istringstream iss(rest);
        std::string id;
        while (std::getline(iss, id, ',')) {
            if (!id.empty()) ids.push_back(id);
        }
        m_phases[static_cast<AttackPhase>(phase_val)] = ids;
    }
    return true;
}

std::vector<std::string> RedTeamPlaybook::get_common_playbooks() {
    return {"initial_access", "lateral_movement", "full_chain", "defense_evasion"};
}

RedTeamPlaybook RedTeamPlaybook::create_initial_access_playbook() {
    RedTeamPlaybook pb;
    pb.m_playbook_name = "initial_access";
    pb.add_phase(AttackPhase::RECONNAISSANCE, {"scan_discovery", "port_enumeration"});
    pb.add_phase(AttackPhase::INITIAL_ACCESS, {"phishing_link", "exploit_vuln"});
    return pb;
}

RedTeamPlaybook RedTeamPlaybook::create_lateral_movement_playbook() {
    RedTeamPlaybook pb;
    pb.m_playbook_name = "lateral_movement";
    pb.add_phase(AttackPhase::DISCOVERY, {"account_discovery", "remote_system_discovery"});
    pb.add_phase(AttackPhase::LATERAL_MOVEMENT, {"ssh_lateral", "wmi_lateral"});
    return pb;
}

RedTeamPlaybook RedTeamPlaybook::create_full_chain_playbook() {
    RedTeamPlaybook pb;
    pb.m_playbook_name = "full_chain";
    pb.add_phase(AttackPhase::RECONNAISSANCE, {"network_scan"});
    pb.add_phase(AttackPhase::INITIAL_ACCESS, {"exploit_public_app"});
    pb.add_phase(AttackPhase::EXECUTION, {"command_interpreter"});
    pb.add_phase(AttackPhase::PERSISTENCE, {"scheduled_task"});
    pb.add_phase(AttackPhase::LATERAL_MOVEMENT, {"remote_services"});
    pb.add_phase(AttackPhase::COLLECTION, {"local_data_staging"});
    pb.add_phase(AttackPhase::COMMAND_AND_CONTROL, {"app_layer_protocol"});
    pb.add_phase(AttackPhase::IMPACT, {"data_encrypted"});
    return pb;
}

AssessmentEngine::AssessmentEngine() = default;
AssessmentEngine::~AssessmentEngine() = default;

void AssessmentEngine::run_coverage_assessment() {
    m_technique_rates.clear();
    m_phase_rates.clear();
}

void AssessmentEngine::run_detection_rate_assessment() {
}

void AssessmentEngine::run_impact_assessment() {
}

double AssessmentEngine::calculate_detection_coverage() {
    if (m_technique_rates.empty()) return 0.0;
    double sum = 0.0;
    for (const auto& [_, rate] : m_technique_rates) sum += rate;
    return sum / m_technique_rates.size();
}

double AssessmentEngine::calculate_false_positive_rate() {
    return 0.0;
}

std::map<std::string, double> AssessmentEngine::get_technique_detection_rates() const {
    return m_technique_rates;
}

std::map<AttackPhase, double> AssessmentEngine::get_phase_detection_rates() const {
    return m_phase_rates;
}

std::string AssessmentEngine::generate_assessment_report() const {
    std::ostringstream report;
    report << "=== Neuro-Mesh Security Assessment Report ===\n";
    double coverage = m_technique_rates.empty() ? 0.0 : [&]() {
        double sum = 0.0;
        for (const auto& [_, rate] : m_technique_rates) sum += rate;
        return sum / m_technique_rates.size();
    }();
    report << "Detection coverage: " << (coverage * 100.0) << "%\n";
    report << "Techniques assessed: " << m_technique_rates.size() << "\n";
    report << "Phases covered: " << m_phase_rates.size() << "\n";
    if (!m_technique_rates.empty()) {
        report << "\nTechnique Detection Rates:\n";
        for (const auto& [tech, rate] : m_technique_rates) {
            report << "  " << tech << ": " << (rate * 100.0) << "%\n";
        }
    }
    return report.str();
}

void AssessmentEngine::export_report(const std::string& path) {
    std::ofstream out(path);
    if (out) out << generate_assessment_report();
}

void AssessmentEngine::set_baseline_results(const std::vector<AttackResult>& results) {
    m_baseline_results = results;
}

} // namespace neuro_mesh::attacks
