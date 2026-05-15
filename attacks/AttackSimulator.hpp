#pragma once
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>
#include <optional>
#include <memory>

namespace neuro_mesh::attacks {

enum class AttackPhase {
    RECONNAISSANCE,
    INITIAL_ACCESS,
    EXECUTION,
    PERSISTENCE,
    PRIVILEGE_ESCALATION,
    DEFENSE_EVASION,
    CREDENTIAL_ACCESS,
    DISCOVERY,
    LATERAL_MOVEMENT,
    COLLECTION,
    COMMAND_AND_CONTROL,
    IMPACT
};

enum class AttackTechnique {
    T1059_Command_SHELL_INTERPRETER,
    T1059_004_WINDOWS_COMMAND_SHELL,
    T1087_ACCOUNT_DISCOVERY,
    T1082_SYSTEM_INFO_DISCOVERY,
    T1005_DATA_FROM_Local_System,
    T1041_EXFILTRATION_OVER_C2_CHANNEL,
    T1071_APPLICATION_LAYER_PROTOCOL,
    T1571_NON_STANDARD_PORT,
    T1003_OS_CREDENTIAL_DUMPING,
    T1021_REMOTE_SERVICES,
    T1053_SCHEDULED_TASK,
    T1547_BOOT_OR_LOGON_AUTOSTART,
    T1136_CREATE_ACCOUNT,
    T1078_VALID_ACCOUNTS,
    T1562_IMPAIR_DEFENSES,
    T1562_001_DISABLE_SECURITY_TOOLS,
    T1070_4_FILE_DELETION,
    T1486_DATA_ENCRYPTED_FOR_IMPACT,
    T1489_SERVICE_STOP,
    T1529_SYSTEM_SHUTDOWN,
    T1535_UNSAFE_Revoked_COMMITMENT
};

enum class AttackSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class DetectionResult {
    DETECTED,
    BLOCKED,
    ALLOWED,
    PARTIALLY_DETECTED
};

struct AttackScenario {
    std::string scenario_id;
    std::string name;
    std::string description;
    AttackPhase phase;
    AttackTechnique technique;
    AttackSeverity severity;
    std::vector<std::string> mitre_tactics;
    std::vector<std::string> detection_signatures;
    int success_probability_percent;
};

struct AttackResult {
    std::string scenario_id;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    DetectionResult detection;
    std::vector<std::string> detection_methods;
    std::string detection_details;
    bool execution_successful;
    std::string error_message;
    std::map<std::string, std::string> telemetry_captured;
};

struct DetectionMetrics {
    AttackScenario scenario;
    int total_attempts;
    int detected_count;
    int blocked_count;
    int allowed_count;
    std::chrono::milliseconds avg_detection_time;
    double detection_rate_percent;
    double block_rate_percent;
};

struct AtomicAttack {
    std::string attack_id;
    std::string name;
    std::string description;
    AttackTechnique technique;
    std::function<bool()> executor;
    std::function<std::map<std::string, std::string>()> telemetry_generator;
};

class AttackOrchestrator {
public:
    AttackOrchestrator();
    ~AttackOrchestrator();

    void load_scenarios(const std::vector<AttackScenario>& scenarios);
    void register_atomic_attack(const AtomicAttack& attack);

    std::vector<AttackScenario> get_available_scenarios() const;
    std::vector<AttackScenario> get_scenarios_by_phase(AttackPhase phase) const;
    std::vector<AttackScenario> get_scenarios_by_technique(AttackTechnique technique) const;

    AttackResult execute_scenario(const std::string& scenario_id);
    std::vector<AttackResult> execute_campaign(const std::vector<std::string>& scenario_ids);

    DetectionMetrics calculate_metrics(const std::string& scenario_id) const;
    std::vector<DetectionMetrics> calculate_all_metrics() const;

    void set_detection_callback(std::function<void(const AttackResult&)> callback);
    void set_defense_callback(std::function<void(const std::string&, const std::string&)> callback);

    double get_overall_detection_rate() const;
    std::vector<std::string> get_undetected_techniques() const;

private:
    std::vector<AttackScenario> m_scenarios;
    std::map<std::string, AtomicAttack> m_atomic_attacks;
    std::vector<AttackResult> m_results;

    std::function<void(const AttackResult&)> m_detection_callback;
    std::function<void(const std::string&, const std::string&)> m_defense_callback;

    bool execute_attack(const AttackScenario& scenario, AttackResult& result);
    std::map<std::string, std::string> capture_telemetry();
};

class ThreatSimulator {
public:
    ThreatSimulator();
    ~ThreatSimulator();

    bool simulate_network_attack(const std::string& target_ip, int target_port,
                                 const std::string& attack_type);

    bool simulate_endpoint_attack(const std::string& target_process,
                                   const std::string& attack_type);

    bool simulate_lateral_movement(const std::string& source_node,
                                    const std::string& target_node,
                                    const std::string& technique);

    bool simulate_credential_theft(const std::string& target_user,
                                   const std::string& method);

    bool simulate_data_exfiltration(const std::string& data_path,
                                    const std::string& exfil_method);

    bool simulate_command_and_control(const std::string& c2_server,
                                      const std::string& protocol);

    void set_network_injector(std::function<bool(const std::string&, const std::vector<uint8_t>&)> injector);
    void set_process_injector(std::function<bool(pid_t, const std::string&)> injector);

private:
    std::function<bool(const std::string&, const std::vector<uint8_t>&)> m_network_injector;
    std::function<bool(pid_t, const std::string&)> m_process_injector;

    bool send_malicious_packet(const std::string& target_ip, int port, const std::vector<uint8_t>& payload);
    bool inject_malicious_process(pid_t target_pid, const std::string& payload_path);
};

class BypassTechniques {
public:
    static std::vector<uint8_t> mutate_signature(const std::vector<uint8_t>& original);
    static std::vector<uint8_t> obfuscate_shellcode(const std::vector<uint8_t>& shellcode);
    static std::string encode_payload(const std::string& payload, const std::string& encoding);
    static std::string encrypt_payload(const std::string& payload, const std::string& key);
    static std::vector<std::string> generate_anti_debug_tricks();
    static std::vector<std::string> generate_anti_vm_tricks();
    static std::string create_persistence_legitimate(const std::string& payload_path);
};

class RedTeamPlaybook {
public:
    RedTeamPlaybook();
    ~RedTeamPlaybook();

    void add_phase(AttackPhase phase, const std::vector<std::string>& scenario_ids);
    std::vector<std::string> get_phase_scenarios(AttackPhase phase) const;

    bool execute_playbook(const std::string& playbook_name);
    bool validate_playbook() const;

    void save_playbook(const std::string& path);
    bool load_playbook(const std::string& path);

    static std::vector<std::string> get_common_playbooks();
    static RedTeamPlaybook create_initial_access_playbook();
    static RedTeamPlaybook create_lateral_movement_playbook();
    static RedTeamPlaybook create_full_chain_playbook();

private:
    std::map<AttackPhase, std::vector<std::string>> m_phases;
    std::string m_playbook_name;
};

class AssessmentEngine {
public:
    AssessmentEngine();
    ~AssessmentEngine();

    void run_coverage_assessment();
    void run_detection_rate_assessment();
    void run_impact_assessment();

    double calculate_detection_coverage();
    double calculate_false_positive_rate();

    std::map<std::string, double> get_technique_detection_rates() const;
    std::map<AttackPhase, double> get_phase_detection_rates() const;

    std::string generate_assessment_report() const;
    void export_report(const std::string& path);

    void set_baseline_results(const std::vector<AttackResult>& results);

private:
    std::vector<AttackResult> m_baseline_results;
    std::vector<AttackResult> m_current_results;
    std::map<std::string, double> m_technique_rates;
    std::map<AttackPhase, double> m_phase_rates;
};

} // namespace neuro_mesh::attacks