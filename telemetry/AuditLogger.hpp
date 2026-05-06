#pragma once
#include <string>

namespace neuro_mesh::telemetry {

enum class AuditLevel { INFO, WARNING, CRITICAL, DEFENSE_ACTION };

class AuditLogger {
public:
    static void initialize(); 
    static void emit_json(AuditLevel level, const std::string& component, 
                          const std::string& action, const std::string& target, 
                          const std::string& details);
    
    // NEW: Continuous metric emitter
    static void emit_metric(double cpu_percent, double ram_mb, int active_agents);

private:
    // Socket managed via RAII UniqueFD in AuditLogger.cpp
};

} // namespace neuro_mesh::telemetry
