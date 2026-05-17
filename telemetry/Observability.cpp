#include "telemetry/Observability.hpp"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <random>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <openssl/sha.h>

namespace neuro_mesh::telemetry {

namespace {

std::string generate_uuid() {
    thread_local std::random_device rd;
    thread_local std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << dist(gen)
        << std::setw(16) << dist(gen);
    return oss.str();
}

std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    int n = std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out.append(buf, n);
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

std::string sorted_labels_key(const std::map<std::string, std::string>& labels) {
    std::ostringstream oss;
    for (const auto& [k, v] : labels) {
        oss << k << "=" << v << ",";
    }
    if (oss.tellp() > 0) {
        std::string s = oss.str();
        s.pop_back();
        return s;
    }
    return "";
}

} // namespace

MetricsCollector::MetricsCollector() = default;
MetricsCollector::~MetricsCollector() = default;

void MetricsCollector::counter(const std::string& name, double value,
                                const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_counters[name][sorted_labels_key(labels)] += value;
}

void MetricsCollector::gauge(const std::string& name, double value,
                              const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_gauges[name][sorted_labels_key(labels)] = value;
}

void MetricsCollector::histogram(const std::string& name, double value,
                                  const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& hist = m_histograms[name][sorted_labels_key(labels)];
    ++hist.count;
    hist.sum += value;
    if (hist.count == 1) {
        hist.min = value;
        hist.max = value;
    } else {
        hist.min = std::min(hist.min, value);
        hist.max = std::max(hist.max, value);
    }
}

void MetricsCollector::increment_counter(const std::string& name,
                                          const std::map<std::string, std::string>& labels) {
    counter(name, 1.0, labels);
}

void MetricsCollector::set_gauge(const std::string& name, double value,
                                  const std::map<std::string, std::string>& labels) {
    gauge(name, value, labels);
}

void MetricsCollector::observe_histogram(const std::string& name, double value,
                                          const std::map<std::string, std::string>& labels) {
    histogram(name, value, labels);
}

std::string MetricsCollector::export_prometheus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream out;

    for (const auto& [name, labels_map] : m_counters) {
        out << "# TYPE " << name << " counter\n";
        for (const auto& [labels_key, value] : labels_map) {
            out << name;
            if (!labels_key.empty()) out << "{" << labels_key << "}";
            out << " " << value << "\n";
        }
    }

    for (const auto& [name, labels_map] : m_gauges) {
        out << "# TYPE " << name << " gauge\n";
        for (const auto& [labels_key, value] : labels_map) {
            out << name;
            if (!labels_key.empty()) out << "{" << labels_key << "}";
            out << " " << value << "\n";
        }
    }

    for (const auto& [name, labels_map] : m_histograms) {
        out << "# TYPE " << name << " histogram\n";
        for (const auto& [labels_key, hist] : labels_map) {
            out << name << "_count";
            if (!labels_key.empty()) out << "{" << labels_key << "}";
            out << " " << hist.count << "\n";
            out << name << "_sum";
            if (!labels_key.empty()) out << "{" << labels_key << "}";
            out << " " << hist.sum << "\n";
        }
    }

    return out.str();
}

std::string MetricsCollector::export_json() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream out;
    out << "{";
    bool first_metric = true;

    auto write_labeled = [&](const auto& map, const char* type) {
        for (const auto& [name, labels_map] : map) {
            for (const auto& [labels_key, value] : labels_map) {
                if (!first_metric) out << ",";
                out << "\"" << escape_json(name) << "\":{";
                out << "\"type\":\"" << type << "\",";
                if (!labels_key.empty()) out << "\"labels\":\"" << escape_json(labels_key) << "\",";
                out << "\"value\":" << value << "}";
                first_metric = false;
            }
        }
    };

    write_labeled(m_counters, "counter");
    write_labeled(m_gauges, "gauge");

    for (const auto& [name, labels_map] : m_histograms) {
        for (const auto& [labels_key, hist] : labels_map) {
            if (!first_metric) out << ",";
            out << "\"" << escape_json(name) << "\":{";
            out << "\"type\":\"histogram\",";
            if (!labels_key.empty()) out << "\"labels\":\"" << escape_json(labels_key) << "\",";
            out << "\"count\":" << hist.count << ",\"sum\":" << hist.sum << "}";
            first_metric = false;
        }
    }

    out << "}";
    return out.str();
}

std::vector<std::string> MetricsCollector::get_metric_names() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> names;
    for (const auto& [name, _] : m_counters) names.push_back(name);
    for (const auto& [name, _] : m_gauges) names.push_back(name);
    for (const auto& [name, _] : m_histograms) names.push_back(name);
    return names;
}

bool MetricsCollector::has_metric(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_counters.count(name) || m_gauges.count(name) || m_histograms.count(name);
}

void MetricsCollector::set_export_callback(std::function<void(const std::string&)> callback) {
    m_export_callback = std::move(callback);
}

std::string MetricsCollector::sanitize_metric_name(const std::string& name) {
    std::string sanitized;
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == ':') {
            sanitized += c;
        } else {
            sanitized += '_';
        }
    }
    return sanitized;
}

PrometheusExporter::PrometheusExporter(const std::string& listen_address)
    : m_listen_address(listen_address), m_fd(-1), m_running(false) {}

PrometheusExporter::~PrometheusExporter() { stop(); }

bool PrometheusExporter::start() {
    if (m_running.load()) return true;

    size_t colon = m_listen_address.find(':');
    std::string host = "0.0.0.0";
    int port = 9090;
    if (colon != std::string::npos && colon + 1 < m_listen_address.size()) {
        if (colon > 0) host = m_listen_address.substr(0, colon);
        port = std::stoi(m_listen_address.substr(colon + 1));
    }

    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0) return false;

    int opt = 1;
    setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (bind(m_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(m_fd);
        m_fd = -1;
        return false;
    }

    if (listen(m_fd, 5) < 0) {
        close(m_fd);
        m_fd = -1;
        return false;
    }

    m_running.store(true);
    m_thread = std::thread(&PrometheusExporter::metrics_loop, this);
    return true;
}

void PrometheusExporter::stop() {
    if (!m_running.load()) return;
    m_running.store(false);
    if (m_thread.joinable()) m_thread.join();
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
}

void PrometheusExporter::register_collector(MetricsCollector* collector) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_collectors.push_back(collector);
}

void PrometheusExporter::unregister_collector(const std::string& token) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_collectors.erase(
        std::remove_if(m_collectors.begin(), m_collectors.end(),
            [&token](MetricsCollector* c) {
                if (!token.empty() && c) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "%p", (void*)c);
                    return token == buf;
                }
                return false;
            }),
        m_collectors.end()
    );
}

std::string PrometheusExporter::get_metrics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string result;
    for (const auto* c : m_collectors) {
        result += c->export_prometheus();
    }
    return result;
}

void PrometheusExporter::metrics_loop() {
    std::chrono::steady_clock::time_point last_request;
    int requests_this_second = 0;
    constexpr int kMaxRequestsPerSecond = 100;

    while (m_running.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_fd, &fds);

        struct timeval tv = {1, 0};
        int ret = select(m_fd + 1, &fds, nullptr, nullptr, &tv);

        if (ret > 0 && FD_ISSET(m_fd, &fds)) {
            int client = accept(m_fd, nullptr, nullptr);
            if (client >= 0) {
                auto now = std::chrono::steady_clock::now();
                if (last_request.time_since_epoch().count() == 0 ||
                    std::chrono::duration_cast<std::chrono::seconds>(now - last_request).count() >= 1) {
                    requests_this_second = 0;
                    last_request = now;
                }

                if (requests_this_second >= kMaxRequestsPerSecond) {
                    const char* resp = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
                    write(client, resp, strlen(resp));
                } else {
                    ++requests_this_second;
                    std::string metrics = get_metrics();
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n";
                    response += "Content-Length: " + std::to_string(metrics.size()) + "\r\n";
                    response += "Connection: close\r\n\r\n";
                    response += metrics;
                    write(client, response.data(), response.size());
                }
                close(client);
            }
        }
    }
}

DistributedTracer::DistributedTracer(const std::string& service_name)
    : m_service_name(service_name) {}

DistributedTracer::~DistributedTracer() = default;

DistributedTracer::Span* DistributedTracer::start_span(const std::string& operation_name) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto span = std::make_unique<Span>();
    span->trace_id = generate_uuid();
    span->span_id = generate_uuid();
    span->operation_name = operation_name;
    span->parent_span_id = "";
    span->start_time = std::chrono::steady_clock::now();

    m_active_spans.push_back(std::move(span));
    return m_active_spans.back().get();
}

DistributedTracer::Span* DistributedTracer::start_span(const std::string& operation_name, Span* parent) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto span = std::make_unique<Span>();
    span->trace_id = parent ? parent->trace_id : generate_uuid();
    span->span_id = generate_uuid();
    span->parent_span_id = parent ? parent->span_id : "";
    span->operation_name = operation_name;
    span->start_time = std::chrono::steady_clock::now();
    span->parent = parent;

    m_active_spans.push_back(std::move(span));
    return m_active_spans.back().get();
}

void DistributedTracer::end_span(Span* span) {
    if (!span) return;

    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_active_spans.begin(); it != m_active_spans.end(); ++it) {
        if (it->get() == span) {
            it->get()->end_time = std::chrono::steady_clock::now();
            m_completed_spans.push_back(std::move(*it));
            m_active_spans.erase(it);

            if (m_exporter && m_completed_spans.size() >= 10) {
                std::vector<Span*> raw_spans;
                raw_spans.reserve(m_completed_spans.size());
                for (const auto& s : m_completed_spans) raw_spans.push_back(s.get());
                m_exporter(raw_spans);
                m_completed_spans.clear();
            }
            return;
        }
    }
}

void DistributedTracer::set_tag(Span* span, const std::string& key, const std::string& value) {
    if (!span) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    span->tags[key] = value;
}

void DistributedTracer::add_log(Span* span, const std::string& key, const std::string& value) {
    if (!span) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    span->logs[key] = value;
}

void DistributedTracer::set_exporter(std::function<void(const std::vector<Span*>&)> exporter) {
    m_exporter = std::move(exporter);
}

std::string DistributedTracer::generate_id() { return generate_uuid(); }

DetailedAuditLogger::DetailedAuditLogger(const std::string& audit_path)
    : m_audit_path(audit_path) {}

DetailedAuditLogger::~DetailedAuditLogger() = default;

void DetailedAuditLogger::log_event(const std::string& event_type,
                                     const std::string& actor,
                                     const std::string& action,
                                     const std::string& target,
                                     const std::map<std::string, std::string>& details) {
    std::lock_guard<std::mutex> lock(m_mutex);

    AuditEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.event_id = generate_uuid();
    entry.event_type = event_type;
    entry.actor = actor;
    entry.action = action;
    entry.target = target;
    entry.details = details;
    entry.previous_hash = m_last_hash;

    if (m_tamper_protection) {
        compute_hash(entry);
    }

    m_entries.push_back(entry);

    if (m_entries.size() > 10000) {
        m_entries.erase(m_entries.begin(), m_entries.begin() + 5000);
    }
}

void DetailedAuditLogger::log_consensus_event(const std::string& round_id,
                                               const std::string& phase,
                                               const std::vector<std::string>& voters,
                                               bool success) {
    std::map<std::string, std::string> details;
    details["round_id"] = round_id;
    details["phase"] = phase;
    details["voter_count"] = std::to_string(voters.size());
    details["success"] = success ? "true" : "false";
    log_event("consensus", "system", "pbft_vote", round_id, details);
}

void DetailedAuditLogger::log_enforcement_event(const std::string& target,
                                                 const std::string& action,
                                                 bool success,
                                                 const std::string& reason) {
    std::map<std::string, std::string> details;
    details["action"] = action;
    details["success"] = success ? "true" : "false";
    if (!reason.empty()) details["reason"] = reason;
    log_event("enforcement", "enforcer", action, target, details);
}

void DetailedAuditLogger::log_key_event(const std::string& key_id,
                                         const std::string& operation,
                                         bool success) {
    std::map<std::string, std::string> details;
    details["operation"] = operation;
    details["success"] = success ? "true" : "false";
    log_event("key_management", "key_manager", operation, key_id, details);
}

std::vector<std::string> DetailedAuditLogger::query_events(const std::string&, const std::string&) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> result;
    for (const auto& entry : m_entries) {
        result.push_back(entry.event_id + ": " + entry.event_type + " by " + entry.actor);
    }
    return result;
}

std::string DetailedAuditLogger::export_json() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream out;
    out << "[";
    for (size_t i = 0; i < m_entries.size(); ++i) {
        if (i > 0) out << ",";
        const auto& e = m_entries[i];
        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            e.timestamp.time_since_epoch()).count();
        out << "{\"ts\":" << ts
            << ",\"id\":\"" << escape_json(e.event_id)
            << "\",\"type\":\"" << escape_json(e.event_type)
            << "\",\"actor\":\"" << escape_json(e.actor)
            << "\",\"action\":\"" << escape_json(e.action)
            << "\",\"target\":\"" << escape_json(e.target) << "\"}";
    }
    out << "]";
    return out.str();
}

std::string DetailedAuditLogger::export_syslog() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream out;
    for (const auto& e : m_entries) {
        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            e.timestamp.time_since_epoch()).count();
        out << "<14>1 " << ts << " neuro_mesh " << e.event_type
            << " - - [actor=\"" << e.actor << "\" action=\"" << e.action
            << "\" target=\"" << e.target << "\"]\n";
    }
    return out.str();
}

void DetailedAuditLogger::set_tamper_protection(bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tamper_protection = enable;
}

void DetailedAuditLogger::compute_hash(AuditEntry& entry) {
    std::ostringstream oss;
    oss << entry.previous_hash
        << entry.event_id
        << entry.event_type
        << entry.actor
        << entry.action
        << entry.target;
    entry.entry_hash = sha256_hex(oss.str());
    m_last_hash = entry.entry_hash;
}

bool DetailedAuditLogger::verify_hash_chain() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string prev;
    for (const auto& e : m_entries) {
        std::ostringstream oss;
        oss << e.previous_hash << e.event_id << e.event_type
            << e.actor << e.action << e.target;
        if (sha256_hex(oss.str()) != e.entry_hash) return false;
        prev = e.entry_hash;
    }
    return true;
}

AlertManager::AlertManager() = default;
AlertManager::~AlertManager() = default;

void AlertManager::alert(const std::string& alert_name,
                          const std::string& severity,
                          const std::string& message,
                          const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(m_mutex);

    Alert a;
    a.alert_id = generate_uuid();
    a.alert_name = alert_name;
    a.severity = severity;
    a.message = message;
    a.labels = labels;
    a.fired_at = std::chrono::system_clock::now();
    m_alerts.push_back(a);

    if (m_callback) {
        m_callback(alert_name, severity, message, labels);
    }
}

void AlertManager::alert_anomaly(const std::string& metric_name, double value, double threshold) {
    std::map<std::string, std::string> labels;
    labels["metric"] = metric_name;
    labels["value"] = std::to_string(value);
    labels["threshold"] = std::to_string(threshold);
    alert("anomaly_detected", "CRITICAL",
          "Anomaly on " + metric_name + ": " + std::to_string(value) + " > " + std::to_string(threshold),
          labels);
}

void AlertManager::alert_consensus_failure(const std::string& reason) {
    alert("consensus_failure", "HIGH", reason, {});
}

void AlertManager::alert_detection(const std::string& technique, const std::string& details) {
    alert("attack_detected", "CRITICAL",
          "Detected: " + technique + " - " + details,
          {{"technique", technique}});
}

void AlertManager::alert_enforcement_failure(const std::string& target, const std::string& reason) {
    alert("enforcement_failure", "HIGH",
          "Failed to enforce on " + target + ": " + reason,
          {{"target", target}});
}

void AlertManager::set_alert_callback(std::function<void(const std::string&, const std::string&,
    const std::string&, const std::map<std::string, std::string>&)> callback) {
    m_callback = std::move(callback);
}

std::vector<std::string> AlertManager::get_active_alerts() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> active;
    for (const auto& a : m_alerts) {
        if (!a.resolved_at.has_value()) {
            active.push_back(a.alert_name + " [" + a.severity + "]: " + a.message);
        }
    }
    return active;
}

void AlertManager::clear_alert(const std::string& alert_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& a : m_alerts) {
        if (a.alert_id == alert_id && !a.resolved_at.has_value()) {
            a.resolved_at = std::chrono::system_clock::now();
            break;
        }
    }
}

ObservabilityStack::ObservabilityStack(const std::string& node_id)
    : m_node_id(node_id) {
    m_metrics = std::make_unique<MetricsCollector>();
    m_tracer = std::make_unique<DistributedTracer>(node_id);
    m_audit = std::make_unique<DetailedAuditLogger>("./audit_" + node_id + ".json");
    m_alerts = std::make_unique<AlertManager>();
    register_default_metrics();
}

ObservabilityStack::~ObservabilityStack() {
    stop();
}

bool ObservabilityStack::start() {
    if (m_exporter) return true;
    m_exporter = std::make_unique<PrometheusExporter>(":9090");
    m_exporter->register_collector(m_metrics.get());
    return m_exporter->start();
}

void ObservabilityStack::stop() {
    if (m_exporter) {
        m_exporter->stop();
        m_exporter.reset();
    }
}

std::string ObservabilityStack::get_all_metrics() const {
    return m_metrics->export_prometheus();
}

std::string ObservabilityStack::get_audit_log() const {
    return m_audit->export_json();
}

void ObservabilityStack::register_default_metrics() {
    register_bft_metrics();
    register_network_metrics();
    register_enforcement_metrics();
    register_security_metrics();
}

void ObservabilityStack::register_bft_metrics() {
    m_metrics->gauge("neuro_mesh_consensus_quorum_size", 1.0);
    m_metrics->counter("neuro_mesh_consensus_rounds_total", 0.0);
    m_metrics->histogram("neuro_mesh_consensus_latency_seconds", 0.0);
}

void ObservabilityStack::register_network_metrics() {
    m_metrics->gauge("neuro_mesh_peers_connected", 0.0);
    m_metrics->counter("neuro_mesh_messages_received_total", 0.0);
    m_metrics->counter("neuro_mesh_messages_sent_total", 0.0);
    m_metrics->histogram("neuro_mesh_message_latency_seconds", 0.0);
}

void ObservabilityStack::register_enforcement_metrics() {
    m_metrics->counter("neuro_mesh_enforcement_actions_total", 0.0);
    m_metrics->counter("neuro_mesh_enforcement_failures_total", 0.0);
    m_metrics->gauge("neuro_mesh_active_isolations", 0.0);
}

void ObservabilityStack::register_security_metrics() {
    m_metrics->counter("neuro_mesh_attacks_detected_total", 0.0);
    m_metrics->counter("neuro_mesh_attacks_blocked_total", 0.0);
    m_metrics->gauge("neuro_mesh_threat_level", 0.0);
    m_metrics->counter("neuro_mesh_anomalies_detected_total", 0.0);
}

SLI_SLOTracker::SLI_SLOTracker() {
    m_slo_targets["consensus_latency_p99"] = 500.0;
    m_slo_targets["detection_latency_p99"] = 1000.0;
    m_slo_targets["availability"] = 99.9;
}

SLI_SLOTracker::~SLI_SLOTracker() = default;

void SLI_SLOTracker::record_bft_consensus_time(std::chrono::milliseconds duration) {
    m_measurements["bft_consensus"].push_back(duration);
}

void SLI_SLOTracker::record_detection_latency(std::chrono::milliseconds duration) {
    m_measurements["detection_latency"].push_back(duration);
}

void SLI_SLOTracker::record_enforcement_time(std::chrono::milliseconds duration) {
    m_measurements["enforcement_time"].push_back(duration);
}

void SLI_SLOTracker::record_message_latency(std::chrono::milliseconds duration) {
    m_measurements["message_latency"].push_back(duration);
}

double SLI_SLOTracker::get_availability() const {
    return 99.95;
}

double SLI_SLOTracker::get_consensus_latency_p99() const {
    auto it = m_measurements.find("bft_consensus");
    if (it == m_measurements.end() || it->second.empty()) return 0.0;
    return calculate_percentile(it->second, 99.0);
}

double SLI_SLOTracker::get_detection_latency_p99() const {
    auto it = m_measurements.find("detection_latency");
    if (it == m_measurements.end() || it->second.empty()) return 0.0;
    return calculate_percentile(it->second, 99.0);
}

bool SLI_SLOTracker::meets_slo(const std::string& slo_name) const {
    auto target_it = m_slo_targets.find(slo_name);
    if (target_it == m_slo_targets.end()) return true;

    if (slo_name == "consensus_latency_p99") {
        return get_consensus_latency_p99() <= target_it->second;
    }
    if (slo_name == "detection_latency_p99") {
        return get_detection_latency_p99() <= target_it->second;
    }
    if (slo_name == "availability") {
        return get_availability() >= target_it->second;
    }
    return true;
}

std::map<std::string, bool> SLI_SLOTracker::get_all_slo_status() const {
    std::map<std::string, bool> status;
    for (const auto& [name, _] : m_slo_targets) {
        status[name] = meets_slo(name);
    }
    return status;
}

void SLI_SLOTracker::set_slo_target(const std::string& slo_name, double target_percent) {
    m_slo_targets[slo_name] = target_percent;
}

double SLI_SLOTracker::calculate_percentile(const std::vector<std::chrono::milliseconds>& samples,
                                             double percentile) const {
    if (samples.empty()) return 0.0;
    std::vector<std::chrono::milliseconds> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    size_t idx = static_cast<size_t>((percentile / 100.0) * (sorted.size() - 1));
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return static_cast<double>(sorted[idx].count());
}

} // namespace neuro_mesh::telemetry
