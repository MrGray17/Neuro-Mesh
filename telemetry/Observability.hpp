#pragma once
#include <string>
#include <memory>
#include <map>
#include <vector>
#include <functional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <sstream>

namespace neuro_mesh::telemetry {

enum class MetricType {
    COUNTER,
    GAUGE,
    HISTOGRAM,
    SUMMARY
};

struct MetricValue {
    double value = 0.0;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> labels;
};

struct HistogramBucket {
    double le;
    uint64_t cumulative_count;
};

struct HistogramMetric {
    uint64_t count = 0;
    double sum = 0.0;
    double min = 0.0;
    double max = 0.0;
    std::vector<HistogramBucket> buckets;
};

class MetricFamily {
public:
    std::string name;
    std::string help;
    MetricType type;
    std::string unit;

    std::map<std::string, std::string> get_metric_values() const;
    std::string get_prometheus_format() const;
};

class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector();

    void counter(const std::string& name, double value, const std::map<std::string, std::string>& labels = {});
    void gauge(const std::string& name, double value, const std::map<std::string, std::string>& labels = {});
    void histogram(const std::string& name, double value, const std::map<std::string, std::string>& labels = {});

    void increment_counter(const std::string& name, const std::map<std::string, std::string>& labels = {});
    void set_gauge(const std::string& name, double value, const std::map<std::string, std::string>& labels = {});
    void observe_histogram(const std::string& name, double value, const std::map<std::string, std::string>& labels = {});

    std::string export_prometheus() const;
    std::string export_json() const;

    std::vector<std::string> get_metric_names() const;
    bool has_metric(const std::string& name) const;

    void set_export_callback(std::function<void(const std::string&)> callback);

    static std::string sanitize_metric_name(const std::string& name);

private:
    std::map<std::string, std::map<std::string, double>> m_counters;
    std::map<std::string, std::map<std::string, double>> m_gauges;
    std::map<std::string, std::map<std::string, HistogramMetric>> m_histograms;

    mutable std::mutex m_mutex;
    std::function<void(const std::string&)> m_export_callback;
};

class PrometheusExporter {
public:
    explicit PrometheusExporter(const std::string& listen_address = ":9090");
    ~PrometheusExporter();

    bool start();
    void stop();

    void register_collector(MetricsCollector* collector);
    void unregister_collector(const std::string& name);

    std::string get_metrics() const;

private:
    void metrics_loop();

    std::string m_listen_address;
    int m_fd = -1;
    std::atomic<bool> m_running;
    std::thread m_thread;
    std::vector<MetricsCollector*> m_collectors;
    mutable std::mutex m_mutex;
};

class DistributedTracer {
public:
    DistributedTracer(const std::string& service_name);
    ~DistributedTracer();

    struct Span {
        std::string trace_id;
        std::string span_id;
        std::string parent_span_id;
        std::string operation_name;
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;
        std::map<std::string, std::string> tags;
        std::map<std::string, std::string> logs;
        Span* parent = nullptr;
    };

    Span* start_span(const std::string& operation_name);
    Span* start_span(const std::string& operation_name, Span* parent);

    void end_span(Span* span);

    void set_tag(Span* span, const std::string& key, const std::string& value);
    void add_log(Span* span, const std::string& key, const std::string& value);

    std::string get_trace_id(Span* span) const { return span->trace_id; }
    std::string get_span_id(Span* span) const { return span->span_id; }

    void set_exporter(std::function<void(const std::vector<Span>&)> exporter);

    static std::string generate_id();

private:
    std::string m_service_name;
    std::vector<Span> m_active_spans;
    std::vector<Span> m_completed_spans;
    mutable std::mutex m_mutex;
    std::function<void(const std::vector<Span>&)> m_exporter;
};

class DetailedAuditLogger {
public:
    DetailedAuditLogger(const std::string& audit_path);
    ~DetailedAuditLogger();

    void log_event(const std::string& event_type,
                   const std::string& actor,
                   const std::string& action,
                   const std::string& target,
                   const std::map<std::string, std::string>& details = {});

    void log_consensus_event(const std::string& round_id,
                              const std::string& phase,
                              const std::vector<std::string>& voters,
                              bool success);

    void log_enforcement_event(const std::string& target,
                               const std::string& action,
                               bool success,
                               const std::string& reason = "");

    void log_key_event(const std::string& key_id,
                       const std::string& operation,
                       bool success);

    std::vector<std::string> query_events(const std::string& start_time,
                                          const std::string& end_time) const;

    std::string export_json() const;
    std::string export_syslog() const;

    void set_tamper_protection(bool enable);

private:
    struct AuditEntry {
        std::chrono::system_clock::time_point timestamp;
        std::string event_id;
        std::string event_type;
        std::string actor;
        std::string action;
        std::string target;
        std::map<std::string, std::string> details;
        std::string previous_hash;
        std::string entry_hash;
    };

    void compute_hash(AuditEntry& entry);
    bool verify_hash_chain() const;

    std::string m_audit_path;
    std::vector<AuditEntry> m_entries;
    mutable std::mutex m_mutex;
    bool m_tamper_protection = false;
    std::string m_last_hash;
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    void alert(const std::string& alert_name,
               const std::string& severity,
               const std::string& message,
               const std::map<std::string, std::string>& labels = {});

    void alert_anomaly(const std::string& metric_name, double value, double threshold);
    void alert_consensus_failure(const std::string& reason);
    void alert_detection(const std::string& technique, const std::string& details);
    void alert_enforcement_failure(const std::string& target, const std::string& reason);

    void set_alert_callback(std::function<void(const std::string&, const std::string&,
                                               const std::string&, const std::map<std::string, std::string>&)> callback);

    std::vector<std::string> get_active_alerts() const;
    void clear_alert(const std::string& alert_id);

private:
    struct Alert {
        std::string alert_id;
        std::string alert_name;
        std::string severity;
        std::string message;
        std::map<std::string, std::string> labels;
        std::chrono::system_clock::time_point fired_at;
        std::optional<std::chrono::system_clock::time_point> resolved_at;
    };

    std::vector<Alert> m_alerts;
    mutable std::mutex m_mutex;
    std::function<void(const std::string&, const std::string&,
                      const std::string&, const std::map<std::string, std::string>&)> m_callback;
};

class ObservabilityStack {
public:
    ObservabilityStack(const std::string& node_id);
    ~ObservabilityStack();

    MetricsCollector* metrics() { return m_metrics.get(); }
    DistributedTracer* tracer() { return m_tracer.get(); }
    DetailedAuditLogger* audit() { return m_audit.get(); }
    AlertManager* alerts() { return m_alerts.get(); }

    bool start();
    void stop();

    std::string get_all_metrics() const;
    std::string get_audit_log() const;

    void register_default_metrics();

private:
    std::string m_node_id;

    std::unique_ptr<MetricsCollector> m_metrics;
    std::unique_ptr<DistributedTracer> m_tracer;
    std::unique_ptr<DetailedAuditLogger> m_audit;
    std::unique_ptr<AlertManager> m_alerts;
    std::unique_ptr<PrometheusExporter> m_exporter;

    void register_bft_metrics();
    void register_network_metrics();
    void register_enforcement_metrics();
    void register_security_metrics();
};

class SLI_SLOTracker {
public:
    SLI_SLOTracker();
    ~SLI_SLOTracker();

    void record_bft_consensus_time(std::chrono::milliseconds duration);
    void record_detection_latency(std::chrono::milliseconds duration);
    void record_enforcement_time(std::chrono::milliseconds duration);
    void record_message_latency(std::chrono::milliseconds duration);

    double get_availability() const;
    double get_consensus_latency_p99() const;
    double get_detection_latency_p99() const;

    bool meets_slo(const std::string& slo_name) const;
    std::map<std::string, bool> get_all_slo_status() const;

    void set_slo_target(const std::string& slo_name, double target_percent);

private:
    std::map<std::string, std::vector<std::chrono::milliseconds>> m_measurements;
    std::map<std::string, double> m_slo_targets;

    double calculate_percentile(const std::vector<std::chrono::milliseconds>& samples, double percentile) const;
};

} // namespace neuro_mesh::telemetry