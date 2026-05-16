#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include "consensus/PeerManager.hpp"
#include "crypto/CryptoCore.hpp"
#include "crypto/KeyManager.hpp"
#include "net/TransportLayer.hpp"
#include "common/StateJournal.hpp"
#include "enforcer/PolicyEnforcer.hpp"

namespace neuro_mesh {

class MitigationEngine;
class TelemetryBridge;

// Backward-compatible alias for code referencing PeerInfo
using PeerInfo = PeerEntry;

class MeshNode {
public:
    static constexpr int DISCOVERY_UDP_PORT = 9998;
    static constexpr int TCP_PORT_START    = 10000;
    static constexpr int TLS_PORT_START    = 10500;
    static constexpr int HEARTBEAT_SEC          = 5;

    MeshNode(const std::string& node_id,
             PolicyEnforcer* enforcer, MitigationEngine* mitigation,
             TelemetryBridge* bridge = nullptr);
    ~MeshNode();

    void start();
    void stop();
    void initiate_consensus(const std::string& target_id, const std::string& evidence_json);

    void gossip_telemetry(const std::string& telemetry_json);
    void gossip_event_json(const std::string& json);
    std::string get_mesh_telemetry() const;

    int tcp_port() const { return m_tcp_port; }
    int tls_port() const { return m_tls_port; }
    int peer_count() const;
    std::vector<std::string> get_active_peer_ids() const;

    void set_seed_peers(const std::vector<std::pair<std::string, int>>& seeds);
    void unpin_peer_key(const std::string& node_id);
    bool is_targeted_recently() const;

    std::vector<std::string> split_string(const std::string& str, char delimiter);
    static bool try_parse_int(const std::string& s, int& out) noexcept;
    static bool try_parse_long(const std::string& s, int64_t& out) noexcept;

    static void notify_webhook(const std::string& url, const std::string& target_id,
                                const std::string& evidence_json, int quorum, int64_t timestamp_us);

private:
    void p2p_listener_loop();
    void discovery_beacon_loop();
    void tcp_listener_loop();
    void tls_acceptor_loop();
    void liveness_monitor();

    void process_message(const std::string& msg, const std::string& sender_ip);
    bool validate_message(const std::string& msg) const;
    void process_discovery_beacon(const std::string& msg, const std::string& sender_ip);
    void process_telemetry_gossip(const std::string& msg, const std::string& sender_ip);
    void broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json);
    void send_udp_broadcast(const std::string& payload);
    void send_udp_discovery(const std::string& payload);
    void send_udp_unicast(const std::string& ip, int port, const std::string& payload);

    bool send_tls_to_peer(const std::string& peer_id, const std::string& payload);
    void send_tls_broadcast(const std::string& payload);
    bool connect_tls_to_peer(const std::string& peer_id, const std::string& ip, int port);
    void disconnect_tls_peer(const std::string& peer_id);

    void send_discovery_beacon();
    void announce_identity();
    bool perform_pex_handshake(const std::string& ip, int port, const std::string& expected_peer_id);
    void prune_stale_peers();

    // === Identity ===
    std::string m_node_id;
    int m_udp_port;
    int m_tcp_port;
    int m_tls_port;
    int m_broadcast_fd = -1;
    int m_discovery_fd = -1;
    int m_discovery6_fd = -1;
    std::atomic<bool> m_running;

    crypto::UniquePKEY m_private_key;
    std::string m_public_key_pem;
    std::string m_public_key_b64;
    PBFTConsensus m_pbft;
    std::atomic<uint64_t> m_sequence_number{0};

    // === TLS infrastructure ===
    net::TLSConfig m_tls_config;
    std::unique_ptr<net::TransportLayer> m_transport;
    std::unique_ptr<net::PeerDiscovery> m_discovery;
    crypto::KeyManager m_key_manager;
    std::string m_tls_cert_path;
    std::string m_tls_key_path;
    std::string m_tls_cert_fingerprint;

    // === Thread handles ===
    std::thread m_listener_thread;
    std::thread m_discovery_thread;
    std::thread m_tcp_thread;
    std::thread m_tls_thread;
    std::thread m_liveness_thread;
    std::chrono::steady_clock::time_point m_last_announce_time;
    std::chrono::steady_clock::time_point m_last_targeted_at;

    // === Dependencies ===
    PolicyEnforcer* m_enforcer;
    MitigationEngine* m_mitigation;
    TelemetryBridge* m_bridge;
    StateJournal m_journal;
    std::string m_webhook_url;
    size_t m_max_evidence_size;

    // === PeerManager — consolidated peer registry, TOFU, rate limits, telemetry ===
    PeerManager m_peer_manager;

    // === Seed peers for cross-subnet unicast discovery ===
    std::vector<std::pair<std::string, int>> m_seed_peers;

    // === TLS connection task queue ===
    struct TLSConnectTask {
        std::string peer_id;
        std::string ip;
        int port;
    };
    mutable std::mutex m_tls_queue_mtx;
    std::condition_variable m_tls_queue_cv;
    std::vector<TLSConnectTask> m_tls_connect_queue;
    std::jthread m_tls_worker_thread;
    void tls_worker_loop();
};

} // namespace neuro_mesh
