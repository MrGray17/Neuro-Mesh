#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <set>
#include <unordered_map>
#include <chrono>
#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include "crypto/KeyManager.hpp"
#include "net/TransportLayer.hpp"
#include "common/StateJournal.hpp"
#include "enforcer/PolicyEnforcer.hpp"

namespace neuro_mesh {

class MitigationEngine;
class TelemetryBridge;

struct PeerInfo {
    std::string node_id;
    std::string ip;
    int tcp_port = 0;
    int tls_port = 0;
    std::string public_key_pem;
    std::chrono::steady_clock::time_point last_heartbeat;
    bool verified = false;
    int tls_fd = -1;
};

class MeshNode {
public:
    static constexpr int DISCOVERY_UDP_PORT = 9998;
    static constexpr int TCP_PORT_START    = 10000;
    static constexpr int TLS_PORT_START    = 10500;
    static constexpr int HEARTBEAT_SEC          = 5;
    static constexpr int LIVENESS_SEC           = 30;
    static constexpr int CONSENSUS_COOLDOWN_SEC = 30;

    // Constructor: starts with n=1 (self), scales up as peers are discovered.
    MeshNode(const std::string& node_id,
             PolicyEnforcer* enforcer, MitigationEngine* mitigation,
             TelemetryBridge* bridge = nullptr);
    ~MeshNode();

    void start();
    void stop();
    void initiate_consensus(const std::string& target_id, const std::string& evidence_json);

    // Telemetry gossip — each node shares its vitals so any node can serve the dashboard
    void gossip_telemetry(const std::string& telemetry_json);
    void gossip_event_json(const std::string& json);  // broadcast arbitrary event to all peers' bridges
    std::string get_mesh_telemetry() const;  // aggregated JSON of all known node telemetry

    int tcp_port() const { return m_tcp_port; }
    int tls_port() const { return m_tls_port; }
    int peer_count() const;
    std::vector<std::string> get_active_peer_ids() const;

    // Seed peers for cross-subnet discovery (env NEURO_PEERS="ip:port,ip:port")
    void set_seed_peers(const std::vector<std::pair<std::string, int>>& seeds);

    // TOFU key management — unpin a peer's key to allow rotation (manual intervention)
    void unpin_peer_key(const std::string& node_id);

    // Attack detection — true when this node is the target of a recent PBFT round
    bool is_targeted_recently() const;

    // Utility — split string by delimiter (public for testing)
    std::vector<std::string> split_string(const std::string& str, char delimiter);
    static bool try_parse_int(const std::string& s, int& out) noexcept;
    static bool try_parse_long(const std::string& s, int64_t& out) noexcept;

    // Alert webhook — POST JSON to configured endpoint on isolation
    static void notify_webhook(const std::string& url, const std::string& target_id,
                                const std::string& evidence_json, int quorum, int64_t timestamp_us);

private:
    // === Threads ===
    void p2p_listener_loop();        // PBFT consensus (UDP :9999 + TLS)
    void discovery_beacon_loop();    // UDP heartbeat broadcast (UDP :9998)
    void tcp_listener_loop();        // PEX handshake server (TCP auto-port)
    void tls_acceptor_loop();        // TLS acceptor for incoming peer connections
    void liveness_monitor();         // Peer timeout detection

    // === Messaging ===
    void process_message(const std::string& msg, const std::string& sender_ip);
    bool validate_message(const std::string& msg) const;
    void process_discovery_beacon(const std::string& msg, const std::string& sender_ip);
    void process_telemetry_gossip(const std::string& msg, const std::string& sender_ip);
    void broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json);
    void send_udp_broadcast(const std::string& payload);
    void send_udp_discovery(const std::string& payload);
    void send_udp_unicast(const std::string& ip, int port, const std::string& payload);

    // === TLS transport ===
    bool send_tls_to_peer(const std::string& peer_id, const std::string& payload);
    void send_tls_broadcast(const std::string& payload);
    bool connect_tls_to_peer(const std::string& peer_id, const std::string& ip, int port);
    void disconnect_tls_peer(const std::string& peer_id);

    // === Discovery / PEX ===
    void send_discovery_beacon();
    void announce_identity();
    bool perform_pex_handshake(const std::string& ip, int port, const std::string& expected_peer_id);
    void prune_stale_peers();

    // === Identity ===
    std::string m_node_id;
    int m_udp_port;                // PBFT consensus port (9999)
    int m_tcp_port;                // PEX handshake port (auto-assigned)
    int m_tls_port;                // TLS acceptor port (auto-assigned)
    std::atomic<bool> m_running;

    crypto::UniquePKEY m_private_key;
    std::string m_public_key_pem;
    std::string m_public_key_b64;  // base64-encoded for discovery beacons
    PBFTConsensus m_pbft;
    uint64_t m_sequence_number{0};

    // === TLS infrastructure ===
    net::TLSConfig m_tls_config;
    std::unique_ptr<net::TransportLayer> m_transport;
    std::unique_ptr<net::PeerDiscovery> m_discovery;
    crypto::KeyManager m_key_manager;
    std::string m_tls_cert_path;
    std::string m_tls_key_path;
    std::string m_tls_cert_fingerprint;  // SHA256 of TLS cert for TOFU

    // === Thread handles ===
    std::thread m_listener_thread;
    std::thread m_discovery_thread;
    std::thread m_tcp_thread;
    std::thread m_tls_thread;
    std::thread m_liveness_thread;
    std::chrono::steady_clock::time_point m_last_announce_time;
    std::chrono::steady_clock::time_point m_last_targeted_at;  // last PBFT round targeting self

    // === Peer registry (thread-safe) ===
    mutable std::shared_mutex m_peers_mtx;
    std::unordered_map<std::string, PeerInfo> m_peers;

    // === Dependencies ===
    PolicyEnforcer* m_enforcer;
    MitigationEngine* m_mitigation;
    TelemetryBridge* m_bridge;
    StateJournal m_journal;
    std::string m_webhook_url;

    // === TOFU: Trust-On-First-Use for ANNOUNCE key pinning + TLS cert pinning ===
    struct TOFUEntry {
        std::string pinned_pem;
        std::string pinned_tls_fingerprint;
        std::chrono::steady_clock::time_point first_seen;
        bool trust_frozen = false;
    };
    std::unordered_map<std::string, TOFUEntry> m_tofu_trust;
    mutable std::mutex m_tofu_mtx;

    // Verify peer TLS cert matches pinned fingerprint
    bool verify_peer_tls_cert(const std::string& peer_id, const std::string& cert_fingerprint) const;

    // === Seed peers for cross-subnet unicast discovery ===
    std::vector<std::pair<std::string, int>> m_seed_peers;

    // === Legacy peer tracking (for ANNOUNCE protocol compatibility) ===
    std::mutex m_peer_mtx;
    std::set<std::string> m_known_peer_ips;

    // === Telemetry gossip state ===
    mutable std::mutex m_telemetry_mtx;
    std::string m_own_telemetry;
    std::unordered_map<std::string, std::string> m_peer_telemetry;  // node_id -> last JSON

    // === Consensus rate limiting ===
    mutable std::mutex m_cooldown_mtx;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_last_consensus;

    // === Per-peer UDP message rate limiting ===
    struct RateLimitState {
        int count = 0;
        std::chrono::steady_clock::time_point window_start;
    };
    mutable std::mutex m_ratelimit_mtx;
    std::unordered_map<std::string, RateLimitState> m_rate_limits;
    static constexpr int RATE_LIMIT_PER_SEC = 100;
};

} // namespace neuro_mesh
