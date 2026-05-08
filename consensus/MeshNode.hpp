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
#include "common/StateJournal.hpp"
#include "jailer/SystemJailer.hpp"

namespace neuro_mesh {

class MitigationEngine;
class TelemetryBridge;

struct PeerInfo {
    std::string node_id;
    std::string ip;
    int tcp_port = 0;
    std::string public_key_pem;
    std::chrono::steady_clock::time_point last_heartbeat;
    bool verified = false;
};

class MeshNode {
public:
    static constexpr int DISCOVERY_UDP_PORT = 9998;
    static constexpr int TCP_PORT_START    = 10000;
    static constexpr int HEARTBEAT_SEC     = 5;
    static constexpr int LIVENESS_SEC      = 30;

    // Constructor: starts with n=1 (self), scales up as peers are discovered.
    MeshNode(const std::string& node_id,
             SystemJailer* jailer, MitigationEngine* mitigation,
             TelemetryBridge* bridge = nullptr);
    ~MeshNode();

    void start();
    void stop();
    void initiate_threat_consensus(const std::string& target_id, const std::string& evidence_json);

    int tcp_port() const { return m_tcp_port; }
    int peer_count() const;
    std::vector<std::string> get_active_peer_ids() const;

private:
    // === Threads ===
    void p2p_listener_loop();        // PBFT consensus (UDP :9999)
    void discovery_beacon_loop();    // UDP heartbeat broadcast (UDP :9998)
    void tcp_listener_loop();        // PEX handshake server (TCP auto-port)
    void liveness_monitor();         // Peer timeout detection

    // === Messaging ===
    void process_message(const std::string& msg, const std::string& sender_ip);
    void process_discovery_beacon(const std::string& msg, const std::string& sender_ip);
    void broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json);
    void send_udp_broadcast(const std::string& payload);
    void send_udp_discovery(const std::string& payload);

    // === Discovery / PEX ===
    void send_discovery_beacon();
    void announce_identity();
    bool perform_pex_handshake(const std::string& ip, int port, const std::string& expected_peer_id);
    void add_verified_peer(const std::string& node_id, const std::string& ip,
                           int tcp_port, const std::string& public_key_pem);
    void prune_stale_peers();
    std::vector<std::string> split_string(const std::string& str, char delimiter);

    // === Identity ===
    std::string m_node_id;
    int m_udp_port;                // PBFT consensus port (9999)
    int m_tcp_port;                // PEX handshake port (auto-assigned)
    std::atomic<bool> m_running;

    crypto::UniquePKEY m_private_key;
    std::string m_public_key_pem;
    std::string m_public_key_b64;  // base64-encoded for discovery beacons
    PBFTConsensus m_pbft;

    // === Thread handles ===
    std::thread m_listener_thread;
    std::thread m_discovery_thread;
    std::thread m_tcp_thread;
    std::thread m_liveness_thread;
    std::chrono::steady_clock::time_point m_last_announce_time;

    // === Peer registry (thread-safe) ===
    mutable std::shared_mutex m_peers_mtx;
    std::unordered_map<std::string, PeerInfo> m_peers;

    // === Dependencies ===
    SystemJailer* m_jailer;
    MitigationEngine* m_mitigation;
    TelemetryBridge* m_bridge;
    StateJournal m_journal;

    // === Legacy peer tracking (for ANNOUNCE protocol compatibility) ===
    std::mutex m_peer_mtx;
    std::set<std::string> m_known_peer_ips;
};

} // namespace neuro_mesh
