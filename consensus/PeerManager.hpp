#pragma once
#include <string>
#include <vector>
#include <set>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <chrono>
#include "consensus/PBFT.hpp"

namespace neuro_mesh {

struct PeerEntry {
    std::string node_id;
    std::string ip;
    int tcp_port = 0;
    int tls_port = 0;
    std::string public_key_pem;
    std::chrono::steady_clock::time_point last_heartbeat;
    bool verified = false;
    int tls_fd = -1;
};

class PeerManager {
public:
    static constexpr int RATE_LIMIT_PER_SEC = 100;
    static constexpr int CONSENSUS_COOLDOWN_SEC = 30;
    static constexpr int LIVENESS_SEC = 30;

    PeerManager() = default;
    ~PeerManager() = default;

    // Non-copyable, non-movable (contains mutexes)
    PeerManager(const PeerManager&) = delete;
    PeerManager& operator=(const PeerManager&) = delete;
    PeerManager(PeerManager&&) = delete;
    PeerManager& operator=(PeerManager&&) = delete;

    // === Peer registry ===
    bool add_peer(const std::string& peer_id, const std::string& ip,
                  int tcp_port, int tls_port, const std::string& public_key_pem);
    bool update_peer_heartbeat(const std::string& peer_id, const std::string& ip,
                               int tcp_port, int tls_port, const std::string& public_key_pem);
    bool has_peer(const std::string& peer_id) const;
    PeerEntry get_peer(const std::string& peer_id) const;
    std::vector<PeerEntry> get_all_peers() const;
    std::vector<std::string> get_all_peer_ids() const;
    int peer_count() const;
    void remove_peer(const std::string& peer_id);
    std::vector<std::string> get_stale_peers() const;

    // === Peer info access ===
    bool get_peer_tls_fd(const std::string& peer_id, int& fd) const;
    void set_peer_tls_fd(const std::string& peer_id, int fd);
    std::string get_peer_key(const std::string& peer_id) const;
    bool is_peer_verified(const std::string& peer_id) const;

    // === TOFU trust ===
    bool verify_tls_cert(const std::string& peer_id, const std::string& cert_fingerprint);
    void unpin_peer_key(const std::string& node_id);
    void pin_tls_fingerprint(const std::string& peer_id, const std::string& fingerprint);

    // === Rate limiting ===
    bool check_rate_limit(const std::string& ip);
    void reset_rate_limit(const std::string& ip);

    // === Consensus cooldown ===
    bool is_on_cooldown(const std::string& target_id) const;
    void set_cooldown(const std::string& target_id);

    // === Telemetry gossip state ===
    void set_own_telemetry(const std::string& json);
    std::string get_own_telemetry() const;
    void set_peer_telemetry(const std::string& peer_id, const std::string& json);
    std::string get_all_telemetry() const;

    // === Known IP tracking ===
    bool is_known_ip(const std::string& ip) const;
    void add_known_ip(const std::string& ip);

    // === PBFT ==
    void register_all_with_pbft(PBFTConsensus& pbft) const;
    void register_one_with_pbft(PBFTConsensus& pbft, const std::string& peer_id) const;

private:
    mutable std::shared_mutex m_peers_mtx;
    std::unordered_map<std::string, PeerEntry> m_peers;

    struct TOFUEntry {
        std::string pinned_tls_fingerprint;
        std::chrono::steady_clock::time_point first_seen;
    };
    mutable std::mutex m_tofu_mtx;
    std::unordered_map<std::string, TOFUEntry> m_tofu_trust;

    struct RateLimitState {
        int count = 0;
        std::chrono::steady_clock::time_point window_start;
    };
    mutable std::mutex m_ratelimit_mtx;
    std::unordered_map<std::string, RateLimitState> m_rate_limits;

    mutable std::mutex m_cooldown_mtx;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_last_consensus;

    mutable std::mutex m_telemetry_mtx;
    std::string m_own_telemetry;
    std::unordered_map<std::string, std::string> m_peer_telemetry;

    mutable std::mutex m_known_ip_mtx;
    std::set<std::string> m_known_peer_ips;
};

} // namespace neuro_mesh
