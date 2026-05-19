#include "consensus/PeerManager.hpp"
#include <iostream>
#include <algorithm>

namespace neuro_mesh {

// =============================================================================
// Peer registry
// =============================================================================

bool PeerManager::add_peer(const std::string& peer_id, const std::string& ip,
                           int tcp_port, int tls_port, const std::string& public_key_pem) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
    if (m_peers.find(peer_id) != m_peers.end()) return false;
    PeerEntry pe;
    pe.node_id = peer_id;
    pe.ip = ip;
    pe.tcp_port = tcp_port;
    pe.tls_port = tls_port;
    pe.public_key_pem = public_key_pem;
    pe.last_heartbeat = std::chrono::steady_clock::now();
    pe.verified = !public_key_pem.empty();
    m_peers[peer_id] = pe;
    return true;
}

bool PeerManager::update_peer_heartbeat(const std::string& peer_id, const std::string& ip,
                                        int tcp_port, int tls_port, const std::string& public_key_pem) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end()) return false;
    it->second.last_heartbeat = std::chrono::steady_clock::now();
    it->second.ip = ip;
    it->second.tcp_port = tcp_port;
    it->second.tls_port = tls_port;
    if (!public_key_pem.empty() && it->second.public_key_pem.empty()) {
        it->second.public_key_pem = public_key_pem;
        it->second.verified = true;
    }
    return true;
}

bool PeerManager::has_peer(const std::string& peer_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    return m_peers.find(peer_id) != m_peers.end();
}

PeerEntry PeerManager::get_peer(const std::string& peer_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    return it != m_peers.end() ? it->second : PeerEntry{};
}

std::vector<PeerEntry> PeerManager::get_all_peers() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    std::vector<PeerEntry> result;
    result.reserve(m_peers.size());
    for (const auto& [id, entry] : m_peers) result.push_back(entry);
    return result;
}

std::vector<std::string> PeerManager::get_all_peer_ids() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    std::vector<std::string> ids;
    ids.reserve(m_peers.size());
    for (const auto& [id, _] : m_peers) ids.push_back(id);
    return ids;
}

int PeerManager::peer_count() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    return static_cast<int>(m_peers.size());
}

void PeerManager::remove_peer(const std::string& peer_id) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
    m_peers.erase(peer_id);
}

std::vector<std::string> PeerManager::get_stale_peers() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    std::vector<std::string> stale;
    auto now = std::chrono::steady_clock::now();
    for (const auto& [id, info] : m_peers) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - info.last_heartbeat).count();
        if (elapsed > LIVENESS_SEC) stale.push_back(id);
    }
    return stale;
}

// =============================================================================
// Peer info access
// =============================================================================

bool PeerManager::get_peer_tls_fd(const std::string& peer_id, int& fd) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end() || it->second.tls_fd < 0) return false;
    fd = it->second.tls_fd;
    return true;
}

void PeerManager::set_peer_tls_fd(const std::string& peer_id, int fd) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end()) it->second.tls_fd = fd;
}

std::string PeerManager::get_peer_key(const std::string& peer_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    return it != m_peers.end() ? it->second.public_key_pem : "";
}

bool PeerManager::is_peer_verified(const std::string& peer_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    return it != m_peers.end() && it->second.verified;
}

// =============================================================================
// TOFU trust
// =============================================================================

bool PeerManager::verify_tls_cert(const std::string& peer_id, const std::string& cert_fingerprint) {
    std::lock_guard<std::mutex> lock(m_tofu_mtx);
    auto it = m_tofu_trust.find(peer_id);
    if (it == m_tofu_trust.end()) return true;
    if (it->second.pinned_tls_fingerprint.empty()) return true;
    return it->second.pinned_tls_fingerprint == cert_fingerprint;
}

void PeerManager::unpin_peer_key(const std::string& node_id) {
    {
        std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
        auto it = m_peers.find(node_id);
        if (it != m_peers.end()) {
            it->second.public_key_pem.clear();
            it->second.verified = false;
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_tofu_mtx);
        m_tofu_trust.erase(node_id);
    }
}

void PeerManager::pin_tls_fingerprint(const std::string& peer_id, const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(m_tofu_mtx);
    auto& entry = m_tofu_trust[peer_id];
    entry.pinned_tls_fingerprint = fingerprint;
    if (entry.first_seen == std::chrono::steady_clock::time_point{}) {
        entry.first_seen = std::chrono::steady_clock::now();
    }
}

// =============================================================================
// Pre-provisioned peer keys (optional hardening)
// =============================================================================

void PeerManager::pre_provision_peer_key(const std::string& peer_id, const std::string& public_key_pem) {
    std::lock_guard<std::mutex> lock(m_preprov_mtx);
    m_pre_provisioned_keys[peer_id] = public_key_pem;
}

bool PeerManager::is_peer_pre_provisioned(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(m_preprov_mtx);
    return m_pre_provisioned_keys.find(peer_id) != m_pre_provisioned_keys.end();
}

// =============================================================================
// Dual-path TOFU confirmation
// =============================================================================

PeerManager::PathConfirmResult PeerManager::confirm_path(const std::string& peer_id,
    uint8_t path_flag, const std::string& public_key_pem) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    if (it == m_peers.end()) {
        return {false, false};
    }

    auto& entry = it->second;

    // Check pre-provisioned key first — if set, verify and bypass TOFU.
    {
        std::lock_guard<std::mutex> prov_lock(m_preprov_mtx);
        auto prov_it = m_pre_provisioned_keys.find(peer_id);
        if (prov_it != m_pre_provisioned_keys.end()) {
            // Peer is pre-provisioned — verify key matches, reject on mismatch.
            if (!public_key_pem.empty() && prov_it->second != public_key_pem) {
                std::cerr << "[SECURITY] PRE-PROVISIONED key MISMATCH for " << peer_id
                          << " — received key does not match expected key. Rejecting peer." << std::endl;
                return {false, true};
            }
            // Key matches pre-provisioned value — mark both paths as confirmed
            // immediately (no TOFU needed for known peers).
            entry.confirmed_paths |= path_flag;
            if (!public_key_pem.empty() && entry.public_key_pem.empty()) {
                entry.public_key_pem = public_key_pem;
                entry.verified = true;
            }
            bool dual = (entry.confirmed_paths & (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE)) ==
                        (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE);
            return {dual, false};
        }
    }

    // No pre-provisioned key — fall back to dual-path TOFU.
    if (entry.confirmed_paths & path_flag) {
        if (!public_key_pem.empty() && entry.public_key_pem != public_key_pem) {
            return {false, true};
        }
        return {(entry.confirmed_paths & (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE)) ==
                    (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE),
                false};
    }

    if (entry.confirmed_paths != 0 && !entry.public_key_pem.empty()) {
        if (!public_key_pem.empty() && entry.public_key_pem != public_key_pem) {
            std::cerr << "[SECURITY] TOFU dual-path MISMATCH for " << peer_id
                      << " — beacon and ANNOUNCE keys differ. Rejecting peer." << std::endl;
            return {false, true};
        }
    }

    entry.confirmed_paths |= path_flag;
    if (!public_key_pem.empty() && entry.public_key_pem.empty()) {
        entry.public_key_pem = public_key_pem;
        entry.verified = true;
    }

    bool dual = (entry.confirmed_paths & (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE)) ==
                (PeerEntry::PATH_BEACON | PeerEntry::PATH_ANNOUNCE);
    return {dual, false};
}

// =============================================================================
// Rate limiting
// =============================================================================

bool PeerManager::check_rate_limit(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_ratelimit_mtx);
    auto now = std::chrono::steady_clock::now();
    auto& rl = m_rate_limits[ip];
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now - rl.window_start).count();
    if (elapsed >= 1000) {
        rl.window_start = now;
        rl.count = 0;
    }
    if (++rl.count > RATE_LIMIT_PER_SEC) {
        if (rl.count == RATE_LIMIT_PER_SEC + 1) {
            std::cerr << "[DEFENSE] Rate-limited peer " << ip
                      << " (>=" << RATE_LIMIT_PER_SEC << " msg/sec)." << std::endl;
        }
        return false;
    }

    // Evict stale entries to prevent unbounded map growth from unique source IPs.
    // Periodically sweep when the map exceeds the cap — remove entries whose
    // window_start is older than RATE_LIMIT_EVICT_SEC seconds.
    if (m_rate_limits.size() > static_cast<size_t>(RATE_LIMIT_MAP_CAP)) {
        for (auto it = m_rate_limits.begin(); it != m_rate_limits.end(); ) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                           now - it->second.window_start).count();
            if (age > RATE_LIMIT_EVICT_SEC) it = m_rate_limits.erase(it);
            else ++it;
        }
        // If still over cap after stale eviction, evict the single oldest entry.
        if (m_rate_limits.size() > static_cast<size_t>(RATE_LIMIT_MAP_CAP)) {
            auto oldest = m_rate_limits.begin();
            for (auto it = std::next(m_rate_limits.begin()); it != m_rate_limits.end(); ++it) {
                if (it->second.window_start < oldest->second.window_start) oldest = it;
            }
            m_rate_limits.erase(oldest);
        }
    }

    return true;
}

void PeerManager::reset_rate_limit(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_ratelimit_mtx);
    m_rate_limits.erase(ip);
}

// =============================================================================
// Consensus cooldown
// =============================================================================

bool PeerManager::is_on_cooldown(const std::string& target_id) const {
    std::lock_guard<std::mutex> lock(m_cooldown_mtx);
    auto it = m_last_consensus.find(target_id);
    if (it == m_last_consensus.end()) return false;
    auto elapsed = std::chrono::steady_clock::now() - it->second;
    return std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < CONSENSUS_COOLDOWN_SEC;
}

void PeerManager::set_cooldown(const std::string& target_id) {
    std::lock_guard<std::mutex> lock(m_cooldown_mtx);
    m_last_consensus[target_id] = std::chrono::steady_clock::now();
}

// =============================================================================
// Telemetry
// =============================================================================

void PeerManager::set_own_telemetry(const std::string& json) {
    std::lock_guard<std::mutex> lock(m_telemetry_mtx);
    m_own_telemetry = json;
}

std::string PeerManager::get_own_telemetry() const {
    std::lock_guard<std::mutex> lock(m_telemetry_mtx);
    return m_own_telemetry;
}

void PeerManager::set_peer_telemetry(const std::string& peer_id, const std::string& json) {
    std::lock_guard<std::mutex> lock(m_telemetry_mtx);
    m_peer_telemetry[peer_id] = json;
}

std::string PeerManager::get_all_telemetry() const {
    std::lock_guard<std::mutex> lock(m_telemetry_mtx);
    std::string result = "[";
    bool first = true;
    if (!m_own_telemetry.empty()) {
        result += m_own_telemetry;
        first = false;
    }
    for (const auto& [id, json] : m_peer_telemetry) {
        if (!first) result += ",";
        result += json;
        first = false;
    }
    result += "]";
    return result;
}

// =============================================================================
// Known IP tracking
// =============================================================================

bool PeerManager::is_known_ip(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(m_known_ip_mtx);
    return m_known_peer_ips.find(ip) != m_known_peer_ips.end();
}

void PeerManager::add_known_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_known_ip_mtx);
    m_known_peer_ips.insert(ip);
}

// =============================================================================
// PBFT
// =============================================================================

void PeerManager::register_all_with_pbft(PBFTConsensus& pbft) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    for (const auto& [id, entry] : m_peers) {
        if (!entry.public_key_pem.empty()) {
            pbft.register_peer_key(id, entry.public_key_pem);
        }
    }
}

void PeerManager::register_one_with_pbft(PBFTConsensus& pbft, const std::string& peer_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    auto it = m_peers.find(peer_id);
    if (it != m_peers.end() && !it->second.public_key_pem.empty()) {
        pbft.register_peer_key(peer_id, it->second.public_key_pem);
    }
}

} // namespace neuro_mesh
