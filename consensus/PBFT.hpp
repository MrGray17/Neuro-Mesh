#pragma once
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <chrono>
#include <iostream>
#include "crypto/CryptoCore.hpp"

namespace neuro_mesh {

enum class PBFTStage { IDLE, PRE_PREPARE, PREPARE, COMMIT, EXECUTED };

struct P2PMessage {
    std::string stage_str;
    std::string sender_id;
    std::string target_id;
    std::string evidence_json;
    std::string signature;
};

class PBFTConsensus {
    static constexpr int VIEW_CHANGE_TIMEOUT_SEC = 30;
    static constexpr int ROUND_TTL_SEC = 120;

    struct ConsensusRound {
        PBFTStage state = PBFTStage::IDLE;
        int view = 0;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point last_activity;
    };

public:
    explicit PBFTConsensus(int total_nodes) : m_total_nodes(total_nodes) {}

    void register_peer_key(const std::string& node_id, const std::string& pem_key) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_peer_public_keys[node_id] = crypto::IdentityCore::get_pubkey_from_pem(pem_key);
    }

    [[nodiscard]] bool verify_message(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        auto it = m_peer_public_keys.find(msg.sender_id);
        if (it == m_peer_public_keys.end()) return false;

        // Signature binds to (stage + target + evidence) to prevent cross-stage replay
        std::string signed_blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;

        if (!crypto::IdentityCore::verify_signature(it->second.get(), signed_blob, msg.signature)) {
            std::cerr << "[PBFT] CRITICAL: Cryptographic signature mismatch from: " << msg.sender_id << std::endl;
            return false;
        }
        return true;
    }

    PBFTStage advance_state(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        // Periodic cleanup of stale rounds (runs inline, amortized over calls)
        cleanup_stale_rounds();

        auto& stage_voters = m_vote_registry[msg.evidence_json][msg.stage_str];

        // De-duplication
        if (stage_voters.find(msg.sender_id) != stage_voters.end()) {
            return PBFTStage::IDLE;
        }
        stage_voters.insert(msg.sender_id);

        ConsensusRound& round = m_rounds[msg.evidence_json];
        if (round.state == PBFTStage::IDLE) {
            round.started_at = std::chrono::steady_clock::now();
        }
        round.last_activity = std::chrono::steady_clock::now();

        int quorum = quorum_size();
        int current_votes = static_cast<int>(stage_voters.size());

        PBFTStage previous_state = round.state;

        // State machine transitions
        if (msg.stage_str == "PRE_PREPARE" && round.state == PBFTStage::IDLE) {
            round.state = PBFTStage::PREPARE;
        }
        else if (msg.stage_str == "PREPARE" && current_votes >= quorum && round.state == PBFTStage::PREPARE) {
            round.state = PBFTStage::COMMIT;
        }
        else if (msg.stage_str == "COMMIT" && current_votes >= quorum && round.state == PBFTStage::COMMIT) {
            round.state = PBFTStage::EXECUTED;
        }

        if (round.state != previous_state) {
            return round.state;
        }
        return PBFTStage::IDLE;
    }

    // Returns true if a view change should be triggered (primary unresponsive)
    [[nodiscard]] bool needs_view_change(const std::string& evidence_json) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_rounds.find(evidence_json);
        if (it == m_rounds.end()) return false;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
        return elapsed > VIEW_CHANGE_TIMEOUT_SEC && it->second.state != PBFTStage::EXECUTED;
    }

    int peer_count() const { return m_total_nodes; }
    int quorum_size() const { return (2 * std::max(1, m_total_nodes) + 2) / 3; }  // PBFT: 2f+1 = ceil(2n/3)

    // ---- Dynamic quorum limitations ----
    // WARNING: Dynamic quorum changes during active PBFT rounds can cause consistency issues.
    // If peers join/leave mid-round, the quorum threshold may shift, potentially allowing
    // a lower threshold to be met by votes collected under the previous threshold.
    // Mitigation: The implementation uses max(1, n) to prevent division-by-zero and
    // increments/decrements atomically. For production use, consider view-change protocol
    // or round invalidation when peer count changes mid-round.

    // ---- Dynamic quorum management ----
    void set_peer_count(int n) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_total_nodes = std::max(1, n);
    }

    void increment_peers() {
        std::lock_guard<std::mutex> lock(m_mtx);
        ++m_total_nodes;
    }

    void decrement_peers() {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_total_nodes = std::max(1, m_total_nodes - 1);
    }

    void prune_peer(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_peer_public_keys.erase(node_id);
        for (auto& [evidence, stage_map] : m_vote_registry) {
            for (auto& [stage, voters] : stage_map) {
                voters.erase(node_id);
            }
        }
        m_total_nodes = std::max(1, m_total_nodes - 1);
    }

private:
    void cleanup_stale_rounds() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_rounds.begin(); it != m_rounds.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
            if (elapsed > ROUND_TTL_SEC) {
                m_vote_registry.erase(it->first);
                it = m_rounds.erase(it);
            } else {
                ++it;
            }
        }
    }

    int m_total_nodes;
    mutable std::mutex m_mtx;

    std::map<std::string, std::map<std::string, std::set<std::string>>> m_vote_registry;
    std::map<std::string, crypto::UniquePKEY> m_peer_public_keys;
    std::map<std::string, ConsensusRound> m_rounds;
};

} // namespace neuro_mesh
