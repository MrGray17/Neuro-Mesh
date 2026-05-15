#pragma once
#include <string>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <optional>
#include <vector>
#include <sstream>
#include <iomanip>
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
    std::string prev_message_hash;
    uint64_t sequence_number = 0;
    int view = 0;
};

struct EquivocationEvidence {
    std::string node_id;
    uint64_t sequence_number;
    int view;
    std::string hash1;
    std::string hash2;
    std::chrono::steady_clock::time_point detected_at;
};

class PBFTConsensus {
public:
    static constexpr int VIEW_CHANGE_TIMEOUT_SEC = 30;
    static constexpr int ROUND_TTL_SEC = 120;
    static constexpr int MAX_SEQUENCE_GAP = 100;

private:
    struct ConsensusRound {
        PBFTStage state = PBFTStage::IDLE;
        int view = 0;
        uint64_t sequence = 0;
        std::string pre_prepare_hash;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point last_activity;
    };

    struct ViewChangeProof {
        int new_view;
        uint64_t last_sequence;
        std::string last_hash;
        std::map<std::string, std::string> voter_signatures;
    };

    struct NodeTrustScore {
        int equivocation_count = 0;
        int consecutive_failures = 0;
        int successful_rounds = 0;
        std::chrono::steady_clock::time_point last_failure;
        double trust_score = 1.0;
    };

public:
    explicit PBFTConsensus(int total_nodes) : m_total_nodes(total_nodes) {
        m_genesis_hash = crypto::IdentityCore::sha256_hex("GENESIS");
    }

    void register_peer_key(const std::string& node_id, const std::string& pem_key) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_peer_public_keys[node_id] = crypto::IdentityCore::get_pubkey_from_pem(pem_key);
        m_node_trust[node_id] = NodeTrustScore{};
    }

    void set_my_identity(const std::string& node_id) {
        m_my_node_id = node_id;
    }

    void set_private_key(crypto::UniquePKEY key) {
        m_private_key = std::move(key);
    }

    std::string compute_message_hash(const P2PMessage& msg) const {
        std::stringstream ss;
        ss << msg.stage_str << "|" << msg.sender_id << "|" << msg.target_id << "|"
           << msg.evidence_json << "|" << msg.prev_message_hash << "|"
           << msg.sequence_number << "|" << msg.view;
        return crypto::IdentityCore::sha256_hex(ss.str());
    }

    std::string sign_message(const P2PMessage& msg) const {
        if (!m_private_key) return "";
        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view);
        return crypto::IdentityCore::sign_payload(m_private_key.get(), blob);
    }

    [[nodiscard]] bool verify_message(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        auto it = m_peer_public_keys.find(msg.sender_id);
        if (it == m_peer_public_keys.end()) return false;

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view);

        if (!crypto::IdentityCore::verify_signature(it->second.get(), blob, msg.signature)) {
            std::cerr << "[PBFT] CRITICAL: Cryptographic signature mismatch from: " << msg.sender_id << std::endl;
            record_failure(msg.sender_id);
            return false;
        }

        if (!verify_message_chaining(msg)) {
            std::cerr << "[PBFT] CRITICAL: Message chain verification failed from: " << msg.sender_id << std::endl;
            return false;
        }

        if (!verify_sequence_continuity(msg)) {
            std::cerr << "[PBFT] CRITICAL: Sequence gap detected from: " << msg.sender_id << std::endl;
            return false;
        }

        record_success(msg.sender_id);
        return true;
    }

    PBFTStage advance_state(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        cleanup_stale_rounds();

        auto msg_hash = compute_message_hash(msg);
        detect_equivocation(msg, msg_hash);

        auto& stage_voters = m_vote_registry[msg.evidence_json][msg.stage_str];

        if (stage_voters.find(msg.sender_id) != stage_voters.end()) {
            return PBFTStage::IDLE;
        }
        stage_voters.insert(msg.sender_id);

        ConsensusRound& round = m_rounds[msg.evidence_json];
        if (round.state == PBFTStage::IDLE) {
            round.started_at = std::chrono::steady_clock::now();
            round.view = msg.view;
            round.sequence = msg.sequence_number;
            round.pre_prepare_hash = msg_hash;
        }

        if (round.view != msg.view) {
            std::cerr << "[PBFT] View mismatch for " << msg.evidence_json << std::endl;
            return PBFTStage::IDLE;
        }

        if (msg.sequence_number < round.sequence) {
            std::cerr << "[PBFT] Old sequence ignored: " << msg.sequence_number << " < " << round.sequence << std::endl;
            return PBFTStage::IDLE;
        }

        round.last_activity = std::chrono::steady_clock::now();

        int quorum = quorum_size();
        int current_votes = static_cast<int>(stage_voters.size());

        PBFTStage previous_state = round.state;

        if (msg.stage_str == "PRE_PREPARE" && round.state == PBFTStage::IDLE) {
            round.state = PBFTStage::PREPARE;
        }
        else if (msg.stage_str == "PREPARE" && current_votes >= quorum && round.state == PBFTStage::PREPARE) {
            if (!verify_quorum_intersection(msg.evidence_json, msg_hash)) {
                std::cerr << "[PBFT] QUORUM INTERSECTION FAILED - possible partition attack" << std::endl;
                return PBFTStage::IDLE;
            }
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

    [[nodiscard]] bool needs_view_change(const std::string& evidence_json) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_rounds.find(evidence_json);
        if (it == m_rounds.end()) return false;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
        return elapsed > VIEW_CHANGE_TIMEOUT_SEC && it->second.state != PBFTStage::EXECUTED;
    }

    int peer_count() const { return m_total_nodes; }
    int quorum_size() const { return (2 * std::max(1, m_total_nodes) + 2) / 3; }

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
        m_node_trust.erase(node_id);
        m_message_history.erase(node_id);
        for (auto& [evidence, stage_map] : m_vote_registry) {
            for (auto& [stage, voters] : stage_map) {
                voters.erase(node_id);
            }
        }
        m_total_nodes = std::max(1, m_total_nodes - 1);
    }

    double get_node_trust(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_node_trust.find(node_id);
        return it != m_node_trust.end() ? it->second.trust_score : 0.0;
    }

    std::vector<EquivocationEvidence> get_equivocation_evidence() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::vector<EquivocationEvidence> result;
        for (const auto& e : m_equivocation_history) {
            result.push_back(e.second);
        }
        return result;
    }

    std::string get_chain_state_hash() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::stringstream ss;
        ss << m_last_confirmed_hash << "|" << m_total_nodes << "|" << m_current_view;
        return crypto::IdentityCore::sha256_hex(ss.str());
    }

    int current_view() const { return m_current_view; }

    void advance_view() {
        std::lock_guard<std::mutex> lock(m_mtx);
        ++m_current_view;
        std::cout << "[PBFT] View advanced to " << m_current_view << std::endl;
    }

private:
    bool verify_message_chaining(const P2PMessage& msg) const {
        if (msg.prev_message_hash.empty()) {
            return msg.sequence_number == 0;
        }

        auto history_it = m_message_history.find(msg.sender_id);
        if (history_it == m_message_history.end()) {
            return msg.sequence_number == 0;
        }

        const auto& history = history_it->second;
        auto prev_it = history.find(msg.sequence_number - 1);
        if (prev_it == history.end()) {
            return msg.sequence_number == 0;
        }

        return prev_it->second == msg.prev_message_hash;
    }

    bool verify_sequence_continuity(const P2PMessage& msg) const {
        auto history_it = m_message_history.find(msg.sender_id);
        if (history_it == m_message_history.end()) {
            return true;
        }

        const auto& history = history_it->second;
        if (history.empty()) return true;

        uint64_t max_seq = 0;
        for (const auto& [seq, _] : history) {
            max_seq = std::max(max_seq, seq);
        }

        if (msg.sequence_number > max_seq + MAX_SEQUENCE_GAP) {
            return false;
        }

        return true;
    }

    bool verify_quorum_intersection(const std::string& evidence, const std::string& expected_hash) const {
        auto prep_it = m_vote_registry.find(evidence);
        if (prep_it == m_vote_registry.end()) return true;

        auto prep_voters_it = prep_it->second.find("PREPARE");
        if (prep_voters_it == prep_it->second.end()) return true;

        const auto& prepare_voters = prep_voters_it->second;
        if (prepare_voters.size() < static_cast<size_t>(quorum_size())) return true;

        std::set<std::string> prep_set(prepare_voters.begin(), prepare_voters.end());

        auto commit_it = prep_it->second.find("COMMIT");
        if (commit_it == prep_it->second.end()) return true;

        const auto& commit_voters = commit_it->second;
        std::set<std::string> commit_set(commit_voters.begin(), commit_voters.end());

        std::vector<std::string> intersection;
        std::set_intersection(prep_set.begin(), prep_set.end(),
                             commit_set.begin(), commit_set.end(),
                             std::back_inserter(intersection));

        return static_cast<int>(intersection.size()) >= quorum_size();
    }

    void detect_equivocation(const P2PMessage& msg, const std::string& msg_hash) {
        auto& history = m_message_history[msg.sender_id];

        auto it = history.find(msg.sequence_number);
        if (it != history.end() && it->second != msg_hash) {
            EquivocationEvidence evidence;
            evidence.node_id = msg.sender_id;
            evidence.sequence_number = msg.sequence_number;
            evidence.view = msg.view;
            evidence.hash1 = it->second;
            evidence.hash2 = msg_hash;
            evidence.detected_at = std::chrono::steady_clock::now();

            m_equivocation_history[msg.sender_id] = evidence;
            record_equivocation(msg.sender_id);

            std::cerr << "[PBFT] EQUIVOCATION DETECTED: " << msg.sender_id
                      << " seq=" << msg.sequence_number << " view=" << msg.view << std::endl;
        }

        history[msg.sequence_number] = msg_hash;
    }

    void record_equivocation(const std::string& node_id) {
        auto& trust = m_node_trust[node_id];
        trust.equivocation_count++;
        trust.trust_score = std::max(0.0, trust.trust_score - 0.3);
        trust.consecutive_failures++;
        trust.last_failure = std::chrono::steady_clock::now();
    }

    void record_failure(const std::string& node_id) {
        auto& trust = m_node_trust[node_id];
        trust.consecutive_failures++;
        trust.trust_score = std::max(0.0, trust.trust_score - 0.1);
        trust.last_failure = std::chrono::steady_clock::now();

        if (trust.consecutive_failures > 5) {
            std::cerr << "[PBFT] WARNING: Node " << node_id << " has " 
                      << trust.consecutive_failures << " consecutive failures" << std::endl;
        }
    }

    void record_success(const std::string& node_id) {
        auto& trust = m_node_trust[node_id];
        if (trust.consecutive_failures > 0) {
            trust.consecutive_failures = 0;
        }
        trust.successful_rounds++;
        trust.trust_score = std::min(1.0, trust.trust_score + 0.05);
    }

    void cleanup_stale_rounds() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_rounds.begin(); it != m_rounds.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
            if (elapsed > ROUND_TTL_SEC) {
                if (it->second.state == PBFTStage::EXECUTED) {
                    m_last_confirmed_hash = it->first;
                }
                m_vote_registry.erase(it->first);
                it = m_rounds.erase(it);
            } else {
                ++it;
            }
        }
    }

    int m_total_nodes;
    int m_current_view = 0;
    mutable std::mutex m_mtx;

    std::string m_genesis_hash;
    std::string m_last_confirmed_hash;
    std::string m_my_node_id;
    crypto::UniquePKEY m_private_key;

    std::map<std::string, std::map<std::string, std::set<std::string>>> m_vote_registry;
    std::map<std::string, crypto::UniquePKEY> m_peer_public_keys;
    std::map<std::string, ConsensusRound> m_rounds;

    std::unordered_map<std::string, NodeTrustScore> m_node_trust;
    std::unordered_map<std::string, std::map<uint64_t, std::string>> m_message_history;
    std::map<std::string, EquivocationEvidence> m_equivocation_history;
};

} // namespace neuro_mesh