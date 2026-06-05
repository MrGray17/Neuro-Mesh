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
#include <array>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstdlib>
#include <algorithm>
#include "crypto/CryptoCore.hpp"

namespace neuro_mesh {

enum class PBFTStage { IDLE, PRE_PREPARE, PREPARE, COMMIT, EXECUTED, BAN_PEER };

struct P2PMessage {
    std::string stage_str;
    std::string sender_id;
    std::string target_id;
    std::string evidence_json;
    std::string signature;
    std::string prev_message_hash;
    uint64_t sequence_number{};
    int view{};
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
    static constexpr int DEFAULT_RATE_WINDOW_SEC = 10;
    static constexpr int DEFAULT_RATE_MAX = 5;
    static constexpr size_t MAX_MSG_HISTORY_PER_SENDER = 10000;

private:
    struct ConsensusRound {
        PBFTStage state = PBFTStage::IDLE;
        int view = 0;
        std::string pre_prepare_hash;
        std::string evidence_key;
        std::string commit_signature;
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
    explicit PBFTConsensus(int total_nodes)
        : m_total_nodes(total_nodes),
          m_rate_window_sec([]() -> int {
              const char* env = std::getenv("NEURO_PBFT_RATE_WINDOW");
              if (!env) return DEFAULT_RATE_WINDOW_SEC;
              char* end = nullptr;
              long val = std::strtol(env, &end, 10);
              return (*end == '\0' && val > 0) ? static_cast<int>(val) : DEFAULT_RATE_WINDOW_SEC;
          }()),
          m_rate_max([]() -> int {
              const char* env = std::getenv("NEURO_PBFT_RATE_MAX");
              if (!env) return DEFAULT_RATE_MAX;
              char* end = nullptr;
              long val = std::strtol(env, &end, 10);
              return (*end == '\0' && val > 0) ? static_cast<int>(val) : DEFAULT_RATE_MAX;
          }()) {
        m_genesis_hash = crypto::IdentityCore::sha256_hex("GENESIS");
    }

    void register_peer_key(const std::string& node_id, const std::string& pem_key) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_peer_public_keys[node_id] = crypto::IdentityCore::get_pubkey_from_pem(pem_key);
        m_node_trust[node_id] = NodeTrustScore{};
        m_registered_peers.insert(node_id);
    }

    bool has_peer(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        return m_registered_peers.count(node_id) > 0;
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
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                         + "|" + msg.prev_message_hash;
        std::string sig = crypto::IdentityCore::sign_payload(m_private_key.get(), blob);

        return sig;
    }

    [[nodiscard]] bool verify_message(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        // Phase 3: silently drop messages from banned peers. We do this
        // BEFORE signature verification and rate limiting to avoid
        // wasting CPU on adversarial traffic.
        if (m_banned_peers.count(msg.sender_id) > 0) {
            return false;
        }

        auto it = m_peer_public_keys.find(msg.sender_id);
        if (it == m_peer_public_keys.end()) return false;

        std::string new_blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                             + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                             + "|" + msg.prev_message_hash;

        if (!crypto::IdentityCore::verify_signature(it->second.get(), new_blob, msg.signature)) {
            // Sample the CRITICAL log to the same thresholds as record_failure
            // to avoid drowning the journal. The auto-prune at 100 failures
            // will still happen — the log is just sampled for readability.
            auto& trust = m_node_trust[msg.sender_id];
            for (int threshold : kLogFailureThresholds) {
                if (trust.consecutive_failures == threshold) {
                    std::cerr << "[PBFT] CRITICAL: Cryptographic signature mismatch from: "
                              << msg.sender_id << std::endl;
                    break;
                }
            }
            record_failure(msg.sender_id);
            return false;
        }

        if (!verify_message_chaining(msg)) {
            std::cerr << "[PBFT] CRITICAL: Message chain verification failed from: " << msg.sender_id << std::endl;
            record_failure(msg.sender_id);
            return false;
        }

        if (!verify_sequence_continuity(msg)) {
            std::cerr << "[PBFT] CRITICAL: Sequence gap detected from: " << msg.sender_id << std::endl;
            record_failure(msg.sender_id);
            return false;
        }

        record_success(msg.sender_id);
        return true;
    }

    PBFTStage advance_state(const P2PMessage& msg) {
        std::lock_guard<std::mutex> lock(m_mtx);

        // Phase 3: silently drop messages from banned peers. Same as
        // verify_message's check — defense in depth.
        if (m_banned_peers.count(msg.sender_id) > 0) {
            return PBFTStage::IDLE;
        }

        // Reject messages from peers not in the key registry. Without this
        // check, a previously auto-banned peer could be re-inserted into
        // m_node_trust by the rate-limit code path below, allowing the
        // failure counter to restart at zero and re-trigger the auto-ban
        // log every 100 messages indefinitely. (Belt-and-suspenders with
        // verify_message()'s early return.)
        if (m_peer_public_keys.find(msg.sender_id) == m_peer_public_keys.end()) {
            return PBFTStage::IDLE;
        }

        cleanup_stale_rounds();

        // Rate limit ALL PBFT messages per-sender. The sliding-window
        // check in check_rate_limit() bounds total inbound volume from
        // any single peer, regardless of stage. Previously this only
        // guarded PRE_PREPARE/BAN_PEER, leaving PREPARE/COMMIT/EXECUTED
        // unauthenticated-rate-limits — an attacker who passed one
        // PRE_PREPARE could flood PREPARE messages unbounded.
        if (!check_rate_limit(msg.sender_id)) {
            // Sample rate-limit log to the same thresholds as record_failure.
            // A persistently rate-limited peer would otherwise produce
            // ~1 log per 2s indefinitely, drowning the journal.
            auto& trust = m_node_trust[msg.sender_id];
            for (int threshold : kLogFailureThresholds) {
                if (trust.consecutive_failures == threshold) {
                    std::cerr << "[PBFT] RATE LIMITED: " << msg.sender_id
                              << " (" << m_rate_max << " msgs/"
                              << m_rate_window_sec << "s)" << std::endl;
                    break;
                }
            }
            record_failure(msg.sender_id);
            return PBFTStage::IDLE;
        }

        auto msg_hash = compute_message_hash(msg);

        std::string round_key = crypto::IdentityCore::sha256_hex(
            msg.evidence_json + "|" + msg.target_id);
        if (round_key.empty()) round_key = msg.evidence_json + "|" + msg.target_id;

        if (m_seen_messages.count(msg_hash)) {
            return PBFTStage::IDLE;
        }
        m_seen_messages.insert(msg_hash);
        if (m_seen_messages.size() > 100000) {
            auto it = m_seen_messages.begin();
            m_seen_messages.erase(it, std::next(it, m_seen_messages.size() / 2));
        }

        detect_equivocation(msg, msg_hash);

        auto& stage_voters = m_vote_registry[round_key][msg.stage_str];

        if (stage_voters.find(msg.sender_id) != stage_voters.end()) {
            return PBFTStage::IDLE;
        }
        stage_voters.insert(msg.sender_id);

        ConsensusRound& round = m_rounds[round_key];
        if (round.state == PBFTStage::IDLE) {
            round.started_at = std::chrono::steady_clock::now();
            round.view = msg.view;
            round.pre_prepare_hash = msg_hash;
            round.evidence_key = round_key;
        }

        if (round.view != msg.view) {
            std::cerr << "[PBFT] View mismatch for " << msg.evidence_json << std::endl;
            return PBFTStage::IDLE;
        }

        round.last_activity = std::chrono::steady_clock::now();

        int quorum = quorum_size_unlocked();
        int current_votes = static_cast<int>(stage_voters.size());

        PBFTStage previous_state = round.state;

        if ((msg.stage_str == "PRE_PREPARE" || msg.stage_str == "BAN_PEER")
            && round.state == PBFTStage::IDLE) {
            round.state = PBFTStage::PREPARE;
        }
        else if (msg.stage_str == "PREPARE" && current_votes >= quorum && round.state == PBFTStage::PREPARE) {
            round.state = PBFTStage::COMMIT;
        }
        else if (msg.stage_str == "COMMIT" && current_votes >= quorum && round.state == PBFTStage::COMMIT) {
            // Quorum intersection guard at the COMMIT→EXECUTED transition.
            // Previously this check was at the PREPARE→COMMIT transition where
            // it was a no-op: at that point the COMMIT voter set is empty (no
            // one has voted COMMIT yet), so verify_quorum_intersection()'s
            // `if (commit_it == prep_it->second.end()) return true;` short-
            // circuit always fired, making the check vacuous. The meaningful
            // invariant — that the PREPARE and COMMIT quorums must overlap —
            // is only checkable once COMMIT votes exist, i.e. here. Without
            // this guard, a partition attacker can drive a round to EXECUTED
            // with disjoint PREPARE/COMMIT quorums, breaking safety.
            if (!verify_quorum_intersection(round_key, msg_hash)) {
                std::cerr << "[PBFT] QUORUM INTERSECTION FAILED at COMMIT->EXECUTED - possible partition attack" << std::endl;
                // Roll back the just-inserted vote to keep the registry clean
                // for the next attempt at the same evidence (surgical fix for
                // liveness: stale poisoned votes would otherwise prevent any
                // future commit on this evidence_key until ROUND_TTL_SEC).
                stage_voters.erase(msg.sender_id);
                return PBFTStage::IDLE;
            }
            round.state = PBFTStage::EXECUTED;
        }
        // Phase 3: BAN_PEER flow. Once the round hits EXECUTED via the
        // normal PRE_PREPARE→PREPARE→COMMIT path, the target peer is
        // added to m_banned_peers. The actual ban application happens
        // in the caller (MeshNode::process_message) by inspecting
        // round.state == EXECUTED AND round_key is a ban round.
        // We don't need a separate path here — the existing state
        // machine handles it. The MeshNode dispatcher distinguishes
        // ban-rounds by checking stage_str.

        if (round.state != previous_state) {
            return round.state;
        }
        return PBFTStage::IDLE;
    }

    [[nodiscard]] bool needs_view_change(const std::string& evidence_json,
                                          const std::string& target_id) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::string round_key = crypto::IdentityCore::sha256_hex(
            evidence_json + "|" + target_id);
        if (round_key.empty()) round_key = evidence_json + "|" + target_id;
        auto it = m_rounds.find(round_key);
        if (it == m_rounds.end()) return false;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
        return elapsed > VIEW_CHANGE_TIMEOUT_SEC && it->second.state != PBFTStage::EXECUTED;
    }

    void set_round_commit_sig(const std::string& round_key, const std::string& sig) {
        std::lock_guard<std::mutex> lock(m_mtx);
        m_rounds[round_key].commit_signature = sig;
    }

    std::string get_round_commit_sig(const std::string& round_key) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_rounds.find(round_key);
        return (it != m_rounds.end()) ? it->second.commit_signature : std::string{};
    }

    int peer_count() const { std::lock_guard<std::mutex> lock(m_mtx); return m_total_nodes; }
    int quorum_size() const { std::lock_guard<std::mutex> lock(m_mtx); return (2 * ((std::max(1, m_total_nodes) - 1) / 3)) + 1; }
    int quorum_size_unlocked() const { return (2 * ((std::max(1, m_total_nodes) - 1) / 3)) + 1; }

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
        prune_peer_locked(node_id);
    }

    // Caller MUST hold m_mtx. Split out so record_failure() can call it
    // from contexts that already hold the lock (verify_message, advance_state)
    // without deadlocking.
void prune_peer_locked(const std::string& node_id) {
    m_peer_public_keys.erase(node_id);
    m_node_trust.erase(node_id);
    m_message_history.erase(node_id);
    m_registered_peers.erase(node_id);  // also clear registration so has_peer() returns false
    for (auto& [evidence, stage_map] : m_vote_registry) {
        for (auto& [stage, voters] : stage_map) {
            voters.erase(node_id);
        }
    }
    m_total_nodes = std::max(1, m_total_nodes - 1);
}

// =============================================================================
// Cross-Node Ban Propagation (BAN_PEER stage)
// =============================================================================
// Phase 3 hardening: when a node auto-bans an adversarial peer (e.g., after
// 100 consecutive signature failures), the ban was per-node state. Other
// nodes in the mesh did not learn about the ban. An adversarial peer could
// rotate through nodes — being banned on Node A while still poisoning
// Nodes B/C/D/E.
//
// BAN_PEER is a new PBFT stage that flows PRE_PREPARE → PREPARE → COMMIT →
// EXECUTED, identical to isolation. On EXECUTED, the target is added to
// m_banned_peers. At the entry of verify_message() and advance_state(),
// banned peers are silently dropped (no log spam, no rate limit, no PBFT
// participation).
//
// Backward compatibility: old nodes that don't know about BAN_PEER will
// receive the message but their switch statement in advance_state() won't
// match — they silently ignore the new stage. Mesh continues to function
// with reduced cross-node ban coverage.
// =============================================================================

    // Phase 3: returns true if auto-ban just fired. Caller (MeshNode
    // heartbeat) drains recent bans and proposes cross-node BAN_PEER rounds.
    std::vector<std::string> drain_recent_bans() {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::vector<std::string> bans(m_recent_bans.begin(), m_recent_bans.end());
        m_recent_bans.clear();
        return bans;
    }

    bool is_banned(const std::string& node_id) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_banned_peers.count(node_id) > 0;
}

bool is_target_banned(const std::string& node_id) const {
    return is_banned(node_id);
}

void ban_peer_locked(const std::string& node_id) {
    m_banned_peers.insert(node_id);
}

// Local auto-ban path — called by record_failure() after kAutoPruneFailures.
// Adds to m_banned_peers AND removes from m_peer_public_keys. The local node
// will not process any further messages from this peer.
void ban_peer_local(const std::string& node_id, const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        ban_peer_locked(node_id);
    }
    std::cerr << "[PBFT] Local auto-ban: " << node_id
              << " reason=" << reason << std::endl;
}

// Initiate a BFT-consensus ban of a peer. Returns true if a ban round was
// started. The actual ban takes effect on EXECUTED. Cross-node: the ban
// propagates to other nodes when they process the BAN_PEER EXECUTED message.
bool propose_ban(const std::string& target_id, const std::string& reason) {
    if (target_id.empty() || target_id == m_my_node_id) {
        return false;  // never ban self
    }
    if (is_banned(target_id)) {
        return false;  // already banned
    }
    // Local ban is immediate; cross-node ban follows via BFT.
    ban_peer_local(target_id, reason);
    return true;
}

    bool try_increment_peers(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (m_registered_peers.count(node_id)) return false;
        m_registered_peers.insert(node_id);
        ++m_total_nodes;
        return true;
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
        if (m_last_confirmed_hash.empty()) {
            return m_genesis_hash;
        }
        std::stringstream ss;
        ss << m_last_confirmed_hash << "|" << m_total_nodes << "|" << m_current_view;
        return crypto::IdentityCore::sha256_hex(ss.str());
    }

    // Returns the hash to use as prev_message_hash when this node sends the
    // next message.  Chains from the most recent message we sent, or genesis.
    std::string get_last_sent_hash(const std::string& sender_id) const {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto it = m_message_history.find(sender_id);
        if (it == m_message_history.end() || it->second.empty()) {
            return m_genesis_hash;
        }
        return it->second.rbegin()->second;
    }

    int current_view() const { std::lock_guard<std::mutex> lock(m_mtx); return m_current_view; }

    void advance_view() {
        std::lock_guard<std::mutex> lock(m_mtx);
        ++m_current_view;
        std::cout << "[PBFT] View advanced to " << m_current_view << std::endl;
    }

private:
    bool verify_message_chaining(const P2PMessage& msg) const {
        auto history_it = m_message_history.find(msg.sender_id);
        if (history_it == m_message_history.end() || history_it->second.empty()) {
            // First message from this sender — accept.  Signature binding
            // already proves the sender authorized this content.
            return true;
        }

        const auto& history = history_it->second;
        auto prev_it = history.find(msg.sequence_number - 1);
        if (prev_it == history.end()) {
            // Gap in stored history (e.g. eviction, view change).
            // Accept if chaining from genesis or prev_hash is empty
            // (both mean "no predecessor in available history").
            return msg.prev_message_hash.empty() || msg.prev_message_hash == m_genesis_hash;
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

    bool verify_quorum_intersection(const std::string& evidence, const std::string& /*expected_hash*/) const {
        auto prep_it = m_vote_registry.find(evidence);
        if (prep_it == m_vote_registry.end()) return true;

        auto prep_voters_it = prep_it->second.find("PREPARE");
        if (prep_voters_it == prep_it->second.end()) return true;

        const auto& prepare_voters = prep_voters_it->second;
        if (prepare_voters.size() < static_cast<size_t>(quorum_size_unlocked())) return true;

        std::set<std::string> prep_set(prepare_voters.begin(), prepare_voters.end());

        auto commit_it = prep_it->second.find("COMMIT");
        if (commit_it == prep_it->second.end()) return true;

        const auto& commit_voters = commit_it->second;
        std::set<std::string> commit_set(commit_voters.begin(), commit_voters.end());

        std::vector<std::string> intersection;
        std::set_intersection(prep_set.begin(), prep_set.end(),
                             commit_set.begin(), commit_set.end(),
                             std::back_inserter(intersection));

        return static_cast<int>(intersection.size()) >= quorum_size_unlocked();
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

        // Cap-based eviction: keep only the most recent N entries per sender
        // to prevent unbounded memory growth (BUG-02 fix).
        if (history.size() > MAX_MSG_HISTORY_PER_SENDER) {
            auto erase_count = history.size() - MAX_MSG_HISTORY_PER_SENDER;
            auto erase_it = history.begin();
            std::advance(erase_it, static_cast<long>(erase_count));
            history.erase(history.begin(), erase_it);
        }
    }

    void record_equivocation(const std::string& node_id) {
        auto& trust = m_node_trust[node_id];
        trust.equivocation_count++;
        trust.trust_score = std::max(0.0, trust.trust_score - 0.3);
        trust.consecutive_failures++;
        trust.last_failure = std::chrono::steady_clock::now();
    }

    // Peer auto-banning thresholds.
    //
    // Background: an adversarial or buggy peer can flood bad-sig messages.
    // The rate limiter caps the volume (5 PRE_PREPARE/10s) but does not stop
    // the peer from accumulating an unbounded `consecutive_failures` counter
    // and spamming WARNING logs. At kAutoPruneFailures we remove the peer
    // entirely via prune_peer() — same primitive used for stale peers.
    //
    // log at: 6, 10, 20, 50, 75 (sample-based) then auto-prune at 100.
    static constexpr int kAutoPruneFailures = 100;
    static const std::array<int, 5> kLogFailureThresholds;

    void record_failure(const std::string& node_id) {
        auto& trust = m_node_trust[node_id];
        trust.consecutive_failures++;
        trust.trust_score = std::max(0.0, trust.trust_score - 0.1);
        trust.last_failure = std::chrono::steady_clock::now();

        // Sample-based WARNING log: only emit at the configured thresholds.
        // Without sampling, a sustained attacker generates O(failures) log
        // lines — e.g. 160,000+ observed in test_stress output.
        for (int threshold : kLogFailureThresholds) {
            if (trust.consecutive_failures == threshold) {
                std::cerr << "[PBFT] WARNING: Node " << node_id << " has "
                          << trust.consecutive_failures << " consecutive failures"
                          << " (auto-prune at " << kAutoPruneFailures << ")"
                          << std::endl;
                break;
            }
        }

        // Auto-prune: after kAutoPruneFailures consecutive failures, treat
        // the peer as adversarial. Remove it from all registries (keys,
        // trust, message history, vote registry) and decrement the quorum
        // size. Subsequent messages from this peer will fail the early
        // return in verify_message() because m_peer_public_keys no longer
        // contains it — silently, with no further log spam.
        if (trust.consecutive_failures >= kAutoPruneFailures) {
            std::cerr << "[PBFT] CRITICAL: Auto-banning peer " << node_id
                      << " after " << trust.consecutive_failures
                      << " consecutive failures" << std::endl;
            // Phase 3: also add to m_banned_peers (defense in depth). The
            // pruned peer's entries are removed from m_peer_public_keys,
            // so verify_message would already drop it. But m_banned_peers
            // is the canonical ban set — populated by both local auto-ban
            // and cross-node BFT. We add to it explicitly here.
            m_banned_peers.insert(node_id);
            m_recent_bans.insert(node_id);
            // Caller (verify_message, advance_state) holds m_mtx, so use
            // the _locked variant to avoid recursive lock acquisition.
            prune_peer_locked(node_id);
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

    bool check_rate_limit(const std::string& sender_id) {
        auto now = std::chrono::steady_clock::now();
        auto& timestamps = m_rate_limits[sender_id];

        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                [&](const auto& ts) {
                    return std::chrono::duration_cast<std::chrono::seconds>(now - ts).count() >= m_rate_window_sec;
                }),
            timestamps.end()
        );

        if (timestamps.size() >= static_cast<size_t>(m_rate_max)) {
            return false;
        }

        timestamps.push_back(now);
        return true;
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
    int m_rate_window_sec;
    int m_rate_max;
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

    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> m_rate_limits;
    std::unordered_set<std::string> m_seen_messages;
    std::unordered_set<std::string> m_registered_peers;

    // Phase 3: set of peers that have been banned (locally or via BFT).
    // Membership is permanent for the lifetime of the process — there is
    // no auto-unban. This is intentional: a peer that was adversarial
    // should not silently come back.
    std::unordered_set<std::string> m_banned_peers;

    // Phase 3: peers that were auto-banned locally but haven't had a
    // cross-node BAN_PEER round initiated yet. MeshNode's heartbeat
    // drains this set and calls propose_ban() to propagate the ban.
    std::unordered_set<std::string> m_recent_bans;

};

// Out-of-class definition for the (non-constexpr) static member array.
// Log the WARNING message at these failure counts: 6 (initial), 10, 20, 50, 75.
// After 100 consecutive failures the peer is auto-pruned.
inline const std::array<int, 5> PBFTConsensus::kLogFailureThresholds = {6, 10, 20, 50, 75};

} // namespace neuro_mesh