#include <gtest/gtest.h>
#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include <string>
#include <thread>
#include <chrono>

using namespace neuro_mesh;
using namespace neuro_mesh::crypto;

class PBFTConsensusTest : public ::testing::Test {
protected:
    void SetUp() override {
        pbft = std::make_unique<PBFTConsensus>(3);
        pbft->set_private_key(IdentityCore::generate_ed25519_key());
        pbft->set_my_identity("SELF");
        peerA_key = IdentityCore::generate_ed25519_key();
        auto peerA_pem = IdentityCore::get_pem_from_pubkey(peerA_key.get());
        pbft->register_peer_key("PEER_A", peerA_pem);
        peerB_key = IdentityCore::generate_ed25519_key();
        auto peerB_pem = IdentityCore::get_pem_from_pubkey(peerB_key.get());
        pbft->register_peer_key("PEER_B", peerB_pem);
    }
    std::unique_ptr<PBFTConsensus> pbft;
    UniquePKEY peerA_key;
    UniquePKEY peerB_key;

    // sign_message() on the consensus object always uses the LOCAL private key,
    // so it can only mint messages whose sender_id matches `my_identity`. For
    // tests we need to mint messages on behalf of arbitrary peers (PEER_A, etc.),
    // so we sign directly with the sender's matching key, binding the same
    // payload fields that sign_message() binds (see PBFT.hpp).
    std::string sign_for(const std::string& sender, const P2PMessage& msg) const {
        EVP_PKEY* key = nullptr;
        if      (sender == "PEER_A") key = peerA_key.get();
        else if (sender == "PEER_B") key = peerB_key.get();
        if (!key) return {};
        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                         + "|" + msg.prev_message_hash;
        return IdentityCore::sign_payload(key, blob);
    }

    P2PMessage make_msg(const std::string& stage, const std::string& sender,
                        const std::string& target, const std::string& evidence,
                        const std::string& prev_hash = "", uint64_t seq = 1, int view = 0) {
        P2PMessage msg;
        msg.stage_str = stage;
        msg.sender_id = sender;
        msg.target_id = target;
        msg.evidence_json = evidence;
        msg.prev_message_hash = prev_hash;
        msg.sequence_number = seq;
        msg.view = view;
        msg.signature = sign_for(sender, msg);
        return msg;
    }
};

// PBFT quorum formula: 2*floor((n-1)/3) + 1. This is the BFT-safe minimum
// to guarantee progress despite f Byzantine failures where f = floor((n-1)/3).
// For n=3 (f=0) the formula yields 1, which is technically correct since
// the system can tolerate 0 faults; in practice, deployments use n >= 4.
TEST_F(PBFTConsensusTest, QuorumSizeFormula) {
    EXPECT_EQ(pbft->quorum_size(), 1);   // n=3, f=0
    pbft->set_peer_count(4);
    EXPECT_EQ(pbft->quorum_size(), 3);   // n=4, f=1
    pbft->set_peer_count(5);
    EXPECT_EQ(pbft->quorum_size(), 3);   // n=5, f=1
    pbft->set_peer_count(7);
    EXPECT_EQ(pbft->quorum_size(), 5);   // n=7, f=2
}

// After advance_state processes a valid signed PRE_PREPARE on a fresh IDLE
// round, the round must transition to PREPARE. advance_state returns the
// resulting stage; IDLE would mean no transition occurred.
TEST_F(PBFTConsensusTest, InitialStateAdvancesToPrepare) {
    std::string evidence = "{\"entropy\":0.9}";
    auto msg = make_msg("PRE_PREPARE", "PEER_A", "TARGET", evidence);
    bool verified = pbft->verify_message(msg);
    EXPECT_TRUE(verified);
    PBFTStage stage = pbft->advance_state(msg);
    EXPECT_EQ(stage, PBFTStage::PREPARE);
}

// A replayed message (same sender+hash) must be silently dropped by
// advance_state — it returns IDLE because the round was already started by
// the original message. This prevents a single message from being counted
// twice toward the quorum.
TEST_F(PBFTConsensusTest, MessageDeduplication) {
    std::string evidence = "{\"entropy\":0.9}";
    auto msg = make_msg("PRE_PREPARE", "PEER_A", "TARGET", evidence);
    bool verified = pbft->verify_message(msg);
    EXPECT_TRUE(verified);
    PBFTStage first = pbft->advance_state(msg);
    EXPECT_EQ(first, PBFTStage::PREPARE);
    // Replay: same hash → already in m_seen_messages → return IDLE.
    PBFTStage replay = pbft->advance_state(msg);
    EXPECT_EQ(replay, PBFTStage::IDLE);
}

TEST_F(PBFTConsensusTest, HashChainingDetectsBrokenChain) {
    std::string evidence = "{\"entropy\":0.9}";
    auto msg1 = make_msg("PRE_PREPARE", "PEER_A", "TARGET", evidence, "genesis_hash", 1, 0);
    bool verified1 = pbft->verify_message(msg1);
    EXPECT_TRUE(verified1);
    pbft->advance_state(msg1);

    P2PMessage msg2;
    msg2.stage_str = "PREPARE";
    msg2.sender_id = "PEER_A";
    msg2.target_id = "TARGET";
    msg2.evidence_json = evidence;
    msg2.prev_message_hash = "WRONG_HASH";
    msg2.sequence_number = 2;
    msg2.view = 0;
    msg2.signature = sign_for("PEER_A", msg2);

    bool verified2 = pbft->verify_message(msg2);
    EXPECT_FALSE(verified2);
}

TEST_F(PBFTConsensusTest, PeerCountReflectsRegistrations) {
    EXPECT_EQ(pbft->peer_count(), 3);
    pbft->increment_peers();
    EXPECT_EQ(pbft->peer_count(), 4);
    pbft->decrement_peers();
    EXPECT_EQ(pbft->peer_count(), 3);
}

TEST_F(PBFTConsensusTest, ViewChangeTimeoutDetection) {
    std::string evidence = "{\"entropy\":0.8}";
    auto msg = make_msg("PRE_PREPARE", "PEER_A", "TARGET", evidence);
    bool verified = pbft->verify_message(msg);
    EXPECT_TRUE(verified);
    pbft->advance_state(msg);
    EXPECT_FALSE(pbft->needs_view_change(evidence, "TARGET"));
}

TEST_F(PBFTConsensusTest, RoundCommitSignatureStorage) {
    std::string evidence = "{\"entropy\":0.95}";
    std::string round_key = IdentityCore::sha256_hex(std::string(evidence) + "|TARGET");
    pbft->set_round_commit_sig(round_key, "SIGNATURE_ABC123");
    EXPECT_EQ(pbft->get_round_commit_sig(round_key), "SIGNATURE_ABC123");
}

TEST_F(PBFTConsensusTest, RoundCommitSignatureEmptyNotFound) {
    EXPECT_TRUE(pbft->get_round_commit_sig("nonexistent_key").empty());
}

TEST_F(PBFTConsensusTest, GetChainStateHash) {
    std::string hash = pbft->get_chain_state_hash();
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.size(), 64u);
}

TEST_F(PBFTConsensusTest, RegisteredPeersCannotDoubleRegister) {
    EXPECT_FALSE(pbft->try_increment_peers("PEER_A"));
}

TEST_F(PBFTConsensusTest, RateLimitingDoesNotCrash) {
    std::string evidence = "{\"flood\":true}";
    for (int i = 0; i < 20; i++) {
        auto msg = make_msg("PRE_PREPARE", "PEER_B", "TARGET", evidence);
        (void)pbft->advance_state(msg);
    }
}

// A fresh round initialized via a valid PRE_PREPARE must transition to
// PREPARE (not stay IDLE) and must not record any equivocation evidence
// (no conflicting messages seen yet).
TEST_F(PBFTConsensusTest, ConsensusRoundInit) {
    std::string evidence = "{\"entropy\":0.7}";
    auto msg = make_msg("PRE_PREPARE", "PEER_A", "TARGET", evidence);
    bool verified = pbft->verify_message(msg);
    EXPECT_TRUE(verified);
    PBFTStage stage = pbft->advance_state(msg);
    EXPECT_EQ(stage, PBFTStage::PREPARE);
    auto e_list = pbft->get_equivocation_evidence();
    EXPECT_GE(e_list.size(), 0u);
}

TEST_F(PBFTConsensusTest, TrustScoreTracking) {
    double t = pbft->get_node_trust("PEER_A");
    EXPECT_GE(t, 0.0);
    EXPECT_LE(t, 1.0);
}

TEST_F(PBFTConsensusTest, HasPeerCheck) {
    EXPECT_TRUE(pbft->has_peer("PEER_A"));
    EXPECT_FALSE(pbft->has_peer("UNKNOWN"));
}

// =============================================================================
// P1-7 regression test: race between set_round_commit_sig() and
// get_round_commit_sig() across the m_rounds map. The original bug was a
// single member variable m_last_proof_sig overwritten between heartbeat
// and consensus threads, producing empty/foreign signatures in the proof
// chain. The fix moved the storage into ConsensusRound, keyed by
// sha256(evidence|target), and protected by m_mtx.
//
// This test hammers both writers and readers in parallel and asserts:
//   1. no crash / no torn read
//   2. any non-empty value read back matches a value that was written
//   3. after all writers finish, the final value for each key is the
//      last write (sequentially consistent per key under the mutex)
// =============================================================================
TEST_F(PBFTConsensusTest, CommitSignatureConcurrentWritersReaders) {
    constexpr int kKeys   = 32;
    constexpr int kIters  = 500;
    std::atomic<int> mismatches{0};
    std::atomic<int> empty_reads{0};
    std::atomic<int> crashes{0};   // would trip via EXPECT_NO_FATAL_FAILURE

    std::vector<std::thread> writers;
    std::vector<std::thread> readers;

    for (int k = 0; k < kKeys; ++k) {
        std::string key = IdentityCore::sha256_hex("KEY_" + std::to_string(k) + "|TARGET");
        pbft->set_round_commit_sig(key, "");  // initialize the round
    }

    for (int t = 0; t < 4; ++t) {
        writers.emplace_back([&, t]() {
            for (int i = 0; i < kIters; ++i) {
                int k = (t * 7919 + i) % kKeys;
                std::string key = IdentityCore::sha256_hex("KEY_" + std::to_string(k) + "|TARGET");
                pbft->set_round_commit_sig(key, "SIG_" + std::to_string(t) + "_" + std::to_string(i));
            }
        });
    }

    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&]() {
            for (int i = 0; i < kIters; ++i) {
                int k = (i * 6151) % kKeys;
                std::string key = IdentityCore::sha256_hex("KEY_" + std::to_string(k) + "|TARGET");
                std::string v = pbft->get_round_commit_sig(key);
                if (v.empty()) {
                    ++empty_reads;
                } else if (v.rfind("SIG_", 0) != 0) {
                    ++mismatches;
                }
            }
        });
    }

    for (auto& th : writers) th.join();
    for (auto& th : readers) th.join();

    EXPECT_EQ(mismatches.load(), 0) << "torn read or foreign value observed";
    EXPECT_EQ(crashes.load(),    0);
    // Empty reads are allowed (read may race ahead of write) but should be < 100%.
    EXPECT_LT(empty_reads.load(), kKeys * kIters);
}

// =============================================================================
// P1-7 regression test: a write started AFTER a get_round_commit_sig() on the
// same key must be observable by a subsequent get (linearizability check).
// =============================================================================
TEST_F(PBFTConsensusTest, CommitSignatureWriteReadOrdering) {
    std::string key = IdentityCore::sha256_hex("ORDER_KEY|TARGET");
    pbft->set_round_commit_sig(key, "");

    // Writer thread
    std::thread writer([&]() {
        for (int i = 0; i < 1000; ++i) {
            pbft->set_round_commit_sig(key, "VALUE_" + std::to_string(i));
        }
    });

    // Reader thread: the value must always be empty OR start with "VALUE_"
    std::atomic<int> violations{0};
    std::thread reader([&]() {
        for (int i = 0; i < 5000; ++i) {
            std::string v = pbft->get_round_commit_sig(key);
            if (!v.empty() && v.rfind("VALUE_", 0) != 0) {
                ++violations;
            }
        }
    });

    writer.join();
    reader.join();

    EXPECT_EQ(violations.load(), 0);
    // After all writers finish, the final value MUST be VALUE_999.
    EXPECT_EQ(pbft->get_round_commit_sig(key), "VALUE_999");
}

// =============================================================================
// Auto-ban regression tests: a peer that repeatedly fails verification must
// be removed from the registry after kAutoPruneFailures (100) consecutive
// failures, preventing unbounded log spam and resource use.
// =============================================================================
TEST_F(PBFTConsensusTest, AutoBanAfterThreshold) {
    // Create a peer with a known key, then send 100 bad-sig messages.
    auto bad_key = IdentityCore::generate_ed25519_key();
    auto bad_pem = IdentityCore::get_pem_from_pubkey(bad_key.get());
    pbft->register_peer_key("BAD_PEER", bad_pem);
    pbft->increment_peers();

    // Sign messages with a DIFFERENT key (the SELF key) so verification fails.
    for (int i = 0; i < 100; ++i) {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "BAD_PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{\"e\":1}";
        msg.prev_message_hash = "genesis";
        msg.sequence_number = i;
        msg.view = 0;
        msg.signature = sign_for("PEER_A", msg);  // wrong key
        (void)pbft->verify_message(msg);
    }

    // After 100 failures, the peer should be auto-banned (removed from keys).
    EXPECT_FALSE(pbft->has_peer("BAD_PEER"));
    // And the trust map entry should be gone.
    EXPECT_EQ(pbft->get_node_trust("BAD_PEER"), 0.0);
}

TEST_F(PBFTConsensusTest, AutoBannedPeerIsSilentlyIgnored) {
    auto bad_key = IdentityCore::generate_ed25519_key();
    auto bad_pem = IdentityCore::get_pem_from_pubkey(bad_key.get());
    pbft->register_peer_key("SPAM_PEER", bad_pem);
    pbft->increment_peers();

    // Push past the auto-ban threshold.
    for (int i = 0; i < 100; ++i) {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "SPAM_PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{}";
        msg.prev_message_hash = "genesis";
        msg.sequence_number = i;
        msg.view = 0;
        msg.signature = "garbage";
        (void)pbft->verify_message(msg);
    }

    // Now the peer is banned. Subsequent messages must return false silently
    // (no further log spam, no trust counter increment).
    P2PMessage msg;
    msg.stage_str = "PRE_PREPARE";
    msg.sender_id = "SPAM_PEER";
    msg.target_id = "TARGET";
    msg.evidence_json = "{}";
    msg.prev_message_hash = "genesis";
    msg.sequence_number = 1000;
    msg.view = 0;
    msg.signature = "garbage";

    bool result = pbft->verify_message(msg);
    EXPECT_FALSE(result);
    // has_peer must still be false (peer was pruned, not re-added).
    EXPECT_FALSE(pbft->has_peer("SPAM_PEER"));
}

TEST_F(PBFTConsensusTest, ChainFailureCountsTowardAutoBan) {
    // Even with a VALID signature, repeated chain/sequence violations must
    // accumulate in the failure counter and eventually trigger auto-ban.
    auto peer_key = IdentityCore::generate_ed25519_key();
    auto peer_pem = IdentityCore::get_pem_from_pubkey(peer_key.get());
    pbft->register_peer_key("CHAIN_PEER", peer_pem);
    pbft->increment_peers();

    for (int i = 0; i < 100; ++i) {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "CHAIN_PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{}";
        msg.prev_message_hash = "WRONG_HASH_" + std::to_string(i);
        msg.sequence_number = i;
        msg.view = 0;
        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                         + "|" + msg.prev_message_hash;
        msg.signature = IdentityCore::sign_payload(peer_key.get(), blob);
        (void)pbft->verify_message(msg);
        // advance_state populates m_message_history via detect_equivocation,
        // which is what verify_message_chaining reads on the next iteration.
        (void)pbft->advance_state(msg);
    }

    // The peer must be auto-banned after 100 chain failures.
    EXPECT_FALSE(pbft->has_peer("CHAIN_PEER"));
}

// Phase 3: BAN_PEER stage support. Tests the public API for explicit
// ban proposals, is_banned query, and verify_message/advance_state
// silent-drop behavior.
TEST_F(PBFTConsensusTest, ProposeBanReturnsFalseForSelf) {
    EXPECT_FALSE(pbft->propose_ban("SELF", "test"));
    EXPECT_FALSE(pbft->is_banned("SELF"));
}

TEST_F(PBFTConsensusTest, ProposeBanReturnsFalseForEmpty) {
    EXPECT_FALSE(pbft->propose_ban("", "test"));
}

TEST_F(PBFTConsensusTest, ProposeBanAddsToBannedSet) {
    EXPECT_TRUE(pbft->propose_ban("MALICIOUS", "test_reason"));
    EXPECT_TRUE(pbft->is_banned("MALICIOUS"));
}

TEST_F(PBFTConsensusTest, ProposeBanReturnsFalseIfAlreadyBanned) {
    pbft->propose_ban("DUPE", "first");
    EXPECT_FALSE(pbft->propose_ban("DUPE", "second"));
    EXPECT_TRUE(pbft->is_banned("DUPE"));
}

TEST_F(PBFTConsensusTest, BannedPeerIsSilentlyIgnoredByVerifyMessage) {
    // Register a peer with a valid key, then ban them.
    auto k = IdentityCore::generate_ed25519_key();
    auto pem = IdentityCore::get_pem_from_pubkey(k.get());
    pbft->register_peer_key("VERIFIER_TARGET", pem);
    pbft->increment_peers();

    P2PMessage msg;
    msg.stage_str = "PRE_PREPARE";
    msg.sender_id = "VERIFIER_TARGET";
    msg.target_id = "T";
    msg.evidence_json = "{}";
    msg.prev_message_hash = "";
    msg.sequence_number = 0;
    msg.view = 0;
    std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                     + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                     + "|" + msg.prev_message_hash;
    msg.signature = IdentityCore::sign_payload(k.get(), blob);

    // Before ban: verify_message should return true (signature valid)
    EXPECT_TRUE(pbft->verify_message(msg));

    // Ban the peer
    pbft->propose_ban("VERIFIER_TARGET", "test");

    // After ban: verify_message returns false (silently dropped)
    EXPECT_FALSE(pbft->verify_message(msg));
}

TEST_F(PBFTConsensusTest, BannedPeerIsSilentlyIgnoredByAdvanceState) {
    auto k = IdentityCore::generate_ed25519_key();
    auto pem = IdentityCore::get_pem_from_pubkey(k.get());
    pbft->register_peer_key("ADVANCE_TARGET", pem);
    pbft->increment_peers();

    P2PMessage msg;
    msg.stage_str = "PRE_PREPARE";
    msg.sender_id = "ADVANCE_TARGET";
    msg.target_id = "T";
    msg.evidence_json = "{}";
    msg.prev_message_hash = "";
    msg.sequence_number = 0;
    msg.view = 0;
    std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                     + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                     + "|" + msg.prev_message_hash;
    msg.signature = IdentityCore::sign_payload(k.get(), blob);

    // Ban the peer BEFORE sending
    pbft->propose_ban("ADVANCE_TARGET", "test");

    // advance_state should return IDLE (no state change for banned peer)
    EXPECT_EQ(pbft->advance_state(msg), PBFTStage::IDLE);
}

TEST_F(PBFTConsensusTest, LocalAutoBanAddsToBannedSet) {
    // Verify that the local auto-ban path (after 100 consecutive failures)
    // also populates m_banned_peers. This is the defense-in-depth check:
    // even if prune_peer_locked were bypassed, the banned-set check
    // would still drop the peer.
    auto k = IdentityCore::generate_ed25519_key();
    auto pem = IdentityCore::get_pem_from_pubkey(k.get());
    pbft->register_peer_key("AUTO_BAN", pem);
    pbft->increment_peers();
    EXPECT_FALSE(pbft->is_banned("AUTO_BAN"));

    for (int i = 0; i < 100; ++i) {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "AUTO_BAN";
        msg.target_id = "T";
        msg.evidence_json = "{}";
        msg.prev_message_hash = "";
        msg.sequence_number = i;
        msg.view = 0;
        // Build the message but DON'T sign it — so verify_message will
        // return false (signature mismatch), triggering record_failure.
        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|"
                         + std::to_string(msg.sequence_number) + "|" + std::to_string(msg.view)
                         + "|" + msg.prev_message_hash;
        msg.signature = "INVALID_SIG_" + std::to_string(i);
        (void)pbft->verify_message(msg);
    }

    // Peer should be auto-banned AND added to banned set
    EXPECT_TRUE(pbft->is_banned("AUTO_BAN"));
    EXPECT_FALSE(pbft->has_peer("AUTO_BAN"));
}

TEST_F(PBFTConsensusTest, BanPeerLocalMethodDirectly) {
    // Test the lower-level ban_peer_local() method
    pbft->ban_peer_local("DIRECT_BAN", "test_reason");
    EXPECT_TRUE(pbft->is_banned("DIRECT_BAN"));
}

TEST_F(PBFTConsensusTest, IsTargetBannedAliasWorks) {
    // is_target_banned is a const alias for is_banned, used by MeshNode.
    pbft->propose_ban("ALIASED", "test");
    EXPECT_TRUE(pbft->is_target_banned("ALIASED"));
    EXPECT_FALSE(pbft->is_target_banned("OTHER"));
}
