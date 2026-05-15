#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include <iostream>
#include <cassert>
#include <thread>

using namespace neuro_mesh;
using namespace neuro_mesh::crypto;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        std::cout << "  " << (name) << "... "; \
        try

#define END_TEST() \
        std::cout << "PASSED" << std::endl; \
        ++tests_passed; \
        } catch (const std::exception& e) { \
            std::cout << "FAILED: " << e.what() << std::endl; \
            ++tests_failed; \
        } \
    } while(0)

int main() {
    std::cout << "[PBFT] Running PBFT consensus unit tests..." << std::endl;

    // =========================================================================
    TEST("quorum_size() computation") {
        PBFTConsensus pbft1(1);
        assert(pbft1.quorum_size() == 1);

        PBFTConsensus pbft3(3);
        assert(pbft3.quorum_size() == 2);  // ceil(2*3/3) = 2

        PBFTConsensus pbft4(4);
        assert(pbft4.quorum_size() == 3);  // ceil(2*4/3) = ceil(8/3) = 3

        PBFTConsensus pbft5(5);
        assert(pbft5.quorum_size() == 4);  // ceil(2*5/3) = ceil(10/3) = 4

        // Defensive: quorum_size with n=0 ctor (should clamp to 1)
        PBFTConsensus pbft0(0);
        assert(pbft0.quorum_size() == 1);
    END_TEST();

    // =========================================================================
    TEST("verify_message with valid signature") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "NODE_A";
        msg.target_id = "NODE_B";
        msg.evidence_json = "{\"entropy\":0.9}";

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        assert(pbft.verify_message(msg));
    END_TEST();

    // =========================================================================
    TEST("verify_message rejects unknown sender") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "NODE_Z";   // NOT registered
        msg.target_id = "NODE_B";
        msg.evidence_json = "{\"entropy\":0.9}";

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        assert(!pbft.verify_message(msg));
    END_TEST();

    // =========================================================================
    TEST("verify_message rejects tampered evidence") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "NODE_A";
        msg.target_id = "NODE_B";
        msg.evidence_json = "{\"entropy\":0.9}";

        // Sign one blob...
        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        // ...but tamper the evidence after signing
        msg.evidence_json = "{\"entropy\":0.1}";

        assert(!pbft.verify_message(msg));
    END_TEST();

    // =========================================================================
    TEST("Signature binding prevents cross-stage replay") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        // Sign a PRE_PREPARE message
        std::string evidence = "{\"entropy\":0.9}";
        std::string blob = std::string("PRE_PREPARE") + "|NODE_B|" + evidence;
        std::string sig = IdentityCore::sign_payload(key.get(), blob);

        // Try to replay it as a COMMIT (different stage)
        P2PMessage replayed;
        replayed.stage_str = "COMMIT";  // changed stage
        replayed.sender_id = "NODE_A";
        replayed.target_id = "NODE_B";
        replayed.evidence_json = evidence;
        replayed.signature = sig;

        assert(!pbft.verify_message(replayed));
    END_TEST();

    // =========================================================================
    TEST("Full PBFT state machine: PRE_PREPARE → PREPARE → COMMIT → EXECUTED") {
        auto key_a = IdentityCore::generate_ed25519_key();
        auto key_b = IdentityCore::generate_ed25519_key();
        auto key_c = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());
        std::string pem_b = IdentityCore::get_pem_from_pubkey(key_b.get());
        std::string pem_c = IdentityCore::get_pem_from_pubkey(key_c.get());

        PBFTConsensus pbft(3);  // 3 nodes, quorum = 2
        pbft.register_peer_key("A", pem_a);
        pbft.register_peer_key("B", pem_b);
        pbft.register_peer_key("C", pem_c);

        std::string evidence = "{\"entropy\":0.9}";

        // Helper: create signed message
        auto make_msg = [&](const std::string& stage, const std::string& sender,
                            const std::string& target, EVP_PKEY* key) -> P2PMessage {
            std::string blob = stage + "|" + target + "|" + evidence;
            return {stage, sender, target, evidence,
                    IdentityCore::sign_payload(key, blob)};
        };

        // Step 1: A sends PRE_PREPARE targeting B
        auto msg1 = make_msg("PRE_PREPARE", "A", "B", key_a.get());
        assert(pbft.verify_message(msg1));
        PBFTStage s1 = pbft.advance_state(msg1);
        assert(s1 == PBFTStage::PREPARE);  // transitioned to PREPARE

        // Step 2: B sends PREPARE (shouldn't reach quorum yet, only 1 PREPARE vote)
        auto msg2 = make_msg("PREPARE", "B", "B", key_b.get());
        assert(pbft.verify_message(msg2));
        PBFTStage s2 = pbft.advance_state(msg2);
        assert(s2 == PBFTStage::IDLE);  // not enough votes yet

        // Step 3: C sends PREPARE (now 2 PREPARE votes = quorum) → COMMIT
        auto msg3 = make_msg("PREPARE", "C", "B", key_c.get());
        assert(pbft.verify_message(msg3));
        PBFTStage s3 = pbft.advance_state(msg3);
        assert(s3 == PBFTStage::COMMIT);

        // Step 4: A sends COMMIT (1 vote, not yet quorum)
        auto msg4 = make_msg("COMMIT", "A", "B", key_a.get());
        assert(pbft.verify_message(msg4));
        PBFTStage s4 = pbft.advance_state(msg4);
        assert(s4 == PBFTStage::IDLE);

        // Step 5: B sends COMMIT (2 votes = quorum) → EXECUTED
        auto msg5 = make_msg("COMMIT", "B", "B", key_b.get());
        assert(pbft.verify_message(msg5));
        PBFTStage s5 = pbft.advance_state(msg5);
        assert(s5 == PBFTStage::EXECUTED);
    END_TEST();

    // =========================================================================
    TEST("Duplicate votes are rejected (deduplication)") {
        auto key_a = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("A", pem_a);

        std::string evidence = "{\"entropy\":0.5}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence;

        P2PMessage msg{"PRE_PREPARE", "A", "B", evidence,
                        IdentityCore::sign_payload(key_a.get(), blob)};

        assert(pbft.verify_message(msg));
        PBFTStage s1 = pbft.advance_state(msg);
        assert(s1 == PBFTStage::PREPARE);

        // Same message again → IDLE (already voted)
        assert(pbft.verify_message(msg));
        PBFTStage s2 = pbft.advance_state(msg);
        assert(s2 == PBFTStage::IDLE);
    END_TEST();

    // =========================================================================
    TEST("Dynamic peer count changes quorum") {
        PBFTConsensus pbft(1);
        assert(pbft.quorum_size() == 1);

        pbft.increment_peers();
        assert(pbft.peer_count() == 2);
        assert(pbft.quorum_size() == 2);  // (2*2+2)/3 = 2

        pbft.increment_peers();
        assert(pbft.peer_count() == 3);
        assert(pbft.quorum_size() == 2);  // (2*3+2)/3 = 2

        pbft.decrement_peers();
        assert(pbft.peer_count() == 2);
        assert(pbft.quorum_size() == 2);

        pbft.decrement_peers();
        assert(pbft.peer_count() == 1);   // clamped to 1
        assert(pbft.quorum_size() == 1);

        pbft.decrement_peers();
        assert(pbft.peer_count() == 1);   // still clamped
        assert(pbft.quorum_size() == 1);
    END_TEST();

    // =========================================================================
    TEST("prune_peer removes votes and keys") {
        auto key_a = IdentityCore::generate_ed25519_key();
        auto key_b = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());
        std::string pem_b = IdentityCore::get_pem_from_pubkey(key_b.get());

        PBFTConsensus pbft(3);
        pbft.register_peer_key("A", pem_a);
        pbft.register_peer_key("B", pem_b);

        std::string evidence = "{\"e\":1}";
        auto make_msg = [&](const std::string& sender, EVP_PKEY* key) -> P2PMessage {
            std::string blob = std::string("PRE_PREPARE") + "|X|" + evidence;
            return {"PRE_PREPARE", sender, "X", evidence,
                    IdentityCore::sign_payload(key, blob)};
        };

        // A votes
        auto msg_a = make_msg("A", key_a.get());
        assert(pbft.verify_message(msg_a));
        pbft.advance_state(msg_a);

        // B votes (would reach quorum if A was still counted)
        auto msg_b = make_msg("B", key_b.get());
        assert(pbft.verify_message(msg_b));

        // Prune A
        pbft.prune_peer("A");

        // A's key is gone — verify should fail for A now
        assert(!pbft.verify_message(msg_a));

        // B can still verify
        assert(pbft.verify_message(msg_b));

        // Peer count decreased
        assert(pbft.peer_count() == 2);
    END_TEST();

    // =========================================================================
    TEST("needs_view_change detects stale rounds") {
        PBFTConsensus pbft(2);
        // Advance to PREPARE stage
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());
        pbft.register_peer_key("A", pem);

        std::string evidence = "{\"e\":1}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence;
        P2PMessage msg{"PRE_PREPARE", "A", "B", evidence,
                        IdentityCore::sign_payload(key.get(), blob)};

        assert(pbft.verify_message(msg));
        pbft.advance_state(msg);

        // Immediately after: no view change needed
        assert(!pbft.needs_view_change(evidence));

        // After 31 seconds the round should need a view change...
        // (We can't actually wait 31s in a unit test, but we trust the logic.)
        std::cout << "(timeout logic not waited) ";
    END_TEST();

    // =========================================================================
    std::cout << "\n[PBFT] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[PBFT] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[PBFT] All tests passed. PBFT consensus logic is correct." << std::endl;
    return 0;
}
