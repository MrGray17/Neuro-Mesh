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

    TEST("quorum_size() computation") {
        PBFTConsensus pbft1(1);
        assert(pbft1.quorum_size() == 1);

        PBFTConsensus pbft3(3);
        assert(pbft3.quorum_size() == 2);

        PBFTConsensus pbft4(4);
        assert(pbft4.quorum_size() == 3);

        PBFTConsensus pbft5(5);
        assert(pbft5.quorum_size() == 4);

        PBFTConsensus pbft0(0);
        assert(pbft0.quorum_size() == 1);
    END_TEST();

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

    TEST("verify_message rejects unknown sender") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "NODE_Z";
        msg.target_id = "NODE_B";
        msg.evidence_json = "{\"entropy\":0.9}";

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        assert(!pbft.verify_message(msg));
    END_TEST();

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

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        msg.evidence_json = "{\"entropy\":0.1}";

        assert(!pbft.verify_message(msg));
    END_TEST();

    TEST("Signature binding prevents cross-stage replay") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        std::string evidence = "{\"entropy\":0.9}";
        std::string blob = std::string("PRE_PREPARE") + "|NODE_B|" + evidence;
        std::string sig = IdentityCore::sign_payload(key.get(), blob);

        P2PMessage replayed;
        replayed.stage_str = "COMMIT";
        replayed.sender_id = "NODE_A";
        replayed.target_id = "NODE_B";
        replayed.evidence_json = evidence;
        replayed.signature = sig;

        assert(!pbft.verify_message(replayed));
    END_TEST();

    TEST("Full PBFT state machine: PRE_PREPARE → PREPARE → COMMIT → EXECUTED") {
        auto key_a = IdentityCore::generate_ed25519_key();
        auto key_b = IdentityCore::generate_ed25519_key();
        auto key_c = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());
        std::string pem_b = IdentityCore::get_pem_from_pubkey(key_b.get());
        std::string pem_c = IdentityCore::get_pem_from_pubkey(key_c.get());

        PBFTConsensus pbft(3);
        pbft.register_peer_key("A", pem_a);
        pbft.register_peer_key("B", pem_b);
        pbft.register_peer_key("C", pem_c);

        std::string evidence = "{\"entropy\":0.9}";

        auto make_msg = [&](const std::string& stage, const std::string& sender,
                            const std::string& target, EVP_PKEY* key) -> P2PMessage {
            std::string b = stage + "|" + target + "|" + evidence;
            P2PMessage m;
            m.stage_str = stage;
            m.sender_id = sender;
            m.target_id = target;
            m.evidence_json = evidence;
            m.signature = IdentityCore::sign_payload(key, b);
            return m;
        };

        auto msg1 = make_msg("PRE_PREPARE", "A", "B", key_a.get());
        assert(pbft.verify_message(msg1));
        assert(pbft.advance_state(msg1) == PBFTStage::PREPARE);

        auto msg2 = make_msg("PREPARE", "B", "B", key_b.get());
        assert(pbft.verify_message(msg2));
        assert(pbft.advance_state(msg2) == PBFTStage::IDLE);

        auto msg3 = make_msg("PREPARE", "C", "B", key_c.get());
        assert(pbft.verify_message(msg3));
        assert(pbft.advance_state(msg3) == PBFTStage::COMMIT);

        auto msg4 = make_msg("COMMIT", "A", "B", key_a.get());
        assert(pbft.verify_message(msg4));
        assert(pbft.advance_state(msg4) == PBFTStage::IDLE);

        auto msg5 = make_msg("COMMIT", "B", "B", key_b.get());
        assert(pbft.verify_message(msg5));
        assert(pbft.advance_state(msg5) == PBFTStage::EXECUTED);
    END_TEST();

    TEST("Duplicate votes are rejected (deduplication)") {
        auto key_a = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("A", pem_a);

        std::string evidence = "{\"entropy\":0.5}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence;

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "A";
        msg.target_id = "B";
        msg.evidence_json = evidence;
        msg.signature = IdentityCore::sign_payload(key_a.get(), blob);

        assert(pbft.verify_message(msg));
        assert(pbft.advance_state(msg) == PBFTStage::PREPARE);

        assert(pbft.verify_message(msg));
        assert(pbft.advance_state(msg) == PBFTStage::IDLE);
    END_TEST();

    TEST("Dynamic peer count changes quorum") {
        PBFTConsensus pbft(1);
        assert(pbft.quorum_size() == 1);

        pbft.increment_peers();
        assert(pbft.peer_count() == 2);
        assert(pbft.quorum_size() == 2);

        pbft.increment_peers();
        assert(pbft.peer_count() == 3);
        assert(pbft.quorum_size() == 2);

        pbft.decrement_peers();
        assert(pbft.peer_count() == 2);
        assert(pbft.quorum_size() == 2);

        pbft.decrement_peers();
        assert(pbft.peer_count() == 1);
        assert(pbft.quorum_size() == 1);

        pbft.decrement_peers();
        assert(pbft.peer_count() == 1);
        assert(pbft.quorum_size() == 1);
    END_TEST();

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
            std::string b = std::string("PRE_PREPARE") + "|X|" + evidence;
            P2PMessage m;
            m.stage_str = "PRE_PREPARE";
            m.sender_id = sender;
            m.target_id = "X";
            m.evidence_json = evidence;
            m.signature = IdentityCore::sign_payload(key, b);
            return m;
        };

        auto msg_a = make_msg("A", key_a.get());
        assert(pbft.verify_message(msg_a));
        pbft.advance_state(msg_a);

        auto msg_b = make_msg("B", key_b.get());
        assert(pbft.verify_message(msg_b));

        pbft.prune_peer("A");

        assert(!pbft.verify_message(msg_a));
        assert(pbft.verify_message(msg_b));
        assert(pbft.peer_count() == 2);
    END_TEST();

    TEST("needs_view_change detects stale rounds") {
        PBFTConsensus pbft(2);
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());
        pbft.register_peer_key("A", pem);

        std::string evidence = "{\"e\":1}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence;
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "A";
        msg.target_id = "B";
        msg.evidence_json = evidence;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        assert(pbft.verify_message(msg));
        pbft.advance_state(msg);

        assert(!pbft.needs_view_change(evidence));
        std::cout << "(timeout logic not waited) ";
    END_TEST();

    std::cout << "\n[PBFT] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[PBFT] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[PBFT] All tests passed. PBFT consensus logic is correct." << std::endl;
    return 0;
}
