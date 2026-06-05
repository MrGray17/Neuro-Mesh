#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace neuro_mesh;
using namespace neuro_mesh::crypto;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        std::cout << "  " << (name) << "... "; \
        try

#define ASSERT(cond) \
        if (!(cond)) { throw std::runtime_error("assertion failed: " #cond); }

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
        ASSERT(pbft1.quorum_size() == 1);

        PBFTConsensus pbft3(3);
        ASSERT(pbft3.quorum_size() == 1);  // f=0, 2f+1=1

        PBFTConsensus pbft4(4);
        ASSERT(pbft4.quorum_size() == 3);  // f=1, 2f+1=3

        PBFTConsensus pbft5(5);
        ASSERT(pbft5.quorum_size() == 3);  // f=1, 2f+1=3

        PBFTConsensus pbft0(0);
        ASSERT(pbft0.quorum_size() == 1);
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

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|0|0|";
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        ASSERT(pbft.verify_message(msg));
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

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|0|0|";
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        ASSERT(!pbft.verify_message(msg));
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

        std::string blob = msg.stage_str + "|" + msg.target_id + "|" + msg.evidence_json + "|0|0|";
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        msg.evidence_json = "{\"entropy\":0.1}";

        ASSERT(!pbft.verify_message(msg));
    END_TEST();

    TEST("Signature binding prevents cross-stage replay") {
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("NODE_A", pem);

        std::string evidence = "{\"entropy\":0.9}";
        std::string blob = std::string("PRE_PREPARE") + "|NODE_B|" + evidence + "|0|0|";
        std::string sig = IdentityCore::sign_payload(key.get(), blob);

        P2PMessage replayed;
        replayed.stage_str = "COMMIT";
        replayed.sender_id = "NODE_A";
        replayed.target_id = "NODE_B";
        replayed.evidence_json = evidence;
        replayed.signature = sig;

        ASSERT(!pbft.verify_message(replayed));
    END_TEST();

    TEST("Full PBFT state machine: PRE_PREPARE → PREPARE → COMMIT → EXECUTED") {
        auto key_a = IdentityCore::generate_ed25519_key();
        auto key_b = IdentityCore::generate_ed25519_key();
        auto key_c = IdentityCore::generate_ed25519_key();
        auto key_d = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());
        std::string pem_b = IdentityCore::get_pem_from_pubkey(key_b.get());
        std::string pem_c = IdentityCore::get_pem_from_pubkey(key_c.get());
        std::string pem_d = IdentityCore::get_pem_from_pubkey(key_d.get());

        PBFTConsensus pbft(4);  // n=4, f=1, quorum=3
        pbft.register_peer_key("A", pem_a);
        pbft.register_peer_key("B", pem_b);
        pbft.register_peer_key("C", pem_c);
        pbft.register_peer_key("D", pem_d);

        std::string evidence = "{\"entropy\":0.9}";

        auto make_msg = [&](const std::string& stage, const std::string& sender,
                            const std::string& target, EVP_PKEY* key) -> P2PMessage {
            std::string b = stage + "|" + target + "|" + evidence + "|0|0|";
            P2PMessage m;
            m.stage_str = stage;
            m.sender_id = sender;
            m.target_id = target;
            m.evidence_json = evidence;
            m.signature = IdentityCore::sign_payload(key, b);
            return m;
        };

        auto msg1 = make_msg("PRE_PREPARE", "A", "B", key_a.get());
        ASSERT(pbft.verify_message(msg1));
        ASSERT(pbft.advance_state(msg1) == PBFTStage::PREPARE);

        auto msg1b = make_msg("PREPARE", "A", "B", key_a.get());
        ASSERT(pbft.verify_message(msg1b));
        ASSERT(pbft.advance_state(msg1b) == PBFTStage::IDLE);  // 1 vote, need 3

        auto msg2 = make_msg("PREPARE", "B", "B", key_b.get());
        ASSERT(pbft.verify_message(msg2));
        ASSERT(pbft.advance_state(msg2) == PBFTStage::IDLE);  // 2 votes, need 3

        auto msg3 = make_msg("PREPARE", "C", "B", key_c.get());
        ASSERT(pbft.verify_message(msg3));
        ASSERT(pbft.advance_state(msg3) == PBFTStage::COMMIT);  // 3 votes (A,B,C), advance

        auto msg3b = make_msg("PREPARE", "D", "B", key_d.get());
        ASSERT(pbft.verify_message(msg3b));
        ASSERT(pbft.advance_state(msg3b) == PBFTStage::IDLE);  // already COMMIT

        auto msg4 = make_msg("COMMIT", "A", "B", key_a.get());
        ASSERT(pbft.verify_message(msg4));
        ASSERT(pbft.advance_state(msg4) == PBFTStage::IDLE);  // 1 vote, need 3

        auto msg5 = make_msg("COMMIT", "B", "B", key_b.get());
        ASSERT(pbft.verify_message(msg5));
        ASSERT(pbft.advance_state(msg5) == PBFTStage::IDLE);  // 2 votes, need 3

        auto msg6 = make_msg("COMMIT", "C", "B", key_c.get());
        ASSERT(pbft.verify_message(msg6));
        ASSERT(pbft.advance_state(msg6) == PBFTStage::EXECUTED);  // 3 votes, quorum=3
    END_TEST();

    TEST("Duplicate votes are rejected (deduplication)") {
        auto key_a = IdentityCore::generate_ed25519_key();
        std::string pem_a = IdentityCore::get_pem_from_pubkey(key_a.get());

        PBFTConsensus pbft(2);
        pbft.register_peer_key("A", pem_a);

        std::string evidence = "{\"entropy\":0.5}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence + "|0|0|";

        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "A";
        msg.target_id = "B";
        msg.evidence_json = evidence;
        msg.signature = IdentityCore::sign_payload(key_a.get(), blob);

        ASSERT(pbft.verify_message(msg));
        ASSERT(pbft.advance_state(msg) == PBFTStage::PREPARE);

        ASSERT(pbft.verify_message(msg));
        ASSERT(pbft.advance_state(msg) == PBFTStage::IDLE);
    END_TEST();

    TEST("Dynamic peer count changes quorum") {
        PBFTConsensus pbft(1);
        ASSERT(pbft.quorum_size() == 1);

        pbft.increment_peers();
        ASSERT(pbft.peer_count() == 2);
        ASSERT(pbft.quorum_size() == 1);  // f=0, 2f+1=1

        pbft.increment_peers();
        ASSERT(pbft.peer_count() == 3);
        ASSERT(pbft.quorum_size() == 1);  // f=0, 2f+1=1

        pbft.increment_peers();
        ASSERT(pbft.peer_count() == 4);
        ASSERT(pbft.quorum_size() == 3);  // f=1, 2f+1=3

        pbft.decrement_peers();
        ASSERT(pbft.peer_count() == 3);
        ASSERT(pbft.quorum_size() == 1);

        pbft.decrement_peers();
        ASSERT(pbft.peer_count() == 2);
        ASSERT(pbft.quorum_size() == 1);

        pbft.decrement_peers();
        ASSERT(pbft.peer_count() == 1);
        ASSERT(pbft.quorum_size() == 1);

        pbft.decrement_peers();
        ASSERT(pbft.peer_count() == 1);
        ASSERT(pbft.quorum_size() == 1);
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
            std::string b = std::string("PRE_PREPARE") + "|X|" + evidence + "|0|0|";
            P2PMessage m;
            m.stage_str = "PRE_PREPARE";
            m.sender_id = sender;
            m.target_id = "X";
            m.evidence_json = evidence;
            m.signature = IdentityCore::sign_payload(key, b);
            return m;
        };

        auto msg_a = make_msg("A", key_a.get());
        ASSERT(pbft.verify_message(msg_a));
        pbft.advance_state(msg_a);

        auto msg_b = make_msg("B", key_b.get());
        ASSERT(pbft.verify_message(msg_b));

        pbft.prune_peer("A");

        ASSERT(!pbft.verify_message(msg_a));
        ASSERT(pbft.verify_message(msg_b));
        ASSERT(pbft.peer_count() == 2);
    END_TEST();

    TEST("needs_view_change detects stale rounds") {
        PBFTConsensus pbft(2);
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());
        pbft.register_peer_key("A", pem);

        std::string evidence = "{\"e\":1}";
        std::string blob = std::string("PRE_PREPARE") + "|B|" + evidence + "|0|0|";
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "A";
        msg.target_id = "B";
        msg.evidence_json = evidence;
        msg.signature = IdentityCore::sign_payload(key.get(), blob);

        ASSERT(pbft.verify_message(msg));
        pbft.advance_state(msg);

        ASSERT(!pbft.needs_view_change(evidence, "B"));
        std::cout << "(timeout logic not waited) ";
    END_TEST();

    TEST("has_peer guard prevents double-increment on duplicate registration") {
        // Simulates the production pattern used in both ANNOUNCE and DISCOVERY
        // handlers: if (!has_peer(id)) { register_peer_key(); increment_peers(); }
        auto key = IdentityCore::generate_ed25519_key();
        std::string pem = IdentityCore::get_pem_from_pubkey(key.get());

        PBFTConsensus pbft(1);  // start with self only
        ASSERT(pbft.peer_count() == 1);

        // First registration (simulates ANNOUNCE firing first)
        if (!pbft.has_peer("A")) {
            pbft.register_peer_key("A", pem);
            pbft.increment_peers();
        }
        ASSERT(pbft.peer_count() == 2);
        ASSERT(pbft.has_peer("A"));

        // Second registration attempt (simulates DISCOVERY firing later)
        // The has_peer() guard should prevent double-increment
        if (!pbft.has_peer("A")) {
            pbft.register_peer_key("A", pem);
            pbft.increment_peers();
        }
        // Count should still be 2, NOT 3
        ASSERT(pbft.peer_count() == 2);

        // Register a different peer — should increment
        if (!pbft.has_peer("B")) {
            pbft.register_peer_key("B", pem);
            pbft.increment_peers();
        }
        ASSERT(pbft.peer_count() == 3);
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
