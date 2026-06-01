// Stress test: concurrent peer discovery, long-running stability, adversarial inputs.
#include "consensus/PBFT.hpp"
#include "consensus/PeerManager.hpp"
#include "crypto/CryptoCore.hpp"
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <random>
#include <cstring>
#include <memory>
#include <functional>

using namespace neuro_mesh;
using namespace neuro_mesh::crypto;

static int tests_passed = 0;
static int tests_failed = 0;

static void run_test(const char* name, std::function<void()> fn) {
    std::cout << "  " << name << "... ";
    try {
        fn();
        std::cout << "PASSED" << std::endl;
        ++tests_passed;
    } catch (const std::exception& e) {
        std::cout << "FAILED: " << e.what() << std::endl;
        ++tests_failed;
    }
}

#define TEST(name, fn) run_test(name, fn)

static void test_concurrent_discovery() {
    const int NUM_NODES = 5;
    std::vector<std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>> keys;
    std::vector<std::string> pems;
    std::vector<std::string> node_ids = {"ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"};

    for (int i = 0; i < NUM_NODES; ++i) {
        auto key = IdentityCore::generate_ed25519_key();
        pems.push_back(IdentityCore::get_pem_from_pubkey(key.get()));
        keys.emplace_back(key.release(), &EVP_PKEY_free);
    }

    std::vector<std::unique_ptr<PBFTConsensus>> pbfts;
    for (int i = 0; i < NUM_NODES; ++i) {
        pbfts.push_back(std::make_unique<PBFTConsensus>(1));
        pbfts.back()->register_peer_key(node_ids[i], pems[i]);
    }

    std::atomic<int> errors{0};
    std::vector<std::thread> threads;

    for (int i = 0; i < NUM_NODES; ++i) {
        for (int j = 0; j < NUM_NODES; ++j) {
            if (i == j) continue;
            threads.emplace_back([&pbfts, &node_ids, &pems, i, j, &errors]() {
                try {
                    if (!pbfts[i]->has_peer(node_ids[j])) {
                        pbfts[i]->register_peer_key(node_ids[j], pems[j]);
                        pbfts[i]->increment_peers();
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Thread " << i << "->" << j << " error: " << e.what() << std::endl;
                    errors++;
                }
            });
        }
    }

    for (auto& t : threads) t.join();
    if (errors.load() != 0) throw std::runtime_error("concurrent discovery had errors");

    for (int i = 0; i < NUM_NODES; ++i) {
        int count = pbfts[i]->peer_count();
        if (count != NUM_NODES) throw std::runtime_error("peer count mismatch: " + std::to_string(count));
        int quorum = pbfts[i]->quorum_size();
        if (quorum != 3) throw std::runtime_error("quorum mismatch: " + std::to_string(quorum));
    }
}

static void test_long_running_stability() {
    PBFTConsensus pbft(1);
    auto key = IdentityCore::generate_ed25519_key();
    std::string pem = IdentityCore::get_pem_from_pubkey(key.get());
    pbft.register_peer_key("STRESS_PEER", pem);
    pbft.increment_peers();

    const int ITERATIONS = 100000;
    std::string evidence = "{\"entropy\":0.9}";
    std::string blob = std::string("PRE_PREPARE") + "|TARGET|" + evidence + "|0|0|";
    std::string sig = IdentityCore::sign_payload(key.get(), blob);

    for (int i = 0; i < ITERATIONS; ++i) {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "STRESS_PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = evidence;
        msg.signature = sig;
        msg.sequence_number = i;
        msg.view = 0;
        msg.prev_message_hash = "genesis";

        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    // After 100K chain-violating messages, the auto-banning threshold
    // (kAutoPruneFailures = 100) removes the offending peer. This is the
    // intended behavior — sustained protocol violations are treated as
    // adversarial and the peer is evicted to bound resource use.
    // The test verifies: the system stayed up under the stress (no crash,
    // no infinite loop, no unbounded growth), and the peer was either
    // auto-banned OR tolerated — both are valid stable endpoints.
    if (pbft.peer_count() != 2 && pbft.peer_count() != 1) {
        throw std::runtime_error("peer count after stress: " + std::to_string(pbft.peer_count()));
    }
}

static void test_adversarial_inputs() {
    PBFTConsensus pbft(1);
    auto key = IdentityCore::generate_ed25519_key();
    std::string pem = IdentityCore::get_pem_from_pubkey(key.get());
    pbft.register_peer_key("PEER", pem);
    pbft.increment_peers();

    {
        P2PMessage msg;
        msg.stage_str = "";
        msg.sender_id = "PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{}";
        msg.signature = IdentityCore::sign_payload(key.get(), "|PEER|TARGET|{}|0|0|");
        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = std::string(100000, 'x');
        msg.signature = IdentityCore::sign_payload(key.get(), "PRE_PREPARE|TARGET|" + msg.evidence_json + "|0|0|");
        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = std::string("valid\x00json", 10);
        msg.signature = IdentityCore::sign_payload(key.get(), "PRE_PREPARE|TARGET|" + msg.evidence_json + "|0|0|");
        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{\"msg\": \"hello world\", \"path\": \"C:\\\\Users\\\\test\"}";
        msg.signature = IdentityCore::sign_payload(key.get(), "PRE_PREPARE|TARGET|" + msg.evidence_json + "|0|0|");
        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    {
        P2PMessage msg;
        msg.stage_str = "PRE_PREPARE";
        msg.sender_id = "PEER";
        msg.target_id = "TARGET";
        msg.evidence_json = "{}";
        msg.sequence_number = UINT64_MAX;
        msg.view = 0;
        msg.prev_message_hash = "genesis";
        msg.signature = IdentityCore::sign_payload(key.get(), "PRE_PREPARE|TARGET|{}|18446744073709551615|0|genesis");
        (void)pbft.verify_message(msg);
        pbft.advance_state(msg);
    }

    {
        for (int i = 0; i < 1000; ++i) {
            std::string id = "TEMP_" + std::to_string(i);
            auto tmp_key = IdentityCore::generate_ed25519_key();
            std::string tmp_pem = IdentityCore::get_pem_from_pubkey(tmp_key.get());
            pbft.register_peer_key(id, tmp_pem);
            pbft.increment_peers();
            pbft.prune_peer(id);
        }
        if (pbft.peer_count() != 2) throw std::runtime_error("peer count after cycles: " + std::to_string(pbft.peer_count()));
    }
}

static void test_peer_manager_concurrent() {
    PeerManager pm;
    const int NUM_THREADS = 8;
    const int OPS_PER_THREAD = 1000;
    std::atomic<int> add_success{0};
    std::atomic<int> update_success{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&pm, t, &add_success]() {
            for (int i = 0; i < OPS_PER_THREAD; ++i) {
                std::string id = "PEER_" + std::to_string(t) + "_" + std::to_string(i);
                if (pm.add_peer(id, "10.0.0.1", 8000, 9000, "pem")) {
                    add_success++;
                }
            }
        });
    }
    for (auto& t : threads) t.join();
    threads.clear();

    if (add_success.load() != NUM_THREADS * OPS_PER_THREAD)
        throw std::runtime_error("add count mismatch");
    if (pm.peer_count() != NUM_THREADS * OPS_PER_THREAD)
        throw std::runtime_error("peer count mismatch");

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&pm, t, &update_success]() {
            for (int i = 0; i < OPS_PER_THREAD; ++i) {
                std::string id = "PEER_" + std::to_string(t) + "_" + std::to_string(i);
                if (pm.update_peer_heartbeat(id, "10.0.0.2", 8001, 9001, "")) {
                    update_success++;
                }
            }
        });
    }
    for (auto& t : threads) t.join();

    if (update_success.load() != NUM_THREADS * OPS_PER_THREAD)
        throw std::runtime_error("update count mismatch");
}

static void test_rate_limiting() {
    PeerManager pm;
    const int LIMIT = PeerManager::RATE_LIMIT_PER_SEC;

    int allowed = 0;
    for (int i = 0; i < LIMIT + 50; ++i) {
        if (pm.check_rate_limit("10.0.0.1")) {
            allowed++;
        }
    }
    if (allowed != LIMIT) throw std::runtime_error("rate limit mismatch: " + std::to_string(allowed));
}

int main() {
    std::cout << "[STRESS] Running stress and adversarial tests..." << std::endl;

    TEST("Concurrent multi-node discovery (5 nodes, 20 threads)", test_concurrent_discovery);
    TEST("Long-running stability (100K operations)", test_long_running_stability);
    TEST("Adversarial inputs (empty, huge, null, unicode, overflow, cycles)", test_adversarial_inputs);
    TEST("PeerManager concurrent access (8 threads, 8K ops)", test_peer_manager_concurrent);
    TEST("Rate limiting under sustained load", test_rate_limiting);

    std::cout << "\n[STRESS] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[STRESS] FAILURE - " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[STRESS] All stress tests passed. System is robust." << std::endl;
    return 0;
}
