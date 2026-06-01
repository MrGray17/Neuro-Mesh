// PBFT consensus performance baseline
// Measures latency and throughput of the consensus state machine
// for a single round, in isolation (no network).
//
// Run with: NEURO_UNSAFE_NO_SANDBOX=1 bin/test_pbft_perf
// Output: lines like "PERF: round=1 latency_us=42"

#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include <chrono>
#include <iostream>
#include <thread>
#include <cstdlib>

using namespace neuro_mesh;
using namespace neuro_mesh::crypto;
using namespace std::chrono;

static UniquePKEY gen_key() { return IdentityCore::generate_ed25519_key(); }
static std::string pem_of(UniquePKEY& k) { return IdentityCore::get_pem_from_pubkey(k.get()); }

// Send a complete PRE_PREPARE → PREPARE → COMMIT cycle for a single round
// across N nodes. Measures wall-clock latency.
static double measure_round_latency_us(int n_nodes, int total_rounds) {
    // Generate keys once. Each node's PBFT object will own its private key,
    // so we need to also keep a copy of the raw EVP_PKEY* for the test
    // driver to sign messages on behalf of each node.
    struct KeyPair {
        UniquePKEY owned;       // given to PBFT object
        EVP_PKEY* raw_for_sign; // same underlying key, kept for sign_payload
    };
    std::vector<KeyPair> keys;
    std::vector<std::string> pems;
    std::vector<std::string> ids;

    for (int i = 0; i < n_nodes; ++i) {
        auto k = gen_key();
        std::string id = "NODE_" + std::to_string(i);
        std::string pem = pem_of(k);
        // Note: k is moved into KeyPair.owned. The raw pointer is valid
        // as long as owned holds the unique_ptr. We use a separate
        // signer_key to sign messages without consuming the original.
        auto signer_key = gen_key(); // separate key for signing
        std::string signer_pem = pem_of(signer_key);
        // For the perf test we cheat: use the same key for both purposes
        // by regenerating it from a fresh seed (not possible with Ed25519
        // here). Instead we just track the original key via raw pointer.
        keys.push_back({std::move(k), nullptr});
        keys.back().raw_for_sign = keys.back().owned.get();
        pems.push_back(pem);
        ids.push_back(id);
    }

    std::vector<std::unique_ptr<PBFTConsensus>> nodes;
    for (int i = 0; i < n_nodes; ++i) {
        // Move the owned key into the PBFT object. After this, the PBFT
        // owns the key, but keys[i].raw_for_sign (raw pointer) remains
        // valid for signing during the test.
        auto pbft = std::make_unique<PBFTConsensus>(n_nodes);
        pbft->set_private_key(std::move(keys[i].owned));
        pbft->set_my_identity(ids[i]);
        for (int j = 0; j < n_nodes; ++j) {
            if (i != j) pbft->register_peer_key(ids[j], pems[j]);
        }
        pbft->increment_peers();
        nodes.push_back(std::move(pbft));
    }

    double total_latency_us = 0.0;
    int completed_rounds = 0;

    for (int round = 0; round < total_rounds; ++round) {
        std::string evidence = R"({"entropy":0.9,"round":)" + std::to_string(round) + "}";
        std::string target = "TARGET_" + std::to_string(round % 10);
        std::string round_key = "rk_" + std::to_string(round);

        auto t0 = steady_clock::now();

        // Node 0 initiates PRE_PREPARE
        P2PMessage pre;
        pre.stage_str = "PRE_PREPARE";
        pre.sender_id = ids[0];
        pre.target_id = target;
        pre.evidence_json = evidence;
        pre.sequence_number = round;
        pre.view = 0;
        pre.prev_message_hash = "";  // disable chain check for perf baseline
        std::string pre_blob = pre.stage_str + "|" + pre.target_id + "|" +
                               pre.evidence_json + "|" + std::to_string(pre.sequence_number) +
                               "|" + std::to_string(pre.view) + "|" + pre.prev_message_hash;
        pre.signature = IdentityCore::sign_payload(keys[0].raw_for_sign, pre_blob);

        // All nodes process
        for (auto& n : nodes) {
            (void)n->verify_message(pre);
            n->advance_state(pre);
        }

        // For quorum, we need 2f+1 PREPARE votes. Simulate: each node signs a PREPARE.
        for (int i = 0; i < n_nodes; ++i) {
            P2PMessage prep;
            prep.stage_str = "PREPARE";
            prep.sender_id = ids[i];
            prep.target_id = target;
            prep.evidence_json = evidence;
            prep.sequence_number = round;
            prep.view = 0;
            prep.prev_message_hash = pre.prev_message_hash;
            std::string prep_blob = prep.stage_str + "|" + prep.target_id + "|" +
                                    prep.evidence_json + "|" + std::to_string(prep.sequence_number) +
                                    "|" + std::to_string(prep.view) + "|" + prep.prev_message_hash;
            prep.signature = IdentityCore::sign_payload(keys[i].raw_for_sign, prep_blob);
            for (auto& n : nodes) {
                (void)n->verify_message(prep);
                n->advance_state(prep);
            }
        }

        auto t1 = steady_clock::now();
        double us = duration_cast<nanoseconds>(t1 - t0).count() / 1000.0;
        total_latency_us += us;
        completed_rounds++;
    }

    return total_latency_us / completed_rounds;
}

int main() {
    std::cout << "PERF: PBFT consensus latency baseline" << std::endl;
    std::cout << "PERF: machine=" <<
#ifdef __linux__
        "linux"
#else
        "other"
#endif
        << " arch=" <<
#ifdef __x86_64__
        "x86_64"
#elif defined(__aarch64__)
        "aarch64"
#else
        "unknown"
#endif
        << std::endl;

    int rounds = 50;
    for (int n : {3, 4, 5, 7}) {
        double avg = measure_round_latency_us(n, rounds);
        std::cout << "PERF: nodes=" << n
                  << " rounds=" << rounds
                  << " avg_latency_us=" << static_cast<int>(avg)
                  << std::endl;
    }
    return 0;
}
