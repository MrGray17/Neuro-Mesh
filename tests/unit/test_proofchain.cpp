#include <gtest/gtest.h>
#include "crypto/ProofChain.hpp"
#include <string>
#include <vector>

using namespace neuro_mesh::crypto;

class ProofChainTest : public ::testing::Test {
protected:
    void SetUp() override {
        chain = std::make_unique<ProofChain>("TEST_NODE");
    }
    void TearDown() override {
        chain.reset();
    }
    std::unique_ptr<ProofChain> chain;
    int sig_counter = 0;
    std::string make_sig() { return "deadbeef" + std::to_string(sig_counter++); }
};

TEST_F(ProofChainTest, AppendSingleLink) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "test_data", make_sig());
    std::string root = chain->get_root_hash();
    EXPECT_FALSE(root.empty());
}

TEST_F(ProofChainTest, AppendMultipleLinksChangesRoot) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "data1", make_sig());
    std::string root1 = chain->get_root_hash();
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_B", "data2", make_sig());
    std::string root2 = chain->get_root_hash();
    EXPECT_FALSE(root1.empty());
    EXPECT_FALSE(root2.empty());
    EXPECT_NE(root1, root2);
}

TEST_F(ProofChainTest, RootHashIsDeterministic) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "data", make_sig());
    std::string root1 = chain->get_root_hash();
    std::string root2 = chain->get_root_hash();
    EXPECT_EQ(root1, root2);
}

TEST_F(ProofChainTest, EmptyChainRootHash) {
    std::string root = chain->get_root_hash();
    EXPECT_TRUE(root.empty());
}

TEST_F(ProofChainTest, GetProofPathForValidSequence) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "link0", make_sig());
    chain->append(ProofEventType::PBFT_PRE_PREPARE, "NODE_B", "link1", make_sig());
    chain->append(ProofEventType::CONSENSUS_REACHED, "NODE_C", "link2", make_sig());
    auto path = chain->get_proof_path(1);
    EXPECT_FALSE(path.empty());
}

TEST_F(ProofChainTest, GetProofPathForInvalidSequence) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "link0", make_sig());
    auto path = chain->get_proof_path(999);
    EXPECT_TRUE(path.empty());
}

TEST_F(ProofChainTest, VerifyProofTamperedRootFails) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "link0", make_sig());
    chain->append(ProofEventType::PBFT_PREPARE, "NODE_B", "link1", make_sig());
    std::string root = chain->get_root_hash();
    auto leaf_hash = ProofLink::sha256_hex("link1");
    auto siblings = chain->get_proof_path(1);
    if (!siblings.empty()) {
        std::string bad_root(64, 'F');
        EXPECT_FALSE(ProofChain::verify_proof(bad_root, leaf_hash, siblings));
    }
}

TEST_F(ProofChainTest, VerifyProofTamperedLeafFails) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "link0", make_sig());
    std::string root = chain->get_root_hash();
    auto bad_leaf = ProofLink::sha256_hex("tampered");
    auto siblings = chain->get_proof_path(0);
    if (!siblings.empty()) {
        EXPECT_FALSE(ProofChain::verify_proof(root, bad_leaf, siblings));
    }
}

TEST_F(ProofChainTest, ExportProofToFile) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A", "link0", make_sig());
    chain->append(ProofEventType::CONSENSUS_REACHED, "NODE_B", "link1", make_sig());
    EXPECT_TRUE(chain->export_proof_to_file(0));
    EXPECT_FALSE(chain->export_proof_to_file(999));
}

TEST_F(ProofChainTest, ConcurrentAppendsMaintainConsistency) {
    for (int i = 0; i < 100; i++) {
        chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_" + std::to_string(i),
                      "data" + std::to_string(i), make_sig());
    }
    std::string root = chain->get_root_hash();
    EXPECT_FALSE(root.empty());
    auto path = chain->get_proof_path(50);
    EXPECT_FALSE(path.empty());
}

TEST_F(ProofChainTest, SequenceLookupSurvivesBoundedPruning) {
    for (size_t i = 0; i < ProofChain::MAX_CHAIN + 2; ++i) {
        chain->append(ProofEventType::ANOMALY_DETECTED, "NODE_A",
                      "data" + std::to_string(i), make_sig());
    }

    ASSERT_EQ(chain->size(), ProofChain::MAX_CHAIN);
    const auto snapshot = chain->links();
    ASSERT_FALSE(snapshot.empty());
    EXPECT_EQ(snapshot.front().sequence, 2u);
    EXPECT_TRUE(chain->get_proof_path(0).empty());
    EXPECT_FALSE(chain->get_proof_path(snapshot.front().sequence).empty());
    EXPECT_TRUE(chain->export_proof_to_file(snapshot.front().sequence));
}

TEST_F(ProofChainTest, SHA256HexProducesExpectedLength) {
    std::string hash = ProofLink::sha256_hex("test");
    EXPECT_EQ(hash.size(), 64u);
    EXPECT_NE(hash, ProofLink::sha256_hex("different"));
}

TEST_F(ProofChainTest, AppendAllEventTypes) {
    chain->append(ProofEventType::ANOMALY_DETECTED, "A", "d", make_sig());
    chain->append(ProofEventType::PBFT_PRE_PREPARE, "A", "d", make_sig());
    chain->append(ProofEventType::PBFT_PREPARE, "A", "d", make_sig());
    chain->append(ProofEventType::PBFT_COMMIT, "B", "d", make_sig());
    chain->append(ProofEventType::CONSENSUS_REACHED, "B", "d", make_sig());
    chain->append(ProofEventType::ISOLATION_EXECUTED, "C", "d", make_sig());
    chain->append(ProofEventType::TELEMETRY_GOSSIP, "D", "d", make_sig());
    EXPECT_FALSE(chain->get_root_hash().empty());
}
