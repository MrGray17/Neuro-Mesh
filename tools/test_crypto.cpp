#include "crypto/CryptoCore.hpp"
#include <iostream>
#include <cassert>

using namespace neuro_mesh::crypto;

int main() {
    std::cout << "[*] Booting V8.0 Ed25519 Verification Module..." << std::endl;

    // 1. Generate keys for Node A (The Proposer)
    UniquePKEY nodeA_key = IdentityCore::generate_ed25519_key();
    std::string nodeA_pub_pem = IdentityCore::get_pem_from_pubkey(nodeA_key.get());
    assert(!nodeA_pub_pem.empty() && "Failed to generate Node A keys!");

    // 2. Generate keys for Node B (The Attacker/Imposter)
    UniquePKEY nodeB_key = IdentityCore::generate_ed25519_key();

    std::string threat_evidence = "{\"TARGET\":\"NODE_5\",\"CPU\":99.0,\"REASON\":\"eBPF_ANOMALY\"}";

    // Node A signs the threat
    std::string signature = IdentityCore::sign_payload(nodeA_key.get(), threat_evidence);
    std::cout << "[+] Node A signed threat evidence." << std::endl;

    // Node C verifies the threat using Node A's public key (SUCCESS expected)
    UniquePKEY verified_pub_key = IdentityCore::get_pubkey_from_pem(nodeA_pub_pem);
    bool is_valid = IdentityCore::verify_signature(verified_pub_key.get(), threat_evidence, signature);
    std::cout << "[+] Verification with correct Public Key: " << (is_valid ? "PASSED" : "FAILED") << std::endl;
    assert(is_valid && "Legitimate signature was rejected!");

    // Verification using Node B's public key (FAILURE expected)
    bool is_imposter_valid = IdentityCore::verify_signature(nodeB_key.get(), threat_evidence, signature);
    std::cout << "[+] Verification with Imposter Public Key: " << (!is_imposter_valid ? "PASSED (Rejected)" : "FAILED (Accepted)") << std::endl;
    assert(!is_imposter_valid && "Imposter key was wrongly accepted!");

    // Tampering test (FAILURE expected)
    std::string tampered_evidence = "{\"TARGET\":\"NODE_1\",\"CPU\":99.0,\"REASON\":\"eBPF_ANOMALY\"}";
    bool is_tampered_valid = IdentityCore::verify_signature(verified_pub_key.get(), tampered_evidence, signature);
    std::cout << "[+] Verification of tampered payload: " << (!is_tampered_valid ? "PASSED (Rejected)" : "FAILED (Accepted)") << std::endl;
    assert(!is_tampered_valid && "Tampered payload was wrongly accepted!");

    std::cout << "\n[SUCCESS] Cryptographic foundation is mathematically flawless. Ready for UDP." << std::endl;
    return 0;
}
