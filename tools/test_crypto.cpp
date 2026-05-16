#include "crypto/CryptoCore.hpp"
#include <iostream>

using namespace neuro_mesh::crypto;

#define ASSERT(cond) \
    if (!(cond)) { throw std::runtime_error("assertion failed: " #cond); }

int main() {
    std::cout << "[*] Booting Ed25519 Verification Module..." << std::endl;

    UniquePKEY nodeA_key = IdentityCore::generate_ed25519_key();
    std::string nodeA_pub_pem = IdentityCore::get_pem_from_pubkey(nodeA_key.get());
    ASSERT(!nodeA_pub_pem.empty() && "Failed to generate Node A keys!");

    UniquePKEY nodeB_key = IdentityCore::generate_ed25519_key();

    std::string threat_evidence = "{\"TARGET\":\"NODE_5\",\"CPU\":99.0,\"REASON\":\"eBPF_ANOMALY\"}";

    std::string signature = IdentityCore::sign_payload(nodeA_key.get(), threat_evidence);
    std::cout << "[+] Node A signed threat evidence." << std::endl;

    UniquePKEY verified_pub_key = IdentityCore::get_pubkey_from_pem(nodeA_pub_pem);
    bool is_valid = IdentityCore::verify_signature(verified_pub_key.get(), threat_evidence, signature);
    std::cout << "[+] Verification with correct Public Key: " << (is_valid ? "PASSED" : "FAILED") << std::endl;
    ASSERT(is_valid && "Legitimate signature was rejected!");

    bool is_imposter_valid = IdentityCore::verify_signature(nodeB_key.get(), threat_evidence, signature);
    std::cout << "[+] Verification with Imposter Public Key: " << (!is_imposter_valid ? "PASSED (Rejected)" : "FAILED (Accepted)") << std::endl;
    ASSERT(!is_imposter_valid && "Imposter key was wrongly accepted!");

    std::string tampered_evidence = "{\"TARGET\":\"NODE_1\",\"CPU\":99.0,\"REASON\":\"eBPF_ANOMALY\"}";
    bool is_tampered_valid = IdentityCore::verify_signature(verified_pub_key.get(), tampered_evidence, signature);
    std::cout << "[+] Verification of tampered payload: " << (!is_tampered_valid ? "PASSED (Rejected)" : "FAILED (Accepted)") << std::endl;
    ASSERT(!is_tampered_valid && "Tampered payload was wrongly accepted!");

    std::cout << "\n[SUCCESS] Cryptographic foundation is mathematically flawless." << std::endl;
    return 0;
}
