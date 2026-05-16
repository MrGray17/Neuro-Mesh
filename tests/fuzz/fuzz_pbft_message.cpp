// Fuzz target for PBFT message parsing (built via make fuzz)
#include <cstdint>
#include <cstddef>
#include <string>
#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    neuro_mesh::PBFTConsensus pbft(3);

    // Register a fake peer key
    auto key = neuro_mesh::crypto::IdentityCore::generate_ed25519_key();
    std::string pem = neuro_mesh::crypto::IdentityCore::get_pem_from_pubkey(key.get());
    pbft.register_peer_key("FUZZ_PEER", pem);

    std::string input(reinterpret_cast<const char*>(data), size);

    // Try to parse as a PBFT message
    // Format: STAGE|SENDER|TARGET|EVIDENCE|SIGNATURE
    size_t p1 = input.find('|');
    if (p1 == std::string::npos) return 0;
    size_t p2 = input.find('|', p1 + 1);
    if (p2 == std::string::npos) return 0;
    size_t p3 = input.find('|', p2 + 1);
    if (p3 == std::string::npos) return 0;
    size_t p4 = input.find('|', p3 + 1);
    if (p4 == std::string::npos) return 0;

    neuro_mesh::P2PMessage msg;
    msg.stage_str = input.substr(0, p1);
    msg.sender_id = input.substr(p1 + 1, p2 - p1 - 1);
    msg.target_id = input.substr(p2 + 1, p3 - p2 - 1);
    msg.evidence_json = input.substr(p3 + 1, p4 - p3 - 1);
    msg.signature = input.substr(p4 + 1);

    // This should never crash
    pbft.verify_message(msg);
    pbft.advance_state(msg);

    return 0;
}
