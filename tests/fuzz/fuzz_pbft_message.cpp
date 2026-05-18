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

    // Parse as the actual wire format used by MeshNode::broadcast_pbft_stage():
    // VOTE|stage|sender|seq|view|target|evidence|prev_hash|signature
    // (9 pipe-delimited fields)
    size_t p[8];
    size_t idx = 0;
    size_t pos = 0;
    while (idx < 8 && pos < input.size()) {
        size_t found = input.find('|', pos);
        if (found == std::string::npos) break;
        p[idx++] = found;
        pos = found + 1;
    }
    if (idx < 8) return 0;  // Need at least 9 fields

    neuro_mesh::P2PMessage msg;
    msg.stage_str       = input.substr(0, p[0]);
    msg.sender_id       = input.substr(p[0] + 1, p[1] - p[0] - 1);
    // tokens[3] = seq, tokens[4] = view — parse as integers
    std::string seq_str = input.substr(p[2] + 1, p[3] - p[2] - 1);
    std::string view_str = input.substr(p[3] + 1, p[4] - p[3] - 1);
    msg.target_id       = input.substr(p[4] + 1, p[5] - p[4] - 1);
    msg.evidence_json   = input.substr(p[5] + 1, p[6] - p[5] - 1);
    msg.prev_message_hash = input.substr(p[6] + 1, p[7] - p[6] - 1);
    msg.signature       = input.substr(p[7] + 1);

    try {
        msg.sequence_number = std::stoull(seq_str);
        msg.view            = std::stoi(view_str);
    } catch (...) {
        msg.sequence_number = 0;
        msg.view            = 0;
    }

    // This should never crash
    pbft.verify_message(msg);
    pbft.advance_state(msg);

    return 0;
}
