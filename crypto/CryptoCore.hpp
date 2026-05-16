#pragma once
#include <string>
#include <memory>
#include <vector>
#include <openssl/evp.h>

namespace neuro_mesh::crypto {

// RAII Wrapper: Guarantees OpenSSL cleans up memory automatically to prevent leaks
struct EVPKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
using UniquePKEY = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;

// D3FEND: D3-IPI (Identity Protection & Integrity) — Ed25519 signatures bind every
// PBFT vote to (stage + target + evidence), preventing cross-stage replay and spoofing.
/**
 * @brief Zero-Trust Identity Core for P2P Mesh
 * Uses Ed25519 for high-speed, non-malleable cryptographic signatures.
 */
class IdentityCore {
public:
    // Generate a fresh Ed25519 Private/Public keypair
    static UniquePKEY generate_ed25519_key();

    // Sign consensus evidence using the node's private key
    static std::string sign_payload(EVP_PKEY* priv_key, const std::string& data);

    // Verify a peer's vote using their public key
    static bool verify_signature(EVP_PKEY* pub_key, const std::string& data, const std::string& signature);

    // Network transport helpers (Convert keys to/from strings)
    static std::string get_pem_from_pubkey(EVP_PKEY* key);
    static UniquePKEY get_pubkey_from_pem(const std::string& pem);

    // SHA-256 hex digest — used for enforcement audit hashing
    static std::string sha256_hex(const std::string& data);

    // Compute SHA-256 fingerprint of a DER-encoded certificate
    static std::string cert_fingerprint(const std::string& der_cert);
};

} // namespace neuro_mesh::crypto
