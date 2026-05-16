#include "crypto/CryptoCore.hpp"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace neuro_mesh::crypto {

UniquePKEY IdentityCore::generate_ed25519_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(pctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }

    EVP_PKEY_CTX_free(pctx);
    return UniquePKEY(key);
}

std::string IdentityCore::sign_payload(EVP_PKEY* priv_key, const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, priv_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    const auto* bytes = reinterpret_cast<const unsigned char*>(data.data());
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, nullptr, &sig_len, bytes, data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, bytes, data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(sig.data()), sig_len);
}

bool IdentityCore::verify_signature(EVP_PKEY* pub_key, const std::string& data, const std::string& signature) {
    if (!pub_key) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pub_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerify(ctx,
        reinterpret_cast<const unsigned char*>(signature.data()), signature.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size());
    EVP_MD_CTX_free(ctx);
    return (result == 1);
}

std::string IdentityCore::get_pem_from_pubkey(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    if (PEM_write_bio_PUBKEY(bio, key) != 1) { BIO_free(bio); return ""; }

    char* pem_data = nullptr;
    long len = BIO_get_mem_data(bio, &pem_data);
    std::string pem(pem_data, len);
    BIO_free(bio);
    return pem;
}

UniquePKEY IdentityCore::get_pubkey_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return UniquePKEY(key);
}

std::string IdentityCore::sha256_hex(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(hash[i]);
    }
    return oss.str();
}

std::string IdentityCore::cert_fingerprint(const std::string& der_cert) {
    return sha256_hex(der_cert);
}

} // namespace neuro_mesh::crypto
