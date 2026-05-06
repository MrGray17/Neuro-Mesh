#include "CryptoCore.hpp"
#include <openssl/pem.h>
#include <openssl/err.h>

namespace neuro_mesh::crypto {

UniquePKEY IdentityCore::generate_ed25519_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0) {
        EVP_PKEY_CTX_free(ctx);
        return UniquePKEY(pkey);
    }
    
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return nullptr;
}

std::string IdentityCore::sign_payload(EVP_PKEY* priv_key, const std::string& data) {
    if (!priv_key) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;

    // First call determines the required buffer size
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, priv_key) <= 0 ||
        EVP_DigestSign(ctx, nullptr, &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    // Second call signs the data
    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(ctx, sig.data(), &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(sig.data()), sig_len);
}

bool IdentityCore::verify_signature(EVP_PKEY* pub_key, const std::string& data, const std::string& signature) {
    if (!pub_key || signature.empty()) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pub_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    int result = EVP_DigestVerify(ctx, 
        reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), 
        reinterpret_cast<const unsigned char*>(data.data()), data.size());

    EVP_MD_CTX_free(ctx);
    return result == 1; 
}

std::string IdentityCore::get_pem_from_pubkey(EVP_PKEY* key) {
    if (!key) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, key);
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    
    BIO_free(bio);
    return pem;
}

UniquePKEY IdentityCore::get_pubkey_from_pem(const std::string& pem) {
    if (pem.empty()) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    
    BIO_free(bio);
    return UniquePKEY(pkey);
}

} // namespace neuro_mesh::crypto
