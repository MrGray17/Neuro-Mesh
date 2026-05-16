#pragma once
#include <string>
#include <memory>
#include <optional>
#include <vector>
#include <chrono>
#include <unordered_set>
#include <functional>
#include <mutex>
#include <openssl/x509.h>
#include "crypto/CryptoCore.hpp"

namespace neuro_mesh::crypto {

enum class KeyType {
    Ed25519,
    RSA,
    Ed448
};

enum class HSMBackend {
    None,
    SoftHSM,
    PKCS11
};

struct CertificateConfig {
    std::string common_name;
    std::string organization;
    std::string organizational_unit;
    std::string country;
    std::string state;
    std::string locality;
    std::vector<std::string> sans;
    uint32_t validity_days = 365;
    bool is_ca = false;
    bool is_server_auth = true;
    bool is_client_auth = false;
};

struct X509Deleter {
    void operator()(X509* cert) const {
        if (cert) X509_free(cert);
    }
};

using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

struct Certificate {
    std::string key_id;
    UniqueX509 certificate;
    UniquePKEY ca_private_key;
    std::string subject;
    std::string issuer;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<std::string> sans;
    bool is_ca;
};

class HSMAccess {
public:
    virtual ~HSMAccess() = default;
    virtual bool is_available() const = 0;
    virtual bool generate_key(KeyType type, const std::string& key_id, UniquePKEY& pub_key, UniquePKEY& priv_key) = 0;
    virtual bool sign_data(const std::string& key_id, const std::string& data, std::string& signature) = 0;
    virtual bool verify_signature(const std::string& key_id, const std::string& data, const std::string& signature) = 0;
};

class SoftHSMBackend : public HSMAccess {
public:
    explicit SoftHSMBackend(const std::string& slot = "");
    bool is_available() const override;
    bool generate_key(KeyType type, const std::string& key_id, UniquePKEY& pub_key, UniquePKEY& priv_key) override;
    bool sign_data(const std::string& key_id, const std::string& data, std::string& signature) override;
    bool verify_signature(const std::string& key_id, const std::string& data, const std::string& signature) override;

private:
    std::string m_slot;
};

class PKCS11Backend : public HSMAccess {
public:
    explicit PKCS11Backend(const std::string& module_path = "",
                           const std::string& pin = "",
                           const std::string& token_label = "");
    ~PKCS11Backend() override;
    bool is_available() const override;
    bool generate_key(KeyType type, const std::string& key_id, UniquePKEY& pub_key, UniquePKEY& priv_key) override;
    bool sign_data(const std::string& key_id, const std::string& data, std::string& signature) override;
    bool verify_signature(const std::string& key_id, const std::string& data, const std::string& signature) override;

private:
    std::string m_module_path;
    std::string m_pin;
    std::string m_token_label;
    void* m_lib;

    // OpenSSL EVP_PKEY wrapper for keys stored on PKCS11 token
    // Uses OpenSSL's pkcs11 engine/provider when available, falls back to
    // loading key via PEM export if the token supports it.
    UniquePKEY load_key_from_token(const std::string& key_id, bool is_private);
    bool token_available() const;
};

struct KeyPair {
    std::string key_id;
    UniquePKEY public_key;
    UniquePKEY private_key;
    KeyType type;

    KeyPair() = default;
    KeyPair(std::string id, UniquePKEY pub, UniquePKEY priv, KeyType t)
        : key_id(std::move(id))
        , public_key(std::move(pub))
        , private_key(std::move(priv))
        , type(t) {}

    KeyPair(const KeyPair& other)
        : key_id(other.key_id)
        , type(other.type) {
        if (other.public_key) {
            public_key.reset(EVP_PKEY_dup(other.public_key.get()));
        }
        if (other.private_key) {
            private_key.reset(EVP_PKEY_dup(other.private_key.get()));
        }
    }

    KeyPair& operator=(const KeyPair& other) {
        if (this != &other) {
            key_id = other.key_id;
            type = other.type;
            if (other.public_key) {
                public_key.reset(EVP_PKEY_dup(other.public_key.get()));
            } else {
                public_key.reset();
            }
            if (other.private_key) {
                private_key.reset(EVP_PKEY_dup(other.private_key.get()));
            } else {
                private_key.reset();
            }
        }
        return *this;
    }

    KeyPair(KeyPair&&) = default;
    KeyPair& operator=(KeyPair&&) = default;
};

class KeyManager {
public:
    explicit KeyManager(const std::string& keystore_path = "");

    std::unique_ptr<KeyPair> generate_key(KeyType type, const std::string& key_id = "");

    bool store_key(const KeyPair& key_pair);
    std::unique_ptr<KeyPair> load_key(const std::string& key_id);
    bool delete_key(const std::string& key_id);

    std::string get_public_key_pem(const std::string& key_id);
    std::string get_private_key_pem(const std::string& key_id);

    bool has_key(const std::string& key_id) const;

    std::unique_ptr<Certificate> generate_certificate(
        const KeyPair& key_pair,
        const CertificateConfig& config,
        const std::string& ca_key_id = "");

    std::unique_ptr<Certificate> load_certificate(const std::string& cert_id);
    bool store_certificate(const Certificate& cert);
    bool delete_certificate(const std::string& cert_id);

    void set_hsm_backend(HSMBackend backend);
    HSMAccess* get_hsm() { return m_hsm.get(); }

    // Optional passphrase for AES-256-GCM keystore encryption
    void set_passphrase(const std::string& passphrase) { m_passphrase = passphrase; }

private:
    std::string m_keystore_path;
    std::optional<KeyPair> m_cached_key;
    std::unique_ptr<HSMAccess> m_hsm;
    HSMBackend m_hsm_backend = HSMBackend::None;
    std::string m_ca_key_id;
    std::string m_cert_store_path;
    std::string m_passphrase;

    std::string generate_key_id(KeyType type);

    // AES-256-GCM encryption helpers (used when m_passphrase is set)
    std::string encrypt_blob(const std::string& plaintext);
    std::string decrypt_blob(const std::string& ciphertext);
};

} // namespace neuro_mesh::crypto