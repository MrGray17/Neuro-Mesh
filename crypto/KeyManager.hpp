#pragma once
#include <string>
#include <memory>
#include <vector>
#include <optional>
#include <chrono>
#include <functional>
#include <thread>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace neuro_mesh::crypto {

enum class KeyType {
    ED25519,
    RSA_4096,
    ML_KEM_768,
    ML_KEM_1024
};

enum class KeySource {
    TPM_2_0,
    SOFT_HSM,
    SOFTWARE,
    MEMORY
};

struct KeyMetadata {
    std::string key_id;
    KeyType type;
    KeySource source;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    bool is_rotating = false;
    std::string parent_key_id;
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> private_key;
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> public_key;
};

struct KeyPair {
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> private_key;
    KeyMetadata metadata;
};

struct Certificate {
    std::string pem_encoded;
    std::string subject;
    std::string issuer;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<std::string> san;
    bool is_revoked = false;
};

class KeyManager {
public:
    using KeyRotationCallback = std::function<void(const std::string&)>;

    explicit KeyManager(KeySource preferred_source = KeySource::SOFTWARE);
    ~KeyManager();

    bool is_available() const { return m_available; }
    KeySource source() const { return m_source; }

    std::optional<KeyPair> generate_key(KeyType type, const std::string& key_id = "");

    std::optional<std::string> sign(const std::string& key_id, const std::string& data);

    bool verify(const std::string& key_id, const std::string& data, const std::string& signature);

    bool import_key(KeyType type, const std::string& key_id, const std::string& private_key_pem);

    bool export_public_key(const std::string& key_id, std::string& public_key_pem);

    bool delete_key(const std::string& key_id);

    std::optional<Certificate> create_certificate(
        const std::string& key_id,
        const std::string& subject,
        const std::vector<std::string>& san,
        const std::chrono::days& validity_days);

    bool import_certificate(const Certificate& cert);

    std::optional<Certificate> get_certificate(const std::string& key_id);

    std::vector<std::string> list_key_ids() const;

    void set_rotation_callback(KeyRotationCallback callback);

    bool rotate_key(const std::string& key_id);

    std::optional<KeyPair> get_key_pair(const std::string& key_id);

    static std::string key_type_to_string(KeyType type);
    static std::string source_to_string(KeySource source);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    KeySource m_source;
    bool m_available;
};

class KeyManagerFactory {
public:
    static std::unique_ptr<KeyManager> create(KeySource source);
    static std::vector<KeySource> available_sources();
    static KeySource detect_best_source();
};

class KeyRotationScheduler {
public:
    KeyRotationScheduler(KeyManager* manager, std::chrono::hours rotation_interval);

    void start();
    void stop();

    void schedule_rotation(const std::string& key_id);
    void cancel_rotation(const std::string& key_id);

    bool is_rotating(const std::string& key_id) const;

    void on_rotation_complete(const std::string& key_id, const std::string& new_key_id);

private:
    void rotation_loop();
    void execute_rotation(const std::string& key_id);

    KeyManager* m_manager;
    std::chrono::hours m_interval;
    bool m_running;
    std::thread m_thread;
    std::mutex m_mutex;
    std::unordered_map<std::string, bool> m_pending_rotations;
};

} // namespace neuro_mesh::crypto