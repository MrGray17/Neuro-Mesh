#include "crypto/KeyManager.hpp"
#include "crypto/CryptoCore.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>

#ifdef __linux__
#include <dlfcn.h>
#endif

namespace neuro_mesh::crypto {

class KeyManager::Impl {
public:
    Impl(KeySource source) : m_source(source) {
        m_available = initialize();
    }

    bool is_available() const { return m_available; }
    KeySource source() const { return m_source; }

    std::optional<KeyPair> generate_key(KeyType type, const std::string& key_id) {
        std::string id = key_id.empty() ? generate_key_id() : key_id;

        if (m_source == KeySource::TPM_2_0) {
            return generate_tpm_key(type, id);
        } else if (m_source == KeySource::SOFT_HSM) {
            return generate_soft_hsm_key(type, id);
        } else {
            return generate_software_key(type, id);
        }
    }

    std::optional<std::string> sign(const std::string& key_id, const std::string& data) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) {
            std::cerr << "[KEYMGR] Key not found: " << key_id << std::endl;
            return std::nullopt;
        }

        if (m_source == KeySource::TPM_2_0) {
            return sign_tpm(key_id, data);
        } else if (m_source == KeySource::SOFT_HSM) {
            return sign_soft_hsm(key_id, data);
        } else {
            return sign_software(key_id, data);
        }
    }

    bool verify(const std::string& key_id, const std::string& data, const std::string& signature) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return false;

        std::string blob = data;
        return IdentityCore::verify_signature(it->second.metadata.public_key.get(), blob, signature);
    }

    bool import_key(KeyType type, const std::string& key_id, const std::string& private_key_pem) {
        if (m_source != KeySource::SOFTWARE && m_source != KeySource::MEMORY) {
            std::cerr << "[KEYMGR] Import not supported for source: " << static_cast<int>(m_source) << std::endl;
            return false;
        }

        BIO* bio = BIO_new_mem_buf(private_key_pem.c_str(), -1);
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) return false;

        KeyPair kp;
        kp.private_key.reset(pkey);
        kp.metadata.key_id = key_id;
        kp.metadata.type = type;
        kp.metadata.source = m_source;
        kp.metadata.created_at = std::chrono::system_clock::now();
        kp.metadata.expires_at = kp.metadata.created_at + std::chrono::days(365 * 5);

        kp.metadata.public_key.reset(EVP_PKEY_dup(pkey));

        m_keys[key_id] = std::move(kp);
        return true;
    }

    bool export_public_key(const std::string& key_id, std::string& public_key_pem) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return false;

        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, it->second.metadata.public_key.get());
        char* ptr = nullptr;
        long len = BIO_get_mem_data(bio, &ptr);
        public_key_pem = std::string(ptr, len);
        BIO_free(bio);
        return true;
    }

    bool delete_key(const std::string& key_id) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return false;

        if (m_source == KeySource::TPM_2_0) {
            delete_tpm_key(key_id);
        } else if (m_source == KeySource::SOFT_HSM) {
            delete_soft_hsm_key(key_id);
        }

        m_keys.erase(it);
        return true;
    }

    std::optional<Certificate> create_certificate(
        const std::string& key_id,
        const std::string& subject,
        const std::vector<std::string>& san,
        const std::chrono::days& validity_days) {

        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return std::nullopt;

        X509* cert = X509_new();
        if (!cert) return std::nullopt;

        X509_set_version(cert, 2);

        ASN1_INTEGER_set(X509_get_serialNumber(cert), generate_serial());

        X509_NAME* name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
            (const unsigned char*)subject.c_str(), -1, -1, 0);
        X509_set_subject_name(cert, name);
        X509_set_issuer_name(cert, name);

        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), validity_days.count() * 24 * 60 * 60);

        EVP_PKEY* pubkey = it->second.metadata.public_key.get();
        X509_set_pubkey(cert, pubkey);

        if (!san.empty()) {
            STACK_OF(GENERAL_NAME)* names = sk_GENERAL_NAME_new_null();
            for (const auto& s : san) {
                GENERAL_NAME* gen = GENERAL_NAME_new();
                GENERAL_NAME_set_type_value(gen, GEN_DNS, (char*)s.c_str());
                sk_GENERAL_NAME_push(names, gen);
            }
            X509_add1_ext_i2d(cert, NID_subject_alt_name, names, 0, 0);
        }

        X509_sign(cert, it->second.metadata.private_key.get(), EVP_sha256());

        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio, cert);
        char* ptr = nullptr;
        long len = BIO_get_mem_data(bio, &ptr);
        std::string pem(ptr, len);
        BIO_free(bio);

        Certificate result;
        result.pem_encoded = pem;
        result.subject = subject;
        result.issuer = subject;
        result.not_before = std::chrono::system_clock::now();
        result.not_after = result.not_before + validity_days;
        result.san = san;

        m_certificates[key_id] = result;

        return result;
    }

    std::vector<std::string> list_key_ids() const {
        std::vector<std::string> ids;
        for (const auto& [id, _] : m_keys) {
            ids.push_back(id);
        }
        return ids;
    }

    std::optional<Certificate> get_certificate(const std::string& key_id) {
        auto it = m_certificates.find(key_id);
        if (it != m_certificates.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void set_rotation_callback(KeyRotationCallback callback) {
        m_rotation_callback = callback;
    }

    bool rotate_key(const std::string& key_id) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return false;

        KeyType type = it->second.metadata.type;
        it->second.metadata.is_rotating = true;

        std::string new_id = key_id + "_" + std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        auto new_key = generate_key(type, new_id);
        if (!new_key) return false;

        m_keys[new_id] = std::move(*new_key);
        m_keys[new_id].metadata.parent_key_id = key_id;
        m_keys[new_id].metadata.created_at = std::chrono::system_clock::now();

        it->second.metadata.is_rotating = false;

        if (m_rotation_callback) {
            m_rotation_callback(new_id);
        }

        return true;
    }

    std::optional<KeyPair> get_key_pair(const std::string& key_id) {
        auto it = m_keys.find(key_id);
        if (it != m_keys.end()) {
            return it->second;
        }
        return std::nullopt;
    }

private:
    KeySource m_source;
    bool m_available;
    KeyRotationCallback m_rotation_callback;
    std::unordered_map<std::string, KeyPair> m_keys;
    std::unordered_map<std::string, Certificate> m_certificates;

    bool initialize() {
        if (m_source == KeySource::TPM_2_0) {
            return initialize_tpm();
        } else if (m_source == KeySource::SOFT_HSM) {
            return initialize_soft_hsm();
        }
        return true;
    }

    bool initialize_tpm() {
#ifdef __linux__
        void* handle = dlopen("libtss2.so.0", RTLD_NOW);
        if (!handle) {
            std::cerr << "[KEYMGR] TPM2 library not available, falling back to software" << std::endl;
            m_source = KeySource::SOFTWARE;
            return true;
        }
        dlclose(handle);
        return true;
#else
        std::cerr << "[KEYMGR] TPM2 not supported on this platform" << std::endl;
        m_source = KeySource::SOFTWARE;
        return true;
#endif
    }

    bool initialize_soft_hsm() {
#ifdef __linux__
        void* handle = dlopen("libsofthsm2.so", RTLD_NOW);
        if (!handle) {
            std::cerr << "[KEYMGR] SoftHSM not available, falling back to software" << std::endl;
            m_source = KeySource::SOFTWARE;
            return true;
        }
        dlclose(handle);
        return true;
#else
        m_source = KeySource::SOFTWARE;
        return true;
#endif
    }

    std::string generate_key_id() {
        unsigned char buf[16];
        RAND_bytes(buf, sizeof(buf));
        std::stringstream ss;
        for (int i = 0; i < 16; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
        }
        return ss.str();
    }

    long generate_serial() {
        unsigned char buf[8];
        RAND_bytes(buf, sizeof(buf));
        long serial = 0;
        for (int i = 0; i < 8; ++i) {
            serial = (serial << 8) | buf[i];
        }
        return serial;
    }

    std::optional<KeyPair> generate_software_key(KeyType type, const std::string& key_id) {
        if (type == KeyType::ED25519) {
            auto pkey = IdentityCore::generate_ed25519_key();
            if (!pkey) return std::nullopt;

            KeyPair kp;
            kp.private_key.release();
            kp.private_key.reset(pkey.release());

            kp.metadata.key_id = key_id;
            kp.metadata.type = type;
            kp.metadata.source = KeySource::SOFTWARE;
            kp.metadata.created_at = std::chrono::system_clock::now();
            kp.metadata.expires_at = kp.metadata.created_at + std::chrono::days(365 * 5);

            kp.metadata.public_key.reset(EVP_PKEY_dup(pkey.get()));
            m_keys[key_id] = std::move(kp);

            return m_keys[key_id];
        }

        return std::nullopt;
    }

    std::optional<KeyPair> generate_tpm_key(KeyType type, const std::string& key_id) {
        return generate_software_key(type, key_id);
    }

    std::optional<KeyPair> generate_soft_hsm_key(KeyType type, const std::string& key_id) {
        return generate_software_key(type, key_id);
    }

    std::optional<std::string> sign_software(const std::string& key_id, const std::string& data) {
        auto it = m_keys.find(key_id);
        if (it == m_keys.end()) return std::nullopt;

        return IdentityCore::sign_payload(it->second.metadata.private_key.get(), data);
    }

    std::optional<std::string> sign_tpm(const std::string& key_id, const std::string& data) {
        return sign_software(key_id, data);
    }

    std::optional<std::string> sign_soft_hsm(const std::string& key_id, const std::string& data) {
        return sign_software(key_id, data);
    }

    void delete_tpm_key(const std::string& key_id) {
        // TPM key deletion would go here
    }

    void delete_soft_hsm_key(const std::string& key_id) {
        // SoftHSM key deletion would go here
    }
};

KeyManager::KeyManager(KeySource preferred_source)
    : m_impl(std::make_unique<Impl>(preferred_source))
    , m_source(preferred_source)
    , m_available(m_impl->is_available()) {
}

KeyManager::~KeyManager() = default;

std::optional<KeyPair> KeyManager::generate_key(KeyType type, const std::string& key_id) {
    return m_impl->generate_key(type, key_id);
}

std::optional<std::string> KeyManager::sign(const std::string& key_id, const std::string& data) {
    return m_impl->sign(key_id, data);
}

bool KeyManager::verify(const std::string& key_id, const std::string& data, const std::string& signature) {
    return m_impl->verify(key_id, data, signature);
}

bool KeyManager::import_key(KeyType type, const std::string& key_id, const std::string& private_key_pem) {
    return m_impl->import_key(type, key_id, private_key_pem);
}

bool KeyManager::export_public_key(const std::string& key_id, std::string& public_key_pem) {
    return m_impl->export_public_key(key_id, public_key_pem);
}

bool KeyManager::delete_key(const std::string& key_id) {
    return m_impl->delete_key(key_id);
}

std::optional<Certificate> KeyManager::create_certificate(
    const std::string& key_id,
    const std::string& subject,
    const std::vector<std::string>& san,
    const std::chrono::days& validity_days) {
    return m_impl->create_certificate(key_id, subject, san, validity_days);
}

std::optional<Certificate> KeyManager::get_certificate(const std::string& key_id) {
    return m_impl->get_certificate(key_id);
}

std::vector<std::string> KeyManager::list_key_ids() const {
    return m_impl->list_key_ids();
}

void KeyManager::set_rotation_callback(KeyRotationCallback callback) {
    m_impl->set_rotation_callback(callback);
}

bool KeyManager::rotate_key(const std::string& key_id) {
    return m_impl->rotate_key(key_id);
}

std::optional<KeyPair> KeyManager::get_key_pair(const std::string& key_id) {
    return m_impl->get_key_pair(key_id);
}

std::string KeyManager::key_type_to_string(KeyType type) {
    switch (type) {
        case KeyType::ED25519: return "Ed25519";
        case KeyType::RSA_4096: return "RSA-4096";
        case KeyType::ML_KEM_768: return "ML-KEM-768";
        case KeyType::ML_KEM_1024: return "ML-KEM-1024";
        default: return "Unknown";
    }
}

std::string KeyManager::source_to_string(KeySource source) {
    switch (source) {
        case KeySource::TPM_2_0: return "TPM 2.0";
        case KeySource::SOFT_HSM: return "SoftHSM";
        case KeySource::SOFTWARE: return "Software";
        case KeySource::MEMORY: return "Memory";
        default: return "Unknown";
    }
}

std::unique_ptr<KeyManager> KeyManagerFactory::create(KeySource source) {
    return std::make_unique<KeyManager>(source);
}

std::vector<KeySource> KeyManagerFactory::available_sources() {
    std::vector<KeySource> sources = { KeySource::SOFTWARE };

#ifdef __linux__
    void* tpm = dlopen("libtss2.so.0", RTLD_NOW | RTLD_NOLOAD);
    if (tpm) {
        dlclose(tpm);
        sources.push_back(KeySource::TPM_2_0);
    }

    void* hsm = dlopen("libsofthsm2.so", RTLD_NOW | RTLD_NOLOAD);
    if (hsm) {
        dlclose(hsm);
        sources.push_back(KeySource::SOFT_HSM);
    }
#endif

    return sources;
}

KeySource KeyManagerFactory::detect_best_source() {
    auto sources = available_sources();

    if (std::find(sources.begin(), sources.end(), KeySource::TPM_2_0) != sources.end()) {
        return KeySource::TPM_2_0;
    }
    if (std::find(sources.begin(), sources.end(), KeySource::SOFT_HSM) != sources.end()) {
        return KeySource::SOFT_HSM;
    }
    return KeySource::SOFTWARE;
}

KeyRotationScheduler::KeyRotationScheduler(KeyManager* manager, std::chrono::hours rotation_interval)
    : m_manager(manager)
    , m_interval(rotation_interval)
    , m_running(false) {
}

void KeyRotationScheduler::start() {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&KeyRotationScheduler::rotation_loop, this);
    std::cout << "[KEYMGR] Rotation scheduler started (interval: " << m_interval.count() << "h)" << std::endl;
}

void KeyRotationScheduler::stop() {
    m_running = false;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void KeyRotationScheduler::schedule_rotation(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pending_rotations[key_id] = true;
}

void KeyRotationScheduler::cancel_rotation(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pending_rotations.erase(key_id);
}

bool KeyRotationScheduler::is_rotating(const std::string& key_id) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_pending_rotations.find(key_id);
    return it != m_pending_rotations.end() && it->second;
}

void KeyRotationScheduler::on_rotation_complete(const std::string& key_id, const std::string& new_key_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pending_rotations[key_id] = false;
    std::cout << "[KEYMGR] Key rotation complete: " << key_id << " -> " << new_key_id << std::endl;
}

void KeyRotationScheduler::rotation_loop() {
    while (m_running) {
        std::this_thread::sleep_for(m_interval);

        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [key_id, pending] : m_pending_rotations) {
            if (pending) {
                execute_rotation(key_id);
            }
        }
    }
}

void KeyRotationScheduler::execute_rotation(const std::string& key_id) {
    std::cout << "[KEYMGR] Executing scheduled rotation for key: " << key_id << std::endl;
    m_manager->rotate_key(key_id);
}

} // namespace neuro_mesh::crypto