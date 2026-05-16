#include "crypto/KeyManager.hpp"
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <dlfcn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <mutex>
#include <endian.h>

namespace neuro_mesh::crypto {

namespace {

std::string random_hex(size_t bytes) {
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    std::ostringstream oss;
    for (size_t i = 0; i < bytes; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (dist(rd) & 0xFF);
    }
    return oss.str();
}

std::string key_type_to_string(KeyType type) {
    switch (type) {
        case KeyType::Ed25519: return "ed25519";
        case KeyType::RSA: return "rsa";
        case KeyType::Ed448: return "ed448";
        default: return "unknown";
    }
}

bool create_directory(const std::string& path) {
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

bool path_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

X509* create_x509_cert(const CertificateConfig& config, EVP_PKEY* pub_key, EVP_PKEY* ca_key, X509* ca_cert, bool is_ca) {
    X509* cert = X509_new();
    if (!cert) return nullptr;

    X509_set_version(cert, 2);

    std::random_device rd;
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    uint64_t serial = dist(rd);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), config.validity_days * 24 * 60 * 60);

    X509_set_pubkey(cert, pub_key);

    X509_NAME* name = X509_NAME_new();
    if (!config.common_name.empty()) X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)config.common_name.c_str(), -1, -1, 0);
    if (!config.organization.empty()) X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)config.organization.c_str(), -1, -1, 0);
    if (!config.organizational_unit.empty()) X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)config.organizational_unit.c_str(), -1, -1, 0);
    if (!config.country.empty()) X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)config.country.c_str(), -1, -1, 0);
    if (!config.state.empty()) X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)config.state.c_str(), -1, -1, 0);
    if (!config.locality.empty()) X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)config.locality.c_str(), -1, -1, 0);

    X509_set_subject_name(cert, name);

    if (ca_cert) {
        X509_NAME* ca_name = X509_get_subject_name(ca_cert);
        X509_set_issuer_name(cert, ca_name);
    } else {
        X509_set_issuer_name(cert, name);
    }

    if (!config.sans.empty()) {
        STACK_OF(GENERAL_NAME)* gens = sk_GENERAL_NAME_new_null();
        for (const auto& san : config.sans) {
            GENERAL_NAME* gen = GENERAL_NAME_new();
            ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
            if (ia5 && ASN1_STRING_set(ia5, san.c_str(), san.size())) {
                gen->type = GEN_DNS;
                gen->d.ia5 = ia5;
            }
            sk_GENERAL_NAME_push(gens, gen);
        }
        X509_add1_ext_i2d(cert, NID_subject_alt_name, gens, 0, 0);
        sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    }

    if (is_ca) {
        X509_add1_ext_i2d(cert, NID_basic_constraints, (char*)"CA:TRUE", 0, 0);
        X509_add1_ext_i2d(cert, NID_key_usage, (char*)"keyCertSign,cRLSign", 0, 0);
    } else {
        X509_add1_ext_i2d(cert, NID_basic_constraints, (char*)"CA:FALSE", 0, 0);
        if (config.is_server_auth) X509_add1_ext_i2d(cert, NID_ext_key_usage, (char*)"serverAuth", 0, 0);
        if (config.is_client_auth) X509_add1_ext_i2d(cert, NID_ext_key_usage, (char*)"clientAuth", 0, 0);
    }

    if (ca_key) {
        X509_sign(cert, ca_key, EVP_sha256());
    } else {
        X509_sign(cert, pub_key, EVP_sha256());
    }

    X509_NAME_free(name);
    return cert;
}

} // namespace

KeyManager::KeyManager(const std::string& keystore_path)
    : m_keystore_path(keystore_path)
    , m_cert_store_path(keystore_path + "/certs") {
    if (!m_keystore_path.empty()) {
        create_directory(m_keystore_path);
        create_directory(m_cert_store_path);
    }
}

void KeyManager::set_hsm_backend(HSMBackend backend) {
    m_hsm_backend = backend;
    m_hsm.reset();

    switch (backend) {
        case HSMBackend::SoftHSM:
            m_hsm = std::make_unique<SoftHSMBackend>();
            break;
        case HSMBackend::TPM2:
            m_hsm = std::make_unique<TPM2Backend>();
            break;
        case HSMBackend::PKCS11:
            m_hsm = std::make_unique<PKCS11Backend>("libpkcs11.so", "");
            break;
        default:
            break;
    }
}

std::unique_ptr<KeyPair> KeyManager::generate_key(KeyType type, const std::string& key_id) {
    if (m_hsm && m_hsm->is_available()) {
        UniquePKEY pub_key, priv_key;
        if (m_hsm->generate_key(type, key_id.empty() ? generate_key_id(type) : key_id, pub_key, priv_key)) {
            return std::make_unique<KeyPair>(key_id, std::move(pub_key), std::move(priv_key), type);
        }
    }

    UniquePKEY priv_key;
    UniquePKEY pub_key;

    switch (type) {
        case KeyType::Ed25519: {
            priv_key = IdentityCore::generate_ed25519_key();
            pub_key.reset(EVP_PKEY_dup(priv_key.get()));
            break;
        }
        case KeyType::RSA: {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!pctx) return nullptr;

            if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return nullptr;
            }

            EVP_PKEY* key = nullptr;
            if (EVP_PKEY_keygen(pctx, &key) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return nullptr;
            }
            EVP_PKEY_CTX_free(pctx);

            priv_key.reset(key);
            pub_key.reset(EVP_PKEY_dup(key));
            break;
        }
        case KeyType::Ed448: {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, nullptr);
            if (!pctx) return nullptr;

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return nullptr;
            }

            EVP_PKEY* key = nullptr;
            if (EVP_PKEY_keygen(pctx, &key) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return nullptr;
            }
            EVP_PKEY_CTX_free(pctx);

            priv_key.reset(key);
            pub_key.reset(EVP_PKEY_dup(key));
            break;
        }
        default:
            return nullptr;
    }

    std::string id = key_id.empty() ? generate_key_id(type) : key_id;
    return std::make_unique<KeyPair>(id, std::move(pub_key), std::move(priv_key), type);
}

bool KeyManager::store_key(const KeyPair& key_pair) {
    if (m_keystore_path.empty()) return false;

    std::string key_file = m_keystore_path + "/" + key_pair.key_id + ".pem";
    std::ofstream out(key_file, std::ios::binary);
    if (!out) return false;

    if (!key_pair.private_key) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;

    if (PEM_write_bio_PrivateKey(bio, key_pair.private_key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        return false;
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    out.write(data, len);
    BIO_free(bio);
    out.close();

    m_cached_key.emplace(key_pair);
    return true;
}

std::unique_ptr<KeyPair> KeyManager::load_key(const std::string& key_id) {
    if (m_keystore_path.empty()) return nullptr;

    std::string key_file = m_keystore_path + "/" + key_id + ".pem";
    std::ifstream in(key_file, std::ios::binary);
    if (!in) return nullptr;

    std::stringstream buffer;
    buffer << in.rdbuf();
    std::string pem = buffer.str();

    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return nullptr;

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) return nullptr;

    UniquePKEY priv_key(key);
    UniquePKEY pub_key(EVP_PKEY_dup(key));

    return std::make_unique<KeyPair>(key_id, std::move(pub_key), std::move(priv_key), KeyType::Ed25519);
}

bool KeyManager::delete_key(const std::string& key_id) {
    if (m_keystore_path.empty()) return false;
    return std::remove((m_keystore_path + "/" + key_id + ".pem").c_str()) == 0;
}

std::string KeyManager::get_public_key_pem(const std::string& key_id) {
    if (m_cached_key && m_cached_key->key_id == key_id) {
        return IdentityCore::get_pem_from_pubkey(m_cached_key->public_key.get());
    }
    auto key = load_key(key_id);
    if (!key) return "";
    return IdentityCore::get_pem_from_pubkey(key->public_key.get());
}

std::string KeyManager::get_private_key_pem(const std::string& key_id) {
    if (m_cached_key && m_cached_key->key_id == key_id) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return "";
        PEM_write_bio_PrivateKey(bio, m_cached_key->private_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }
    auto key = load_key(key_id);
    if (!key) return "";
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    PEM_write_bio_PrivateKey(bio, key->private_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    return pem;
}

bool KeyManager::has_key(const std::string& key_id) const {
    if (m_cached_key && m_cached_key->key_id == key_id) return true;
    if (m_keystore_path.empty()) return false;
    return path_exists(m_keystore_path + "/" + key_id + ".pem");
}

std::string KeyManager::generate_key_id(KeyType type) {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return key_type_to_string(type) + "_" + std::to_string(now) + "_" + random_hex(8);
}

std::unique_ptr<Certificate> KeyManager::generate_certificate(
    const KeyPair& key_pair,
    const CertificateConfig& config,
    const std::string& ca_key_id) {

    UniquePKEY ca_key;
    UniqueX509 ca_cert;
    if (!ca_key_id.empty()) {
        auto ca = load_key(ca_key_id);
        if (ca) ca_key = std::move(ca->private_key);
        auto ca_cert_loaded = load_certificate(ca_key_id);
        if (ca_cert_loaded) ca_cert = std::move(ca_cert_loaded->certificate);
    }

    X509* cert = create_x509_cert(config, key_pair.public_key.get(), ca_key.get(), ca_cert.get(), config.is_ca);
    if (!cert) return nullptr;

    auto result = std::make_unique<Certificate>();
    result->key_id = key_pair.key_id + "_cert";
    result->certificate = UniqueX509(cert, X509Deleter());
    result->ca_private_key = std::move(ca_key);
    result->not_before = std::chrono::system_clock::from_time_t(0);
    result->not_after = std::chrono::system_clock::now() + std::chrono::hours(config.validity_days * 24);
    result->is_ca = config.is_ca;
    result->sans = config.sans;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio) {
        X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result->subject = std::string(data, len);
        BIO_free(bio);
    }

    bio = BIO_new(BIO_s_mem());
    if (bio) {
        X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, XN_FLAG_RFC2253);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        result->issuer = std::string(data, len);
        BIO_free(bio);
    }

    return result;
}

std::unique_ptr<Certificate> KeyManager::load_certificate(const std::string& cert_id) {
    std::string cert_file = m_cert_store_path + "/" + cert_id + ".crt";
    std::ifstream in(cert_file, std::ios::binary);
    if (!in) return nullptr;

    std::stringstream buffer;
    buffer << in.rdbuf();
    std::string pem = buffer.str();

    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
    if (!bio) return nullptr;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return nullptr;

    auto result = std::make_unique<Certificate>();
    result->key_id = cert_id;
    result->certificate = UniqueX509(cert, X509Deleter());
    result->is_ca = false;
    return result;
}

bool KeyManager::store_certificate(const Certificate& cert) {
    if (m_cert_store_path.empty()) return false;

    std::string cert_file = m_cert_store_path + "/" + cert.key_id + ".crt";
    std::ofstream out(cert_file, std::ios::binary);
    if (!out) return false;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;

    PEM_write_bio_X509(bio, cert.certificate.get());
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    out.write(data, len);
    BIO_free(bio);
    out.close();

    return true;
}

bool KeyManager::delete_certificate(const std::string& cert_id) {
    if (m_cert_store_path.empty()) return false;
    return std::remove((m_cert_store_path + "/" + cert_id + ".crt").c_str()) == 0;
}

SoftHSMBackend::SoftHSMBackend(const std::string& slot) : m_slot(slot) {
    if (!m_slot.empty() && !path_exists(m_slot)) {
        create_directory(m_slot);
    }
}

bool SoftHSMBackend::is_available() const {
    return true;
}

bool SoftHSMBackend::generate_key(KeyType type, const std::string& key_id, UniquePKEY& pub_key, UniquePKEY& priv_key) {
    switch (type) {
        case KeyType::Ed25519: {
            priv_key = IdentityCore::generate_ed25519_key();
            if (!priv_key) return false;
            pub_key.reset(EVP_PKEY_dup(priv_key.get()));
            break;
        }
        case KeyType::RSA: {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!pctx) return false;
            if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return false;
            }
            EVP_PKEY* key = nullptr;
            if (EVP_PKEY_keygen(pctx, &key) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return false;
            }
            EVP_PKEY_CTX_free(pctx);
            priv_key.reset(key);
            pub_key.reset(EVP_PKEY_dup(key));
            break;
        }
        case KeyType::Ed448: {
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, nullptr);
            if (!pctx) return false;
            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return false;
            }
            EVP_PKEY* key = nullptr;
            if (EVP_PKEY_keygen(pctx, &key) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                return false;
            }
            EVP_PKEY_CTX_free(pctx);
            priv_key.reset(key);
            pub_key.reset(EVP_PKEY_dup(key));
            break;
        }
        default:
            return false;
    }

    if (!m_slot.empty() && priv_key) {
        std::string path = m_slot + "/" + key_id + ".pem";
        std::ofstream out(path, std::ios::binary);
        if (out) {
            BIO* bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PrivateKey(bio, priv_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
            char* data = nullptr;
            long len = BIO_get_mem_data(bio, &data);
            out.write(data, len);
            BIO_free(bio);
        }
    }

    return pub_key != nullptr && priv_key != nullptr;
}

bool SoftHSMBackend::sign_data(const std::string& key_id, const std::string& data, std::string& signature) {
    EVP_PKEY* key = nullptr;

    if (!m_slot.empty()) {
        std::string path = m_slot + "/" + key_id + ".pem";
        std::ifstream in(path, std::ios::binary);
        if (in) {
            std::stringstream buffer;
            buffer << in.rdbuf();
            std::string pem = buffer.str();
            BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
            key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
        }
    }

    if (!key) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(key); return false; }

    bool ok = false;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) == 1) {
        size_t sig_len = 0;
        if (EVP_DigestSign(ctx, nullptr, &sig_len, (const unsigned char*)data.data(), data.size()) == 1) {
            signature.resize(sig_len);
            if (EVP_DigestSign(ctx, (unsigned char*)signature.data(), &sig_len,
                               (const unsigned char*)data.data(), data.size()) == 1) {
                signature.resize(sig_len);
                ok = true;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

bool SoftHSMBackend::verify_signature(const std::string& key_id, const std::string& data, const std::string& signature) {
    EVP_PKEY* key = nullptr;

    if (!m_slot.empty()) {
        std::string path = m_slot + "/" + key_id + ".pem";
        std::ifstream in(path, std::ios::binary);
        if (in) {
            std::stringstream buffer;
            buffer << in.rdbuf();
            std::string pem = buffer.str();
            BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
            key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
        }
    }

    if (!key) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(key); return false; }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1) {
        ok = EVP_DigestVerify(ctx, (const unsigned char*)signature.data(), signature.size(),
                              (const unsigned char*)data.data(), data.size()) == 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

namespace {

struct TPM2Header {
    uint16_t tag;
    uint32_t size;
    uint32_t code;
} __attribute__((packed));

int tpm2_send_command(int fd, const std::vector<uint8_t>& cmd, std::vector<uint8_t>& resp) {
    if (write(fd, cmd.data(), cmd.size()) != static_cast<ssize_t>(cmd.size())) return -1;
    resp.resize(4096);
    ssize_t n = read(fd, resp.data(), resp.size());
    if (n < static_cast<ssize_t>(sizeof(TPM2Header))) return -1;
    resp.resize(n);
    return 0;
}

bool tpm2_get_capability(int fd) {
    std::vector<uint8_t> cmd = {
        0x80, 0x01,             // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x16, // command size = 22
        0x00, 0x00, 0x01, 0x7A, // TPM2_CC_GetCapability
        0x00, 0x00, 0x00, 0x06, // TPM_CAP_TPM_PROPERTIES
        0x00, 0x00, 0x01, 0x00, // TPM_PT_MANUFACTURER
        0x00, 0x00, 0x00, 0x01  // property count = 1
    };
    std::vector<uint8_t> resp;
    return tpm2_send_command(fd, cmd, resp) == 0 &&
           be32toh(reinterpret_cast<TPM2Header*>(resp.data())->code) == 0;
}

} // namespace

TPM2Backend::TPM2Backend(const std::string& device) : m_device(device), m_tpm_fd(-1) {}

bool TPM2Backend::is_available() const {
    if (m_device.empty()) return false;
    int fd = open(m_device.c_str(), O_RDWR);
    if (fd < 0) return false;
    bool ok = tpm2_get_capability(fd);
    close(fd);
    return ok;
}

TPM2Backend::~TPM2Backend() {
    if (m_tpm_fd >= 0) close(m_tpm_fd);
}

bool TPM2Backend::generate_key(KeyType, const std::string&, UniquePKEY&, UniquePKEY&) {
    if (!is_available()) return false;
    return false;
}

bool TPM2Backend::sign_data(const std::string&, const std::string&, std::string&) {
    if (!is_available()) return false;
    return false;
}

bool TPM2Backend::verify_signature(const std::string&, const std::string&, const std::string&) {
    if (!is_available()) return false;
    return false;
}

namespace {

// PKCS#11 v2.40 minimal types for dlopen-based HSM access
using CK_BYTE = unsigned char;
using CK_ULONG = unsigned long;
using CK_BBOOL = CK_BYTE;
using CK_SLOT_ID = CK_ULONG;
using CK_SESSION_HANDLE = CK_ULONG;
using CK_OBJECT_HANDLE = CK_ULONG;
using CK_MECHANISM_TYPE = CK_ULONG;
using CK_ATTRIBUTE_TYPE = CK_ULONG;
using CK_RV = CK_ULONG;
using CK_FLAGS = CK_ULONG;
using CK_USER_TYPE = CK_ULONG;

constexpr CK_RV CKR_OK = 0x00000000;
constexpr CK_BBOOL CK_FALSE = 0;
constexpr CK_FLAGS CKF_SERIAL_SESSION = 0x00000004;
constexpr CK_FLAGS CKF_RW_SESSION = 0x00000002;
constexpr CK_USER_TYPE CKU_USER = 1;
constexpr CK_MECHANISM_TYPE CKM_ECDSA = 0x00001041;
constexpr CK_MECHANISM_TYPE CKM_EDDSA = 0x00001057;
constexpr CK_MECHANISM_TYPE CKM_RSA_PKCS = 0x00000001;
constexpr CK_MECHANISM_TYPE CKM_SHA256_RSA_PKCS = 0x00000040;

struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void* pParameter;
    CK_ULONG ulParameterLen;
};

struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void* pValue;
    CK_ULONG ulValueLen;
};

struct CK_FUNCTION_LIST {
    CK_RV (*C_Initialize)(void*);
    CK_RV (*C_Finalize)(void*);
    CK_RV (*C_GetInfo)(void*);
    CK_RV (*C_GetSlotList)(CK_BBOOL, CK_SLOT_ID*, CK_ULONG*);
    CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, void*);
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_BYTE*, CK_ULONG);
    CK_RV (*C_Logout)(CK_SESSION_HANDLE);
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG,
                                CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG*);
    CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE*, CK_ULONG, CK_BYTE*, CK_ULONG);
    CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
};

} // namespace

PKCS11Backend::PKCS11Backend(const std::string& module, const std::string& pin)
    : m_module(module), m_pin(pin), m_lib(nullptr), m_ctx(nullptr) {}

PKCS11Backend::~PKCS11Backend() {
    if (m_ctx && m_lib) {
        auto* fns = static_cast<CK_FUNCTION_LIST*>(m_ctx);
        fns->C_Finalize(nullptr);
    }
    if (m_lib) dlclose(m_lib);
}

bool PKCS11Backend::is_available() const {
    if (m_module.empty()) return false;
    if (access(m_module.c_str(), R_OK) != 0) return false;
    void* lib = dlopen(m_module.c_str(), RTLD_NOW);
    if (!lib) return false;
    using GetFnList = CK_RV (*)(CK_FUNCTION_LIST**);
    auto get_fn_list = reinterpret_cast<GetFnList>(dlsym(lib, "C_GetFunctionList"));
    if (!get_fn_list) { dlclose(lib); return false; }
    CK_FUNCTION_LIST* fns = nullptr;
    if (get_fn_list(&fns) != CKR_OK || !fns) { dlclose(lib); return false; }
    if (fns->C_Initialize(nullptr) != CKR_OK) { dlclose(lib); return false; }
    CK_ULONG slot_count = 0;
    if (fns->C_GetSlotList(CK_FALSE, nullptr, &slot_count) != CKR_OK || slot_count == 0) {
        fns->C_Finalize(nullptr);
        dlclose(lib);
        return false;
    }
    fns->C_Finalize(nullptr);
    dlclose(lib);
    return true;
}

bool PKCS11Backend::generate_key(KeyType, const std::string&, UniquePKEY&, UniquePKEY&) {
    return false;
}

bool PKCS11Backend::sign_data(const std::string&, const std::string&, std::string&) {
    return false;
}

bool PKCS11Backend::verify_signature(const std::string&, const std::string&, const std::string&) {
    return false;
}

} // namespace neuro_mesh::crypto