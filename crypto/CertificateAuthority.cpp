#include "crypto/CertificateAuthority.hpp"
#include <fstream>
#include <sstream>
#include <mutex>
#include <map>
#include <iostream>

namespace neuro_mesh::crypto {

class CertificateAuthority::Impl {
public:
    std::map<std::string, RevocationEntry> m_revoked_certs;
    mutable std::mutex m_revocation_mtx;

    X509* m_ca_cert = nullptr;
    EVP_PKEY* m_ca_key = nullptr;
    std::string m_ca_cert_pem;
    std::string m_ca_key_pem;
};

CertificateAuthority::CertificateAuthority(const std::string& ca_name)
    : m_impl(std::make_unique<Impl>())
    , m_ca_name(ca_name) {
}

CertificateAuthority::~CertificateAuthority() = default;

bool CertificateAuthority::initialize_root_ca(const std::string& key_pem, const std::string& cert_pem) {
    m_impl->m_ca_key_pem = key_pem;
    m_impl->m_ca_cert_pem = cert_pem;

    BIO* cert_bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!cert_bio) return false;
    m_impl->m_ca_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), key_pem.size());
    if (!key_bio) return false;
    m_impl->m_ca_key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);

    return m_impl->m_ca_cert != nullptr && m_impl->m_ca_key != nullptr;
}

bool CertificateAuthority::load_intermediate_ca(const std::string& key_pem, const std::string& cert_pem, const std::string& root_cert_pem) {
    (void)root_cert_pem;
    m_impl->m_ca_key_pem = key_pem;
    m_impl->m_ca_cert_pem = cert_pem;

    BIO* cert_bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!cert_bio) return false;
    m_impl->m_ca_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);

    BIO* key_bio = BIO_new_mem_buf(key_pem.data(), key_pem.size());
    if (!key_bio) return false;
    m_impl->m_ca_key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);

    return m_impl->m_ca_cert != nullptr && m_impl->m_ca_key != nullptr;
}

std::optional<std::string> CertificateAuthority::create_root_ca(const std::string& common_name, int validity_days) {
    (void)common_name;
    (void)validity_days;
    return std::nullopt;
}

std::optional<std::string> CertificateAuthority::create_intermediate_ca(const std::string& common_name, int validity_days) {
    (void)common_name;
    (void)validity_days;
    return std::nullopt;
}

std::optional<std::string> CertificateAuthority::sign_csr(const std::string& csr_pem, const std::string& subject,
                                                          const std::vector<std::string>& san, int validity_days) {
    (void)csr_pem;
    (void)subject;
    (void)san;
    (void)validity_days;
    return std::nullopt;
}

std::optional<std::string> CertificateAuthority::create_node_certificate(const std::string& node_id,
                                                                         const std::vector<std::string>& san,
                                                                         int validity_days) {
    (void)node_id;
    (void)san;
    (void)validity_days;
    return std::nullopt;
}

std::optional<std::string> CertificateAuthority::create_tls_certificate(const std::string& common_name,
                                                                        const std::vector<std::string>& san,
                                                                        int validity_days) {
    (void)common_name;
    (void)san;
    (void)validity_days;
    return std::nullopt;
}

bool CertificateAuthority::revoke_certificate(const std::string& serial_number, const std::string& reason) {
    std::lock_guard<std::mutex> lock(m_impl->m_revocation_mtx);

    RevocationEntry entry;
    entry.serial_number = serial_number;
    entry.revoked_at = std::chrono::system_clock::now();
    entry.reason = reason;
    entry.revoked_by = m_ca_name;

    m_impl->m_revoked_certs[serial_number] = entry;
    std::cout << "[CA] Certificate revoked: " << serial_number
              << " (reason: " << reason << ")" << std::endl;
    return true;
}

bool CertificateAuthority::is_revoked(const std::string& serial_number) const {
    std::lock_guard<std::mutex> lock(m_impl->m_revocation_mtx);
    return m_impl->m_revoked_certs.count(serial_number) > 0;
}

std::optional<std::string> CertificateAuthority::get_crl() {
    if (!m_impl->m_ca_cert || !m_impl->m_ca_key) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(m_impl->m_revocation_mtx);

    X509_CRL* crl = X509_CRL_new();
    if (!crl) return std::nullopt;

    X509_CRL_set_version(crl, 1);
    X509_CRL_set_issuer_name(crl, X509_get_issuer_name(m_impl->m_ca_cert));

    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    ASN1_TIME* now_asn1 = ASN1_TIME_new();
    ASN1_TIME_set(now_asn1, now_time_t);
    X509_CRL_set_lastUpdate(crl, now_asn1);

    ASN1_TIME* next_asn1 = ASN1_TIME_new();
    auto next_time = now + std::chrono::hours(24);
    auto next_time_t = std::chrono::system_clock::to_time_t(next_time);
    ASN1_TIME_set(next_asn1, next_time_t);
    X509_CRL_set_nextUpdate(crl, next_asn1);

    for (const auto& [serial, entry] : m_impl->m_revoked_certs) {
        X509_REVOKED* revoked = X509_REVOKED_new();
        ASN1_INTEGER* asn1_serial = ASN1_INTEGER_new();

        char* endptr;
        long serial_val = std::strtol(serial.c_str(), &endptr, 16);
        ASN1_INTEGER_set(asn1_serial, serial_val);
        X509_REVOKED_set_serialNumber(revoked, asn1_serial);

        auto rev_time_t = std::chrono::system_clock::to_time_t(entry.revoked_at);
        ASN1_TIME* rev_time = ASN1_TIME_new();
        ASN1_TIME_set(rev_time, rev_time_t);
        X509_REVOKED_set_revocationDate(revoked, rev_time);
        ASN1_TIME_free(rev_time);

        X509_CRL_add0_revoked(crl, revoked);
        ASN1_INTEGER_free(asn1_serial);
    }

    X509_CRL_sign(crl, m_impl->m_ca_key, EVP_sha256());

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_CRL(bio, crl);

    char* buf;
    long len = BIO_get_mem_data(bio, &buf);
    std::string crl_pem(buf, len);

    BIO_free(bio);
    X509_CRL_free(crl);
    ASN1_TIME_free(now_asn1);
    ASN1_TIME_free(next_asn1);

    return crl_pem;
}

bool CertificateAuthority::verify_certificate(const std::string& cert_pem, const std::string& chain_pem) const {
    (void)cert_pem;
    (void)chain_pem;
    return false;
}

bool CertificateAuthority::verify_chain(const std::vector<std::string>& cert_chain) const {
    (void)cert_chain;
    return false;
}

std::vector<std::string> CertificateAuthority::list_revoked_serials() const {
    std::lock_guard<std::mutex> lock(m_impl->m_revocation_mtx);
    std::vector<std::string> result;
    for (const auto& [serial, _] : m_impl->m_revoked_certs) {
        result.push_back(serial);
    }
    return result;
}

std::optional<std::string> CertificateAuthority::generate_csr(const std::string& common_name,
                                                              const std::string& private_key_pem,
                                                              const std::vector<std::string>& san) {
    (void)common_name;
    (void)private_key_pem;
    (void)san;
    return std::nullopt;
}

std::optional<std::string> CertificateAuthority::generate_key(KeyType type) {
    (void)type;
    return std::nullopt;
}

std::string CertificateAuthority::get_cert_serial(const std::string& cert_pem) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!bio) return "";

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return "";

    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string result = hex ? hex : "";

    BN_free(bn);
    OPENSSL_free(hex);
    X509_free(cert);

    return result;
}

std::string CertificateAuthority::get_cert_subject(const std::string& cert_pem) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!bio) return "";

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return "";

    X509_NAME* subject = X509_get_subject_name(cert);
    char* buf = X509_NAME_oneline(subject, nullptr, 0);
    std::string result = buf ? buf : "";
    OPENSSL_free(buf);
    X509_free(cert);

    return result;
}

std::chrono::system_clock::time_point CertificateAuthority::get_cert_not_before(const std::string& cert_pem) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!bio) return std::chrono::system_clock::time_point{};

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return std::chrono::system_clock::time_point{};

    ASN1_TIME* not_before = X509_get_notBefore(cert);
    struct tm tm_val{};
    ASN1_TIME_to_tm(not_before, &tm_val);
    X509_free(cert);

    return std::chrono::system_clock::from_time_t(std::mktime(&tm_val));
}

std::chrono::system_clock::time_point CertificateAuthority::get_cert_not_after(const std::string& cert_pem) {
    BIO* bio = BIO_new_mem_buf(cert_pem.data(), cert_pem.size());
    if (!bio) return std::chrono::system_clock::time_point{};

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) return std::chrono::system_clock::time_point{};

    ASN1_TIME* not_after = X509_get_notAfter(cert);
    struct tm tm_val{};
    ASN1_TIME_to_tm(not_after, &tm_val);
    X509_free(cert);

    return std::chrono::system_clock::from_time_t(std::mktime(&tm_val));
}

// =============================================================================
// CertificateChainValidator
// =============================================================================

CertificateChainValidator::CertificateChainValidator() = default;
CertificateChainValidator::~CertificateChainValidator() = default;

bool CertificateChainValidator::add_trusted_ca(const std::string& ca_cert_pem) {
    m_trusted_cas.push_back(ca_cert_pem);
    return true;
}

bool CertificateChainValidator::remove_trusted_ca(const std::string& ca_subject) {
    (void)ca_subject;
    return false;
}

bool CertificateChainValidator::validate_certificate(const std::string& cert_pem) const {
    (void)cert_pem;
    return false;
}

bool CertificateChainValidator::validate_chain(const std::vector<std::string>& cert_chain) const {
    (void)cert_chain;
    return false;
}

bool CertificateChainValidator::check_revocation(const std::string& cert_pem) const {
    if (!m_check_revocation) return true;
    std::string serial = CertificateAuthority::get_cert_serial(cert_pem);
    return !serial.empty();
}

bool CertificateChainValidator::check_expiration(const std::string& cert_pem) const {
    if (!m_check_expiration) return true;
    auto not_after = CertificateAuthority::get_cert_not_after(cert_pem);
    return not_after > std::chrono::system_clock::now();
}

bool CertificateChainValidator::verify_hostname(const std::string& cert_pem, const std::string& hostname) const {
    (void)cert_pem;
    (void)hostname;
    return false;
}

// =============================================================================
// CertificateStore
// =============================================================================

CertificateStore::CertificateStore(const std::string& storage_path)
    : m_storage_path(storage_path) {
}

CertificateStore::~CertificateStore() = default;

bool CertificateStore::store_certificate(const std::string& node_id, const std::string& cert_pem) {
    (void)node_id;
    (void)cert_pem;
    return false;
}

std::optional<std::string> CertificateStore::get_certificate(const std::string& node_id) const {
    (void)node_id;
    return std::nullopt;
}

bool CertificateStore::store_key(const std::string& node_id, const std::string& key_pem) {
    (void)node_id;
    (void)key_pem;
    return false;
}

std::optional<std::string> CertificateStore::get_key(const std::string& node_id) const {
    (void)node_id;
    return std::nullopt;
}

bool CertificateStore::store_crl(const std::string& crl_pem) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream out(crl_path(), std::ios::binary);
    if (!out) return false;
    out << crl_pem;
    return out.good();
}

std::optional<std::string> CertificateStore::get_crl() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ifstream in(crl_path(), std::ios::binary);
    if (!in) return std::nullopt;
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

bool CertificateStore::delete_certificate(const std::string& node_id) {
    (void)node_id;
    return false;
}

bool CertificateStore::delete_key(const std::string& node_id) {
    (void)node_id;
    return false;
}

std::vector<std::string> CertificateStore::list_certificates() const {
    return {};
}

bool CertificateStore::rotate_certificate(const std::string& node_id, const std::string& new_cert_pem, const std::string& new_key_pem) {
    (void)node_id;
    (void)new_cert_pem;
    (void)new_key_pem;
    return false;
}

bool CertificateStore::is_expired(const std::string& node_id) const {
    (void)node_id;
    return false;
}

bool CertificateStore::needs_rotation(const std::string& node_id) const {
    (void)node_id;
    return false;
}

std::string CertificateStore::cert_path(const std::string& node_id) const {
    return m_storage_path + "/" + node_id + ".pem";
}

std::string CertificateStore::key_path(const std::string& node_id) const {
    return m_storage_path + "/" + node_id + ".key";
}

std::string CertificateStore::crl_path() const {
    return m_storage_path + "/crl.pem";
}

} // namespace neuro_mesh::crypto
