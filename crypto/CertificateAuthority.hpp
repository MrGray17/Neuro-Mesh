#pragma once
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <functional>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>

namespace neuro_mesh::crypto {

enum class CertificateType {
    ROOT_CA,
    INTERMEDIATE_CA,
    NODE_CERTIFICATE,
    TLS_CERTIFICATE
};

struct CertificateChain {
    std::vector<std::string> certificates;
    std::string root_cert_pem;
    std::string intermediate_cert_pem;
    std::string leaf_cert_pem;
};

struct CertificateRequest {
    std::string subject;
    std::vector<std::string> san;
    KeyType key_type;
    CertificateType cert_type;
    std::string csr_pem;
};

struct RevocationEntry {
    std::string serial_number;
    std::chrono::system_clock::time_point revoked_at;
    std::string reason;
    std::string revoked_by;
};

class CertificateAuthority {
public:
    explicit CertificateAuthority(const std::string& ca_name);
    ~CertificateAuthority();

    bool initialize_root_ca(const std::string& key_pem, const std::string& cert_pem);
    bool load_intermediate_ca(const std::string& key_pem, const std::string& cert_pem, const std::string& root_cert_pem);

    std::optional<std::string> create_root_ca(const std::string& common_name, int validity_days = 3650);
    std::optional<std::string> create_intermediate_ca(const std::string& common_name, int validity_days = 1825);

    std::optional<std::string> sign_csr(const std::string& csr_pem, const std::string& subject,
                                        const std::vector<std::string>& san, int validity_days = 365);

    std::optional<std::string> create_node_certificate(const std::string& node_id,
                                                         const std::vector<std::string>& san,
                                                         int validity_days = 7);

    std::optional<std::string> create_tls_certificate(const std::string& common_name,
                                                       const std::vector<std::string>& san,
                                                       int validity_days = 1);

    bool revoke_certificate(const std::string& serial_number, const std::string& reason = "Unspecified");
    bool is_revoked(const std::string& serial_number) const;
    std::optional<std::string> get_crl();

    bool verify_certificate(const std::string& cert_pem, const std::string& chain_pem = "") const;
    bool verify_chain(const std::vector<std::string>& cert_chain) const;

    std::string get_ca_certificate() const { return m_ca_cert_pem; }
    std::string get_ca_name() const { return m_ca_name; }

    std::vector<std::string> list_revoked_serials() const;

    static std::optional<std::string> generate_csr(const std::string& common_name,
                                                   const std::string& private_key_pem,
                                                   const std::vector<std::string>& san = {});

    static std::optional<std::string> generate_key(KeyType type);
    static std::string get_cert_serial(const std::string& cert_pem);
    static std::string get_cert_subject(const std::string& cert_pem);
    static std::chrono::system_clock::time_point get_cert_not_before(const std::string& cert_pem);
    static std::chrono::system_clock::time_point get_cert_not_after(const std::string& cert_pem);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    std::string m_ca_name;
    std::string m_ca_cert_pem;
};

class CertificateChainValidator {
public:
    CertificateChainValidator();
    ~CertificateChainValidator();

    bool add_trusted_ca(const std::string& ca_cert_pem);
    bool remove_trusted_ca(const std::string& ca_subject);

    bool validate_certificate(const std::string& cert_pem) const;
    bool validate_chain(const std::vector<std::string>& cert_chain) const;

    bool check_revocation(const std::string& cert_pem) const;
    bool check_expiration(const std::string& cert_pem) const;

    std::string get_validation_error() const { return m_last_error; }

    void set_revocation_check(bool enable) { m_check_revocation = enable; }
    void set_expiration_check(bool enable) { m_check_expiration = enable; }
    void set_hostname_check(bool enable) { m_check_hostname = enable; }
    bool verify_hostname(const std::string& cert_pem, const std::string& hostname) const;

private:
    std::vector<std::string> m_trusted_cas;
    mutable std::string m_last_error;
    bool m_check_revocation = true;
    bool m_check_expiration = true;
    bool m_check_hostname = true;
};

class CertificateStore {
public:
    CertificateStore(const std::string& storage_path);
    ~CertificateStore();

    bool store_certificate(const std::string& node_id, const std::string& cert_pem);
    std::optional<std::string> get_certificate(const std::string& node_id) const;

    bool store_key(const std::string& node_id, const std::string& key_pem);
    std::optional<std::string> get_key(const std::string& node_id) const;

    bool store_crl(const std::string& crl_pem);
    std::optional<std::string> get_crl() const;

    bool delete_certificate(const std::string& node_id);
    bool delete_key(const std::string& node_id);

    std::vector<std::string> list_certificates() const;
    bool rotate_certificate(const std::string& node_id, const std::string& new_cert_pem, const std::string& new_key_pem);

    bool is_expired(const std::string& node_id) const;
    bool needs_rotation(const std::string& node_id) const;

private:
    std::string m_storage_path;
    mutable std::mutex m_mutex;

    std::string cert_path(const std::string& node_id) const;
    std::string key_path(const std::string& node_id) const;
    std::string crl_path() const;
};

} // namespace neuro_mesh::crypto