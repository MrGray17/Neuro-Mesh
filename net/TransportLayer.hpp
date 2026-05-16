#pragma once
#include <string>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <optional>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace neuro_mesh::net {

struct SSLCTXDeleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct SSLDeleter {
    void operator()(SSL* ssl) const {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
};

struct TLSConfig {
    std::string cert_path;
    std::string key_path;
    std::string ca_path;
    bool verify_client = false;
    std::string ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS";
    bool enable_tls13 = true;
    bool enable_mtls = false;
};

struct MTLSConfig {
    bool require_client_cert = true;
    std::unordered_set<std::string> allowed_client_cns;
    std::string crl_path;
    bool check_cert_validity = true;
    uint32_t max_cert_age_days = 365;
    bool verify_hostname = true;
};

struct PeerInfo {
    std::string node_id;
    std::string ip;
    uint16_t port;
    std::string public_key_pem;
    std::chrono::steady_clock::time_point last_seen;
    bool is_verified = false;
    uint32_t connection_count = 0;
};

struct DiscoveryConfig {
    uint16_t beacon_port = 9998;
    uint16_t beacon_interval_ms = 5000;
    uint16_t peer_timeout_ms = 15000;
    bool enable_tcp_discovery = true;
    uint16_t tcp_discovery_port = 9999;
    bool enable_multicast = false;
    std::string multicast_group = "239.255.255.250";
};

struct ConnectionInfo {
    std::string peer_ip;
    uint16_t peer_port;
    std::string subject_cn;
    bool verified = false;
};

class TLSContext {
public:
    explicit TLSContext(const TLSConfig& config);
    ~TLSContext();

    SSL* create_server_ssl();
    SSL* create_client_ssl();
    bool load_certificate();
    bool load_ca_certificate();

    SSL_CTX* server_context() const { return m_server_ctx.get(); }
    SSL_CTX* client_context() const { return m_client_ctx.get(); }

private:
    TLSConfig m_config;
    std::unique_ptr<SSL_CTX, SSLCTXDeleter> m_server_ctx;
    std::unique_ptr<SSL_CTX, SSLCTXDeleter> m_client_ctx;
};

class MTLSAuth {
public:
    explicit MTLSAuth(const MTLSConfig& config);
    ~MTLSAuth();

    bool initialize_server_context(SSL_CTX* ctx);
    bool initialize_client_context(SSL_CTX* ctx);
    bool verify_client_certificate(SSL* ssl);
    bool load_crl(const std::string& crl_path);

    bool is_cert_revoked(const std::string& serial) const;
    bool is_client_allowed(const std::string& cn) const;

    std::string get_client_cert_cn(SSL* ssl) const;
    std::string get_peer_cert_fingerprint(SSL* ssl) const;

private:
    MTLSConfig m_config;
    std::unordered_set<std::string> m_revoked_serials;
    mutable std::mutex m_mutex;
};

class PeerDiscovery {
public:
    explicit PeerDiscovery(const DiscoveryConfig& config, const std::string& node_id, const std::string& public_key);
    ~PeerDiscovery();

    bool start();
    void stop();

    std::vector<PeerInfo> get_active_peers();
    std::optional<PeerInfo> get_peer(const std::string& node_id);

    bool announce_peer(const PeerInfo& peer);
    bool verify_peer(const std::string& node_id, const std::string& public_key_pem);

    void set_on_peer_discovered(std::function<void(const PeerInfo&)> cb);
    void set_on_peer_lost(std::function<void(const std::string&)> cb);

private:
    void beacon_loop();
    void cleanup_stale_peers();
    bool send_beacon(const std::string& host, uint16_t port);
    bool handle_incoming_beacon(const char* data, size_t len, const sockaddr_in& src);

    DiscoveryConfig m_config;
    std::string m_node_id;
    std::string m_public_key;
    int m_beacon_sock = -1;
    std::atomic<bool> m_running{false};
    std::thread m_beacon_thread;
    std::mutex m_peers_mutex;
    std::unordered_map<std::string, PeerInfo> m_peers;

    std::function<void(const PeerInfo&)> m_on_peer_discovered;
    std::function<void(const std::string&)> m_on_peer_lost;
};

class TransportLayer {
public:
    explicit TransportLayer(const TLSConfig& config);
    ~TransportLayer();

    bool bind(const std::string& address, uint16_t port);
    bool listen(int backlog = 128);
    int accept();

    int connect(const std::string& host, uint16_t port);
    ssize_t send(int fd, const void* buf, size_t len);
    ssize_t recv(int fd, void* buf, size_t len);

    void close(int fd);
    void shutdown();

    std::optional<ConnectionInfo> get_connection_info(int fd) const;

    int server_socket() const { return m_server_fd; }

private:
    TLSContext m_tls_ctx;
    int m_server_fd = -1;
    std::unordered_map<int, std::unique_ptr<SSL, SSLDeleter>> m_active_ssl;
    bool m_running = false;

    bool initialize_openssl();
};

} // namespace neuro_mesh::net