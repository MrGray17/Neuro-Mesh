#include "net/TransportLayer.hpp"
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <chrono>
#include <thread>
#include <algorithm>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/tls1.h>
#include <openssl/obj_mac.h>

namespace neuro_mesh::net {

namespace {

} // namespace

TLSContext::TLSContext(const TLSConfig& config)
    : m_config(config)
    , m_server_ctx(nullptr, SSLCTXDeleter())
    , m_client_ctx(nullptr, SSLCTXDeleter()) {

    SSL_CTX* server = SSL_CTX_new(TLS_server_method());
    SSL_CTX* client = SSL_CTX_new(TLS_client_method());

    if (!server || !client) {
        if (server) SSL_CTX_free(server);
        if (client) SSL_CTX_free(client);
        std::string err_detail;
        BIO* bio = BIO_new(BIO_s_mem());
        if (bio) {
            ERR_print_errors(bio);
            char* data = nullptr;
            long len = BIO_get_mem_data(bio, &data);
            if (len > 0 && data) err_detail.assign(data, len);
            BIO_free(bio);
        }
        throw std::runtime_error("Failed to create SSL contexts: " + err_detail);
    }

    m_server_ctx.reset(server);
    m_client_ctx.reset(client);

    if (m_config.enable_tls13) {
        SSL_CTX_set_min_proto_version(m_server_ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_min_proto_version(m_client_ctx.get(), TLS1_3_VERSION);
        SSL_CTX_set_ciphersuites(m_server_ctx.get(), "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
        SSL_CTX_set_ciphersuites(m_client_ctx.get(), "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    }

    SSL_CTX_set_cipher_list(m_server_ctx.get(), m_config.ciphers.c_str());
    SSL_CTX_set_cipher_list(m_client_ctx.get(), m_config.ciphers.c_str());

    SSL_CTX_set_security_level(m_server_ctx.get(), 2);
    SSL_CTX_set_security_level(m_client_ctx.get(), 2);

    // A mesh node acts as both TLS server and TLS client. Both contexts must
    // carry the same node certificate/key or mutual TLS cannot work outbound.
    if (!m_config.cert_path.empty() && !m_config.key_path.empty()) {
        if (!load_certificate()) {
            throw std::runtime_error("Failed to load TLS certificate/key into both contexts");
        }
    }

    // Load CA and set up mutual TLS if configured. Configuration failure is
    // fatal: silently continuing would create a transport with weaker trust.
    if (!m_config.ca_path.empty()) {
        if (!load_ca_certificate()) {
            throw std::runtime_error("Failed to load TLS CA/verification configuration");
        }
    }
}

TLSContext::~TLSContext() = default;

bool TLSContext::load_certificate() {
    if (m_config.cert_path.empty() || m_config.key_path.empty()) {
        return false;
    }

    auto load_into = [&](SSL_CTX* ctx) -> bool {
        if (SSL_CTX_use_certificate_file(ctx, m_config.cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, m_config.key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        return true;
    };

    return load_into(m_server_ctx.get()) && load_into(m_client_ctx.get());
}

bool TLSContext::load_ca_certificate() {
    if (m_config.ca_path.empty()) {
        return false;
    }

    // Load CA into both contexts
    if (SSL_CTX_load_verify_locations(m_server_ctx.get(), m_config.ca_path.c_str(), nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (SSL_CTX_load_verify_locations(m_client_ctx.get(), m_config.ca_path.c_str(), nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Enable mutual TLS on the server side when configured.
    if (m_config.verify_client || m_config.enable_mtls) {
        SSL_CTX_set_verify(m_server_ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        SSL_CTX_set_client_CA_list(m_server_ctx.get(), SSL_load_client_CA_file(m_config.ca_path.c_str()));
    }

    // Always verify server cert on client side when CA is available.
    SSL_CTX_set_verify(m_client_ctx.get(), SSL_VERIFY_PEER, nullptr);

    return true;
}

bool TLSContext::trust_peer_cert(const std::string& pem_cert) {
    // Load the peer's self-signed cert into the extra cert store of both
    // server and client contexts. This allows OpenSSL to verify the peer's
    // cert during mTLS handshakes even when it's self-signed.
    BIO* bio = BIO_new_mem_buf(pem_cert.data(), static_cast<int>(pem_cert.size()));
    if (!bio) return false;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return false;

    bool ok = true;

    // Add to server context's cert store (for verifying incoming clients).
    X509_STORE* server_store = SSL_CTX_get_cert_store(m_server_ctx.get());
    if (!server_store || X509_STORE_add_cert(server_store, cert) != 1) {
        // Duplicate certificates are benign; clear that error so callers do
        // not treat repeated discovery beacons as trust failures.
        unsigned long err = ERR_peek_last_error();
        if (err != 0 && ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            ERR_clear_error();
        } else {
            ok = false;
        }
    }

    // Add to client context's cert store (for verifying remote servers).
    X509_STORE* client_store = SSL_CTX_get_cert_store(m_client_ctx.get());
    if (!client_store || X509_STORE_add_cert(client_store, cert) != 1) {
        unsigned long err = ERR_peek_last_error();
        if (err != 0 && ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            ERR_clear_error();
        } else {
            ok = false;
        }
    }

    X509_free(cert);
    return ok;
}

SSL* TLSContext::create_server_ssl() {
    return SSL_new(m_server_ctx.get());
}

SSL* TLSContext::create_client_ssl() {
    return SSL_new(m_client_ctx.get());
}

TransportLayer::TransportLayer(const TLSConfig& config)
    : m_tls_ctx(config)
    , m_running(false) {

    if (!initialize_openssl()) {
        throw std::runtime_error("Failed to initialize OpenSSL");
    }
}

TransportLayer::~TransportLayer() {
    shutdown();
}

bool TransportLayer::initialize_openssl() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    return true;
}

bool TransportLayer::bind(const std::string& address, uint16_t port) {
    m_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_server_fd < 0) {
        return false;
    }

    int opt = 1;
    if (setsockopt(m_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(m_server_fd);
        m_server_fd = -1;
        return false;
    }

    // Non-blocking server socket so accept4() returns -1/EAGAIN immediately
    // when no connections are pending (required for clean shutdown).
    int fl = fcntl(m_server_fd, F_GETFL, 0);
    if (fl < 0 || fcntl(m_server_fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(m_server_fd);
        m_server_fd = -1;
        return false;
    }

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (address.empty() || address == "0.0.0.0" || address == "::") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        close(m_server_fd);
        m_server_fd = -1;
        return false;
    }

    if (::bind(m_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(m_server_fd);
        m_server_fd = -1;
        return false;
    }

    m_running = true;
    return true;
}

bool TransportLayer::listen(int backlog) {
    if (m_server_fd < 0) return false;
    return ::listen(m_server_fd, backlog) == 0;
}

int TransportLayer::accept() {
    if (m_server_fd < 0) return -1;

    // Rate limit: max 50 accepts/sec
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_rate_ts).count();
    if (elapsed >= 1) {
        m_accept_rate = 0;
        m_rate_ts = now;
    }
    if (m_accept_rate >= 50) return -1;

    // Max active connections cap
    {
        std::lock_guard<std::mutex> lock(m_ssl_mtx);
        if (m_active_ssl.size() >= 256) return -1;
    }

    struct sockaddr_in client_addr {};
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept4(m_server_fd, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
    if (client_fd < 0) return -1;
    ++m_accept_rate;

    SSL* ssl = m_tls_ctx.create_server_ssl();
    if (!ssl) {
        close(client_fd);
        return -1;
    }

    SSL_set_fd(ssl, client_fd);
    SSL_set_accept_state(ssl);

    struct pollfd pfd;
    pfd.fd = client_fd;
    pfd.events = POLLIN;

    int ret;
    while ((ret = SSL_do_handshake(ssl)) != 1) {
        int err = SSL_get_error(ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            return -1;
        }
        pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;
        int pr = poll(&pfd, 1, 3000);
        if (pr <= 0) {
            if (pr == 0) {
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, sizeof(addr_str));
                std::cerr << "[TLS] Handshake timeout from "
                          << addr_str << std::endl;
            }
            SSL_free(ssl);
            close(client_fd);
            return -1;
        }
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "[TLS] Client certificate verification failed" << std::endl;
        SSL_free(ssl);
        close(client_fd);
        return -1;
    }

    std::lock_guard<std::mutex> lock(m_ssl_mtx);
    m_active_ssl[client_fd] = std::unique_ptr<SSL, SSLDeleter>(ssl, SSLDeleter());
    return client_fd;
}

int TransportLayer::connect(const std::string& host, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv{};
    tv.tv_sec = 5;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (::connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    SSL* ssl = m_tls_ctx.create_client_ssl();
    if (!ssl) {
        close(fd);
        return -1;
    }

    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        std::cerr << "[TLS] Server certificate verification failed for " << host << std::endl;
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    std::lock_guard<std::mutex> lock(m_ssl_mtx);
    m_active_ssl[fd] = std::unique_ptr<SSL, SSLDeleter>(ssl, SSLDeleter());
    return fd;
}

ssize_t TransportLayer::send(int fd, const void* buf, size_t len) {
    SSL* ssl_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_ssl_mtx);
        auto it = m_active_ssl.find(fd);
        if (it != m_active_ssl.end()) {
            ssl_ptr = it->second.get();
        }
    }
    if (!ssl_ptr) {
        size_t total = 0;
        while (total < len) {
            ssize_t n = ::send(fd, static_cast<const char*>(buf) + total, len - total, MSG_NOSIGNAL);
            if (n <= 0) return total > 0 ? static_cast<ssize_t>(total) : -1;
            total += n;
        }
        return static_cast<ssize_t>(total);
    }
    size_t total = 0;
    while (total < len) {
        ssize_t n = SSL_write(ssl_ptr, static_cast<const char*>(buf) + total, len - total);
        if (n <= 0) return total > 0 ? static_cast<ssize_t>(total) : -1;
        total += n;
    }
    return static_cast<ssize_t>(total);
}

ssize_t TransportLayer::recv(int fd, void* buf, size_t len) {
    SSL* ssl_ptr = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_ssl_mtx);
        auto it = m_active_ssl.find(fd);
        if (it != m_active_ssl.end()) {
            ssl_ptr = it->second.get();
        }
    }
    if (!ssl_ptr) {
        return ::recv(fd, buf, len, 0);
    }
    return SSL_read(ssl_ptr, buf, len);
}

void TransportLayer::close(int fd) {
    std::unique_ptr<SSL, SSLDeleter> ssl;
    {
        std::lock_guard<std::mutex> lock(m_ssl_mtx);
        auto it = m_active_ssl.find(fd);
        if (it != m_active_ssl.end()) {
            ssl = std::move(it->second);
            m_active_ssl.erase(it);
        }
    }
    if (ssl) {
        SSL_shutdown(ssl.get());
    }
    if (fd >= 0) {
        ::close(fd);
    }
}

void TransportLayer::shutdown() {
    m_running = false;
    std::lock_guard<std::mutex> lock(m_ssl_mtx);
    for (auto it = m_active_ssl.begin(); it != m_active_ssl.end(); ) {
        SSL_shutdown(it->second.get());
        int fd = it->first;
        it = m_active_ssl.erase(it);
        if (fd >= 0) {
            ::close(fd);
        }
    }

    if (m_server_fd >= 0) {
        ::close(m_server_fd);
        m_server_fd = -1;
    }
}

std::optional<ConnectionInfo> TransportLayer::get_connection_info(int fd) const {
    std::lock_guard<std::mutex> lock(m_ssl_mtx);
    auto it = m_active_ssl.find(fd);
    if (it == m_active_ssl.end()) {
        return std::nullopt;
    }

    SSL* ssl = it->second.get();
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return std::nullopt;
    }

    ConnectionInfo info;
    info.verified = (SSL_get_verify_result(ssl) == X509_V_OK);

    X509_NAME* subject = X509_get_subject_name(cert);
    if (subject) {
        int nid = OBJ_txt2nid("commonName");
        if (nid != NID_undef) {
            int idx = X509_NAME_get_index_by_NID(subject, nid, -1);
            if (idx >= 0) {
                X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
                if (entry) {
                    ASN1_STRING* asn1_str = X509_NAME_ENTRY_get_data(entry);
                    if (asn1_str) {
                        unsigned char* utf8_str = nullptr;
                        int cn_len = ASN1_STRING_to_UTF8(&utf8_str, asn1_str);
                        if (cn_len > 0 && utf8_str) {
                            info.subject_cn.assign(reinterpret_cast<char*>(utf8_str),
                                                   static_cast<size_t>(cn_len));
                            OPENSSL_free(utf8_str);
                        }
                    }
                }
            }
        }
    }

    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &addr_len) == 0) {
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip))) {
            info.peer_ip = ip;
        }
        info.peer_port = ntohs(addr.sin_port);
    }

    X509_free(cert);
    return info;
}

PeerDiscovery::PeerDiscovery(const DiscoveryConfig& config, const std::string& node_id, const std::string& public_key)
    : m_config(config), m_node_id(node_id), m_public_key(public_key), m_beacon_sock(-1) {}

PeerDiscovery::~PeerDiscovery() {
    stop();
}

bool PeerDiscovery::start() {
    if (m_running.load()) return true;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;
    m_beacon_sock = sock;

    int opt = 1;
    setsockopt(m_beacon_sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_config.beacon_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_beacon_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(m_beacon_sock);
        m_beacon_sock = -1;
        return false;
    }

    m_running.store(true);
    m_beacon_thread = std::thread(&PeerDiscovery::beacon_loop, this);

    return true;
}

void PeerDiscovery::stop() {
    if (!m_running.load()) return;

    m_running.store(false);

    if (m_beacon_thread.joinable()) {
        m_beacon_thread.join();
    }

    if (m_beacon_sock >= 0) {
        close(m_beacon_sock);
        m_beacon_sock = -1;
    }
}

void PeerDiscovery::beacon_loop() {
    char buffer[4096];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (m_running.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(m_beacon_sock, &fds);

        struct timeval tv = {1, 0};
        int ret = select(m_beacon_sock + 1, &fds, nullptr, nullptr, &tv);

        if (ret > 0 && FD_ISSET(m_beacon_sock, &fds)) {
            ssize_t len = recvfrom(m_beacon_sock, buffer, sizeof(buffer) - 1, 0,
                                   (struct sockaddr*)&src_addr, &addr_len);
            if (len > 0) {
                buffer[len] = '\0';
                handle_incoming_beacon(buffer, len, src_addr);
            }
        }

        cleanup_stale_peers();
    }
}

bool PeerDiscovery::handle_incoming_beacon(const char* data, size_t len, const sockaddr_in& src) {
    std::string payload(data, len);

    size_t sep1 = payload.find('|');
    size_t sep2 = payload.find('|', sep1 + 1);
    if (sep1 == std::string::npos || sep2 == std::string::npos) return false;

    std::string node_id = payload.substr(0, sep1);
    std::string ip = payload.substr(sep1 + 1, sep2 - sep1 - 1);
    uint16_t port = 0;
    try {
        port = static_cast<uint16_t>(std::stoi(payload.substr(sep2 + 1)));
    } catch (...) {
        return false;
    }

    if (node_id == m_node_id) return false;

    std::lock_guard<std::mutex> lock(m_peers_mutex);

    auto it = m_peers.find(node_id);
    if (it == m_peers.end()) {
        PeerInfo peer;
        peer.node_id = node_id;
        peer.ip = inet_ntoa(src.sin_addr);
        peer.port = port;
        peer.last_seen = std::chrono::steady_clock::now();
        peer.is_verified = false;

        m_peers[node_id] = peer;

        if (m_on_peer_discovered) {
            m_on_peer_discovered(peer);
        }
    } else {
        it->second.last_seen = std::chrono::steady_clock::now();
        it->second.ip = inet_ntoa(src.sin_addr);
        it->second.port = port;
    }

    return true;
}

void PeerDiscovery::cleanup_stale_peers() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> lost_peers;

    std::lock_guard<std::mutex> lock(m_peers_mutex);

    for (auto it = m_peers.begin(); it != m_peers.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - it->second.last_seen).count();

        if (elapsed > m_config.peer_timeout_ms) {
            lost_peers.push_back(it->first);
            it = m_peers.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& node_id : lost_peers) {
        if (m_on_peer_lost) {
            m_on_peer_lost(node_id);
        }
    }
}

std::vector<PeerInfo> PeerDiscovery::get_active_peers() {
    std::lock_guard<std::mutex> lock(m_peers_mutex);

    std::vector<PeerInfo> peers;
    for (const auto& [id, peer] : m_peers) {
        peers.push_back(peer);
    }
    return peers;
}

std::optional<PeerInfo> PeerDiscovery::get_peer(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);

    auto it = m_peers.find(node_id);
    if (it != m_peers.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool PeerDiscovery::announce_peer(const PeerInfo& peer) {
    if (m_beacon_sock < 0) return false;

    std::string payload = m_node_id + "|" + peer.ip + "|" + std::to_string(peer.port);

    struct sockaddr_in dest {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(m_config.beacon_port);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    ssize_t sent = sendto(m_beacon_sock, payload.c_str(), payload.size(), 0,
                          (struct sockaddr*)&dest, sizeof(dest));

    return sent == static_cast<ssize_t>(payload.size());
}

bool PeerDiscovery::verify_peer(const std::string& node_id, const std::string& public_key_pem) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);

    auto it = m_peers.find(node_id);
    if (it != m_peers.end()) {
        it->second.public_key_pem = public_key_pem;
        it->second.is_verified = true;
        return true;
    }
    return false;
}

void PeerDiscovery::set_on_peer_discovered(std::function<void(const PeerInfo&)> cb) {
    m_on_peer_discovered = cb;
}

void PeerDiscovery::set_on_peer_lost(std::function<void(const std::string&)> cb) {
    m_on_peer_lost = cb;
}

} // namespace neuro_mesh::net