#include "net/TransportLayer.hpp"
#include "common/Base64.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

namespace neuro_mesh::net {

TLSContext::TLSContext(const TLSConfig& config) : m_config(config) {
    m_valid = configure_server_ctx() && configure_client_ctx();
}

TLSContext::~TLSContext() = default;

bool TLSContext::configure_server_ctx() {
    const SSL_METHOD* method = TLS_server_method();
    m_server_ctx.reset(SSL_CTX_new(method));
    if (!m_server_ctx) {
        std::cerr << "[TLS] Failed to create server context" << std::endl;
        return false;
    }

    SSL_CTX_set_min_proto_version(m_server_ctx.get(), m_config.min_tls_version);
    SSL_CTX_set_cipher_list(m_server_ctx.get(), "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS");

    if (SSL_CTX_use_certificate_file(m_server_ctx.get(), m_config.node_cert_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load server certificate" << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_server_ctx.get(), m_config.node_key_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load server key" << std::endl;
        return false;
    }

    if (SSL_CTX_check_private_key(m_server_ctx.get()) <= 0) {
        std::cerr << "[TLS] Private key does not match certificate" << std::endl;
        return false;
    }

    if (!m_config.ca_cert_pem.empty()) {
        SSL_CTX_load_verify_locations(m_server_ctx.get(), m_config.ca_cert_pem.c_str(), nullptr);
        SSL_CTX_set_verify(m_server_ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }

    SSL_CTX_set_alpn_protos(m_server_ctx.get(), (const unsigned char*)"\x08http/1.1", 9);

    return true;
}

bool TLSContext::configure_client_ctx() {
    const SSL_METHOD* method = TLS_client_method();
    m_client_ctx.reset(SSL_CTX_new(method));
    if (!m_client_ctx) {
        std::cerr << "[TLS] Failed to create client context" << std::endl;
        return false;
    }

    SSL_CTX_set_min_proto_version(m_client_ctx.get(), m_config.min_tls_version);
    SSL_CTX_set_cipher_list(m_client_ctx.get(), "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS");

    if (SSL_CTX_use_certificate_file(m_client_ctx.get(), m_config.node_cert_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load client certificate" << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(m_client_ctx.get(), m_config.node_key_pem.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[TLS] Failed to load client key" << std::endl;
        return false;
    }

    if (!m_config.ca_cert_pem.empty()) {
        SSL_CTX_load_verify_locations(m_client_ctx.get(), m_config.ca_cert_pem.c_str(), nullptr);
        SSL_CTX_set_verify(m_client_ctx.get(), SSL_VERIFY_PEER, nullptr);
    }

    return true;
}

TLSSocket::TLSSocket(SSL* ssl, int fd, bool is_server)
    : m_ssl(ssl, SSL_free)
    , m_fd(fd)
    , m_is_server(is_server) {
}

TLSSocket::~TLSSocket() {
    close();
}

bool TLSSocket::handshake() {
    int ret = SSL_accept(m_ssl.get()) if (m_is_server) else SSL_connect(m_ssl.get());
    if (ret != 1) {
        int err = SSL_get_error(m_ssl.get(), ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            std::cerr << "[TLS] Handshake failed: " << err << std::endl;
            return false;
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        if (err == SSL_ERROR_WANT_READ) FD_SET(m_fd, &read_fds);
        if (err == SSL_ERROR_WANT_WRITE) FD_SET(m_fd, &write_fds);

        struct timeval tv = {5, 0};
        if (select(m_fd + 1, &read_fds, &write_fds, nullptr, &tv) <= 0) {
            std::cerr << "[TLS] Handshake timeout" << std::endl;
            return false;
        }

        ret = SSL_accept(m_ssl.get()) if (m_is_server) else SSL_connect(m_ssl.get());
        if (ret != 1) {
            std::cerr << "[TLS] Handshake retry failed: " << SSL_get_error(m_ssl.get(), ret) << std::endl;
            return false;
        }
    }

    m_connected = true;
    return true;
}

bool TLSSocket::write(const uint8_t* data, size_t len) {
    if (!m_connected) return false;

    int written = SSL_write(m_ssl.get(), data, len);
    if (written <= 0) {
        int err = SSL_get_error(m_ssl.get(), written);
        if (err != SSL_ERROR_WANT_WRITE) {
            std::cerr << "[TLS] Write failed: " << err << std::endl;
            m_connected = false;
            return false;
        }
    }
    return true;
}

std::optional<std::vector<uint8_t>> TLSSocket::read(size_t max_len) {
    if (!m_connected) return std::nullopt;

    std::vector<uint8_t> buffer(max_len);
    int bytes = SSL_read(m_ssl.get(), buffer.data(), max_len);

    if (bytes <= 0) {
        int err = SSL_get_error(m_ssl.get(), bytes);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN) {
            std::cerr << "[TLS] Read failed: " << err << std::endl;
            m_connected = false;
        }
        return std::nullopt;
    }

    buffer.resize(bytes);
    return buffer;
}

void TLSSocket::close() {
    if (m_connected) {
        SSL_shutdown(m_ssl.get());
        m_connected = false;
    }
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
}

PeerConnection::PeerConnection(const PeerEndpoint& endpoint, std::unique_ptr<TLSSocket> socket)
    : m_endpoint(endpoint)
    , m_socket(std::move(socket))
    , m_state(ConnectionState::CONNECTING)
    , m_last_activity(std::chrono::steady_clock::now())
    , m_messages_sent(0)
    , m_messages_received(0) {
}

PeerConnection::~PeerConnection() = default;

void PeerConnection::set_state(ConnectionState state) {
    m_state = state;
    update_activity();
}

void PeerConnection::update_activity() {
    m_last_activity = std::chrono::steady_clock::now();
}

bool PeerConnection::send_message(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(m_send_mutex);
    return m_socket->write(data.data(), data.size());
}

TransportLayer::TransportLayer(const TLSConfig& tls_config, uint16_t listen_port)
    : m_tls_config(tls_config)
    , m_listen_port(listen_port)
    , m_running(false) {
    m_tls_context = std::make_unique<TLSContext>(tls_config);
}

TransportLayer::~TransportLayer() {
    stop();
}

bool TransportLayer::start() {
    if (m_running) return false;

    m_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_listen_fd < 0) {
        std::cerr << "[TRANSPORT] Failed to create socket" << std::endl;
        return false;
    }

    int opt = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_listen_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(m_listen_port);

    if (bind(m_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[TRANSPORT] Failed to bind to port " << m_listen_port << std::endl;
        close(m_listen_fd);
        return false;
    }

    if (listen(m_listen_fd, 128) < 0) {
        std::cerr << "[TRANSPORT] Failed to listen" << std::endl;
        close(m_listen_fd);
        return false;
    }

    m_running = true;
    m_accept_thread = std::thread(&TransportLayer::accept_loop, this);
    m_send_thread = std::thread(&TransportLayer::send_loop, this);
    m_heartbeat_thread = std::thread(&TransportLayer::heartbeat_loop, this);

    std::cout << "[TRANSPORT] Listening on port " << m_listen_port << std::endl;
    return true;
}

void TransportLayer::stop() {
    if (!m_running) return;
    m_running = false;

    m_queue_cv.notify_all();
    if (m_accept_thread.joinable()) m_accept_thread.join();
    if (m_send_thread.joinable()) m_send_thread.join();
    if (m_heartbeat_thread.joinable()) m_heartbeat_thread.join();

    {
        std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
        for (auto& [id, conn] : m_peers) {
            if (conn->socket()) conn->socket()->close();
        }
    }

    if (m_listen_fd >= 0) {
        close(m_listen_fd);
        m_listen_fd = -1;
    }

    std::cout << "[TRANSPORT] Stopped" << std::endl;
}

bool TransportLayer::connect_to_peer(const PeerEndpoint& endpoint) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(endpoint.port);

    if (inet_pton(AF_INET, endpoint.ip_address.c_str(), &addr.sin_addr) <= 0) {
        struct hostent* he = gethostbyname(endpoint.ip_address.c_str());
        if (!he) {
            close(fd);
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return false;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    SSL* ssl = SSL_new(m_tls_context->client_context());
    SSL_set_fd(ssl, fd);

    auto socket = std::make_unique<TLSSocket>(ssl, fd, false);
    if (!socket->handshake()) {
        return false;
    }

    auto conn = std::make_unique<PeerConnection>(endpoint, std::move(socket));
    conn->set_state(ConnectionState::CONNECTED);

    {
        std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
        m_peers[endpoint.node_id] = std::move(conn);
    }

    std::cout << "[TRANSPORT] Connected to " << endpoint.node_id << " at " << endpoint.ip_address << ":" << endpoint.port << std::endl;

    if (m_connection_callback) {
        m_connection_callback(endpoint.node_id, ConnectionState::CONNECTED);
    }

    std::thread(&TransportLayer::receive_loop, this, endpoint.node_id,
        m_peers.at(endpoint.node_id).get()).detach();

    return true;
}

void TransportLayer::disconnect_peer(const std::string& node_id) {
    std::unique_lock<std::shared_mutex> lock(m_peers_mutex);
    auto it = m_peers.find(node_id);
    if (it != m_peers.end()) {
        it->second->socket()->close();
        m_peers.erase(it);
        lock.unlock();

        if (m_connection_callback) {
            m_connection_callback(node_id, ConnectionState::DISCONNECTED);
        }
    }
}

bool TransportLayer::send_message(const std::string& target_node_id, const void* data, size_t len) {
    OutgoingMessage msg;
    msg.target_node_id = target_node_id;
    msg.data.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + len);
    msg.enqueued_at = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(m_queue_mutex);
    if (m_outgoing_queue.size() >= MAX_QUEUE_SIZE) {
        std::cerr << "[TRANSPORT] Message queue full" << std::endl;
        return false;
    }
    m_outgoing_queue.push(std::move(msg));
    m_queue_cv.notify_one();
    return true;
}

bool TransportLayer::broadcast_message(const void* data, size_t len) {
    std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
    for (const auto& [id, _] : m_peers) {
        send_message(id, data, len);
    }
    return true;
}

void TransportLayer::set_message_callback(MessageCallback callback) {
    m_message_callback = std::move(callback);
}

void TransportLayer::set_connection_callback(ConnectionCallback callback) {
    m_connection_callback = std::move(callback);
}

void TransportLayer::set_error_callback(ErrorCallback callback) {
    m_error_callback = std::move(callback);
}

std::vector<std::string> TransportLayer::get_connected_peers() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
    std::vector<std::string> peers;
    for (const auto& [id, conn] : m_peers) {
        if (conn->state() == ConnectionState::CONNECTED) {
            peers.push_back(id);
        }
    }
    return peers;
}

size_t TransportLayer::peer_count() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
    return m_peers.size();
}

bool TransportLayer::is_connected(const std::string& node_id) const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
    auto it = m_peers.find(node_id);
    return it != m_peers.end() && it->second->state() == ConnectionState::CONNECTED;
}

void TransportLayer::accept_loop() {
    while (m_running) {
        struct sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        int client_fd = accept(m_listen_fd, (struct sockaddr*)&cliaddr, &len);

        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }

        handle_incoming_connection(client_fd);
    }
}

bool TransportLayer::handle_incoming_connection(int client_fd) {
    int opt = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    SSL* ssl = SSL_new(m_tls_context->server_context());
    SSL_set_fd(ssl, client_fd);

    auto socket = std::make_unique<TLSSocket>(ssl, client_fd, true);
    if (!socket->handshake()) {
        return false;
    }

    std::string peer_id = "unknown";
    {
        X509* cert = SSL_get_peer_certificate(ssl->ssl());
        if (cert) {
            char* cn = nullptr;
            X509_NAME_get_text_by_nid(X509_get_subject_name(cert), NID_commonName, nullptr, 0);
            X509_NAME_get_text_by_nid(X509_get_subject_name(cert), NID_commonName, cn, 256);
            if (cn) peer_id = cn;
            X509_free(cert);
        }
    }

    PeerEndpoint endpoint;
    endpoint.node_id = peer_id;
    endpoint.ip_address = inet_ntoa(cliaddr.sin_addr);

    auto conn = std::make_unique<PeerConnection>(endpoint, std::move(socket));
    conn->set_state(ConnectionState::CONNECTED);

    {
        std::shared_lock<std::shared_mutex> lock(m_peers_mutex);
        m_peers[peer_id] = std::move(conn);
    }

    if (m_connection_callback) {
        m_connection_callback(peer_id, ConnectionState::CONNECTED);
    }

    std::thread(&TransportLayer::receive_loop, this, peer_id,
        m_peers.at(peer_id).get()).detach();

    return true;
}

void TransportLayer::receive_loop(const std::string& node_id, PeerConnection* conn) {
    while (m_running && conn->socket() && conn->socket()->is_connected()) {
        auto data = conn->socket()->read(MAX_MESSAGE_SIZE);
        if (!data) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        conn->increment_received();
        conn->update_activity();

        IncomingMessage msg;
        msg.sender_node_id = node_id;
        msg.data = std::move(*data);
        msg.received_at = std::chrono::steady_clock::now();

        if (m_message_callback) {
            m_message_callback(msg);
        }
    }

    conn->set_state(ConnectionState::DISCONNECTED);
    if (m_connection_callback) {
        m_connection_callback(node_id, ConnectionState::DISCONNECTED);
    }
}

void TransportLayer::send_loop() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_queue_mutex);
        m_queue_cv.wait_for(lock, std::chrono::seconds(1), [this] {
            return !m_outgoing_queue.empty() || !m_running;
        });

        if (!m_running) break;
        if (m_outgoing_queue.empty()) continue;

        OutgoingMessage msg = std::move(m_outgoing_queue.front());
        m_outgoing_queue.pop();
        lock.unlock();

        std::shared_lock<std::shared_mutex> peer_lock(m_peers_mutex);
        auto it = m_peers.find(msg.target_node_id);
        if (it == m_peers.end() || it->second->state() != ConnectionState::CONNECTED) {
            continue;
        }

        if (it->second->send_message(msg.data)) {
            it->second->increment_sent();
        }
    }
}

void TransportLayer::heartbeat_loop() {
    while (m_running) {
        std::this_thread::sleep_for(HEARTBEAT_INTERVAL);

        auto now = std::chrono::steady_clock::now();
        std::shared_lock<std::shared_mutex> lock(m_peers_mutex);

        for (auto& [id, conn] : m_peers) {
            auto elapsed = now - conn->last_activity();
            if (elapsed > CONNECTION_TIMEOUT) {
                std::cerr << "[TRANSPORT] Peer " << id << " timed out" << std::endl;
                conn->socket()->close();
                if (m_connection_callback) {
                    m_connection_callback(id, ConnectionState::DISCONNECTED);
                }
            }
        }
    }
}

PeerDiscovery::PeerDiscovery(TransportLayer* transport) : m_transport(transport), m_running(false) {}

PeerDiscovery::~PeerDiscovery() {
    stop();
}

void PeerDiscovery::start() {
    if (m_running) return;
    m_running = true;
    m_discovery_thread = std::thread(&PeerDiscovery::discovery_loop, this);
    std::cout << "[DISCOVERY] Started" << std::endl;
}

void PeerDiscovery::stop() {
    m_running = false;
    if (m_discovery_thread.joinable()) {
        m_discovery_thread.join();
    }
}

void PeerDiscovery::add_seed_node(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_seed_nodes.emplace_back(ip, port);
}

void PeerDiscovery::remove_seed_node(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_seed_nodes.erase(
        std::remove_if(m_seed_nodes.begin(), m_seed_nodes.end(),
            [&](const auto& p) { return p.first == ip && p.second == port; }),
        m_seed_nodes.end()
    );
}

void PeerDiscovery::request_peers_from(const std::string& node_id) {
    std::string msg = "PEER_QUERY|" + m_transport->get_local_node_id();
    m_transport->send_message(node_id, msg.data(), msg.size());
}

std::vector<PeerEndpoint> PeerDiscovery::get_discovered_peers() const {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    std::vector<PeerEndpoint> peers;
    for (const auto& [id, endpoint] : m_discovered_peers) {
        peers.push_back(endpoint);
    }
    return peers;
}

void PeerDiscovery::on_peer_announce(const std::string& node_id, const PeerEndpoint& endpoint) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_discovered_peers[node_id] = endpoint;

    if (m_discovery_callback) {
        m_discovery_callback(endpoint);
    }
}

void PeerDiscovery::on_peer_disconnect(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(m_peers_mutex);
    m_discovered_peers.erase(node_id);
}

void PeerDiscovery::set_discovery_callback(std::function<void(const PeerEndpoint&)> callback) {
    m_discovery_callback = std::move(callback);
}

void PeerDiscovery::discovery_loop() {
    while (m_running) {
        for (const auto& [ip, port] : m_seed_nodes) {
            PeerEndpoint endpoint;
            endpoint.node_id = "seed_" + std::to_string(port);
            endpoint.ip_address = ip;
            endpoint.port = port;
            m_transport->connect_to_peer(endpoint);
        }

        std::this_thread::sleep_for(ANNOUNCE_INTERVAL);
    }
}

void PeerDiscovery::announce_presence() {}

void PeerDiscovery::query_peers() {}

MessageRouter::MessageRouter(TransportLayer* transport, PeerDiscovery* discovery)
    : m_transport(transport), m_discovery(discovery) {}

MessageRouter::~MessageRouter() = default;

void MessageRouter::route_message(const std::string& sender_id, const std::vector<uint8_t>& payload) {
    if (payload.size() < 2) return;

    uint16_t msg_type = (payload[0] << 8) | payload[1];
    std::vector<uint8_t> data(payload.begin() + 2, payload.end());

    std::lock_guard<std::mutex> lock(m_handlers_mutex);
    auto it = m_handlers.find(msg_type);
    if (it != m_handlers.end()) {
        it->second(sender_id, data);
    }
}

bool MessageRouter::send_to(const std::string& target_id, const void* data, size_t len) {
    std::vector<uint8_t> payload(len + 2);
    payload[0] = 0x00;
    payload[1] = 0x01;
    memcpy(payload.data() + 2, data, len);

    return m_transport->send_message(target_id, payload.data(), payload.size());
}

bool MessageRouter::send_via(const std::string& via_node_id, const std::string& ultimate_target,
                              const void* data, size_t len) {
    return send_to(via_node_id, data, len);
}

void MessageRouter::register_handler(uint16_t message_type,
    std::function<void(const std::string&, const std::vector<uint8_t>&)> handler) {
    std::lock_guard<std::mutex> lock(m_handlers_mutex);
    m_handlers[message_type] = std::move(handler);
}

void MessageRouter::unregister_handler(uint16_t message_type) {
    std::lock_guard<std::mutex> lock(m_handlers_mutex);
    m_handlers.erase(message_type);
}

std::optional<std::string> MessageRouter::find_route_to(const std::string& target_id) const {
    std::lock_guard<std::mutex> lock(m_routing_mutex);
    auto it = m_routing_table.find(target_id);
    if (it != m_routing_table.end()) {
        return it->second.next_hop;
    }
    return std::nullopt;
}

NetworkStack::NetworkStack(const NetworkConfig& config)
    : m_config(config)
    , m_transport(std::make_unique<TransportLayer>(config.tls, config.listen_port))
    , m_discovery(std::make_unique<PeerDiscovery>(m_transport.get()))
    , m_router(std::make_unique<MessageRouter>(m_transport.get(), m_discovery.get())) {
}

NetworkStack::~NetworkStack() = default;

bool NetworkStack::start() {
    if (!m_transport->start()) return false;

    if (m_config.enable_peer_discovery) {
        for (const auto& [ip, port] : m_config.seed_nodes) {
            m_discovery->add_seed_node(ip, port);
        }
        m_discovery->start();
    }

    return true;
}

void NetworkStack::stop() {
    m_discovery->stop();
    m_transport->stop();
}

bool NetworkStack::connect(const std::string& ip, uint16_t port, const std::string& expected_node_id) {
    PeerEndpoint endpoint;
    endpoint.node_id = expected_node_id;
    endpoint.ip_address = ip;
    endpoint.port = port;
    return m_transport->connect_to_peer(endpoint);
}

void NetworkStack::disconnect(const std::string& node_id) {
    m_transport->disconnect_peer(node_id);
}

bool NetworkStack::send(uint16_t message_type, const std::string& target_node_id, const void* data, size_t len) {
    std::vector<uint8_t> payload(len + 2);
    payload[0] = (message_type >> 8) & 0xFF;
    payload[1] = message_type & 0xFF;
    memcpy(payload.data() + 2, data, len);

    return m_transport->send_message(target_node_id, payload.data(), payload.size());
}

bool NetworkStack::broadcast(uint16_t message_type, const void* data, size_t len) {
    std::vector<uint8_t> payload(len + 2);
    payload[0] = (message_type >> 8) & 0xFF;
    payload[1] = message_type & 0xFF;
    memcpy(payload.data() + 2, data, len);

    return m_transport->broadcast_message(payload.data(), payload.size());
}

void NetworkStack::register_message_handler(uint16_t message_type,
    std::function<void(const std::string&, const std::vector<uint8_t>&)> handler) {
    m_router->register_handler(message_type, std::move(handler));
}

size_t NetworkStack::connected_peers() const {
    return m_transport->peer_count();
}

bool NetworkStack::is_connected(const std::string& node_id) const {
    return m_transport->is_connected(node_id);
}

std::vector<std::string> NetworkStack::get_connected_peer_ids() const {
    return m_transport->get_connected_peers();
}

} // namespace neuro_mesh::net