#pragma once
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <queue>
#include <optional>
#include <functional>
#include <chrono>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <openssl/ssl.h>
#include <openssl/tls1.h>

namespace neuro_mesh::net {

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    HANDSHAKING,
    CONNECTED,
    CLOSING,
    ERROR
};

struct PeerEndpoint {
    std::string node_id;
    std::string ip_address;
    uint16_t port;
    std::string certificate_pem;
    bool is_validator = false;
    uint32_t trust_level = 1;
};

struct TLSConfig {
    std::string ca_cert_pem;
    std::string node_cert_pem;
    std::string node_key_pem;
    std::vector<std::string> cipher_suites;
    int min_tls_version = TLS1_3_VERSION;
    bool verify_client_cert = true;
    bool request_client_cert = true;
};

struct OutgoingMessage {
    std::string target_node_id;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point enqueued_at;
    int retry_count = 0;
};

struct IncomingMessage {
    std::string sender_node_id;
    std::vector<uint8_t> data;
    std::chrono::steady_clock::time_point received_at;
};

using MessageCallback = std::function<void(IncomingMessage)>;
using ConnectionCallback = std::function<void(const std::string& node_id, ConnectionState state)>;
using ErrorCallback = std::function<void(const std::string& node_id, const std::string& error)>;

class TLSContext {
public:
    explicit TLSContext(const TLSConfig& config);
    ~TLSContext();

    bool is_valid() const { return m_valid; }
    SSL_CTX* server_context() { return m_server_ctx.get(); }
    SSL_CTX* client_context() { return m_client_ctx.get(); }

private:
    bool m_valid = false;
    std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> m_server_ctx;
    std::unique_ptr<SSL_CTX, void(*)(SSL_CTX*)> m_client_ctx;
    TLSConfig m_config;

    bool configure_server_ctx();
    bool configure_client_ctx();
};

class TLSSocket {
public:
    explicit TLSSocket(SSL* ssl, int fd, bool is_server);
    ~TLSSocket();

    bool handshake();
    bool write(const uint8_t* data, size_t len);
    std::optional<std::vector<uint8_t>> read(size_t max_len = 8192);
    void close();
    bool is_connected() const { return m_connected; }
    SSL* ssl() { return m_ssl.get(); }

private:
    std::unique_ptr<SSL, void(*)(SSL*)> m_ssl;
    int m_fd = -1;
    bool m_is_server = false;
    bool m_connected = false;
};

class PeerConnection {
public:
    PeerConnection(const PeerEndpoint& endpoint, std::unique_ptr<TLSSocket> socket);
    ~PeerConnection();

    const std::string& node_id() const { return m_endpoint.node_id; }
    const PeerEndpoint& endpoint() const { return m_endpoint; }
    TLSSocket* socket() { return m_socket.get(); }

    ConnectionState state() const { return m_state.load(); }
    void set_state(ConnectionState state);

    std::chrono::steady_clock::time_point last_activity() const { return m_last_activity; }
    void update_activity();

    uint64_t messages_sent() const { return m_messages_sent.load(); }
    uint64_t messages_received() const { return m_messages_received.load(); }
    void increment_sent() { ++m_messages_sent; }
    void increment_received() { ++m_messages_received; }

    bool send_message(const std::vector<uint8_t>& data);

private:
    PeerEndpoint m_endpoint;
    std::unique_ptr<TLSSocket> m_socket;
    std::atomic<ConnectionState> m_state;
    std::chrono::steady_clock::time_point m_last_activity;
    std::atomic<uint64_t> m_messages_sent;
    std::atomic<uint64_t> m_messages_received;
    mutable std::mutex m_send_mutex;
};

class TransportLayer {
public:
    explicit TransportLayer(const TLSConfig& tls_config, uint16_t listen_port);
    ~TransportLayer();

    bool start();
    void stop();

    bool connect_to_peer(const PeerEndpoint& endpoint);
    void disconnect_peer(const std::string& node_id);

    bool send_message(const std::string& target_node_id, const void* data, size_t len);
    bool broadcast_message(const void* data, size_t len);

    void set_message_callback(MessageCallback callback);
    void set_connection_callback(ConnectionCallback callback);
    void set_error_callback(ErrorCallback callback);

    std::vector<std::string> get_connected_peers() const;
    size_t peer_count() const;
    bool is_connected(const std::string& node_id) const;

    uint16_t listen_port() const { return m_listen_port; }

    std::string get_local_node_id() const { return m_node_id; }
    void set_local_node_id(const std::string& id) { m_node_id = id; }

private:
    void accept_loop();
    void receive_loop(const std::string& node_id, PeerConnection* conn);
    void send_loop();
    void heartbeat_loop();

    bool handle_incoming_connection(int client_fd);
    bool perform_mutual_tls_handshake(SSL* ssl, const std::string& expected_node_id);

    TLSConfig m_tls_config;
    uint16_t m_listen_port;
    std::string m_node_id;

    std::unique_ptr<TLSContext> m_tls_context;
    int m_listen_fd = -1;

    std::atomic<bool> m_running;
    std::thread m_accept_thread;
    std::thread m_send_thread;
    std::thread m_heartbeat_thread;

    mutable std::shared_mutex m_peers_mutex;
    std::map<std::string, std::unique_ptr<PeerConnection>> m_peers;

    std::queue<OutgoingMessage> m_outgoing_queue;
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    MessageCallback m_message_callback;
    ConnectionCallback m_connection_callback;
    ErrorCallback m_error_callback;

    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    static constexpr auto HEARTBEAT_INTERVAL = std::chrono::seconds(10);
    static constexpr auto CONNECTION_TIMEOUT = std::chrono::seconds(30);
    static constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;
};

class PeerDiscovery {
public:
    explicit PeerDiscovery(TransportLayer* transport);
    ~PeerDiscovery();

    void start();
    void stop();

    void add_seed_node(const std::string& ip, uint16_t port);
    void remove_seed_node(const std::string& ip, uint16_t port);

    void request_peers_from(const std::string& node_id);
    std::vector<PeerEndpoint> get_discovered_peers() const;

    void on_peer_announce(const std::string& node_id, const PeerEndpoint& endpoint);
    void on_peer_disconnect(const std::string& node_id);

    void set_discovery_callback(std::function<void(const PeerEndpoint&)> callback);

private:
    void discovery_loop();
    void announce_presence();
    void query_peers();

    TransportLayer* m_transport;
    std::atomic<bool> m_running;
    std::thread m_discovery_thread;

    std::vector<std::pair<std::string, uint16_t>> m_seed_nodes;
    std::map<std::string, PeerEndpoint> m_discovered_peers;
    mutable std::mutex m_peers_mutex;

    std::function<void(const PeerEndpoint&)> m_discovery_callback;

    static constexpr auto ANNOUNCE_INTERVAL = std::chrono::seconds(30);
    static constexpr auto PEER_QUERY_INTERVAL = std::chrono::seconds(60);
    static constexpr size_t MAX_DISCOVERED_PEERS = 100;
};

class MessageRouter {
public:
    explicit MessageRouter(TransportLayer* transport, PeerDiscovery* discovery);
    ~MessageRouter();

    void route_message(const std::string& sender_id, const std::vector<uint8_t>& payload);
    bool send_to(const std::string& target_id, const void* data, size_t len);
    bool send_via(const std::string& via_node_id, const std::string& ultimate_target, const void* data, size_t len);

    void register_handler(uint16_t message_type, std::function<void(const std::string&, const std::vector<uint8_t>&)> handler);
    void unregister_handler(uint16_t message_type);

    std::optional<std::string> find_route_to(const std::string& target_id) const;

private:
    TransportLayer* m_transport;
    PeerDiscovery* m_discovery;

    std::map<uint16_t, std::function<void(const std::string&, const std::vector<uint8_t>&)>> m_handlers;
    mutable std::mutex m_handlers_mutex;

    struct RouteEntry {
        std::string next_hop;
        uint32_t metric;
        std::chrono::steady_clock::time_point last_updated;
    };
    std::map<std::string, RouteEntry> m_routing_table;
    mutable std::mutex m_routing_mutex;
};

struct NetworkConfig {
    uint16_t listen_port = 9900;
    std::string node_id;
    TLSConfig tls;
    std::vector<std::pair<std::string, uint16_t>> seed_nodes;
    bool enable_peer_discovery = true;
    bool enable_routing = true;
};

class NetworkStack {
public:
    explicit NetworkStack(const NetworkConfig& config);
    ~NetworkStack();

    bool start();
    void stop();

    bool connect(const std::string& ip, uint16_t port, const std::string& expected_node_id);
    void disconnect(const std::string& node_id);

    bool send(uint16_t message_type, const std::string& target_node_id, const void* data, size_t len);
    bool broadcast(uint16_t message_type, const void* data, size_t len);

    void register_message_handler(uint16_t message_type, std::function<void(const std::string&, const std::vector<uint8_t>&)> handler);

    size_t connected_peers() const;
    bool is_connected(const std::string& node_id) const;
    std::vector<std::string> get_connected_peer_ids() const;

    TransportLayer* transport() { return m_transport.get(); }
    PeerDiscovery* discovery() { return m_discovery.get(); }
    MessageRouter* router() { return m_router.get(); }

private:
    NetworkConfig m_config;
    std::unique_ptr<TransportLayer> m_transport;
    std::unique_ptr<PeerDiscovery> m_discovery;
    std::unique_ptr<MessageRouter> m_router;
};

} // namespace neuro_mesh::net