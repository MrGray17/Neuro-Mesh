#include "consensus/MeshNode.hpp"
#include "common/UniqueFD.hpp"
#include "common/Base64.hpp"
#include "enforcer/MitigationEngine.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <sys/wait.h>
#include <random>
#include <thread>
#include <mutex>
#include <fstream>
#include <netdb.h>
#include <sys/syscall.h>
#include <linux/close_range.h>

namespace neuro_mesh {

// =============================================================================
// Construction
// =============================================================================

MeshNode::MeshNode(const std::string& node_id,
                   PolicyEnforcer* enforcer, MitigationEngine* mitigation,
                   TelemetryBridge* bridge)
    : m_node_id(node_id),
      m_udp_port(9999),
      m_tcp_port(0),
      m_tls_port(0),
      m_running(false),
      m_pbft(1),   // start with n=1 (self), scale up via discovery
      m_sequence_number(0),
      m_key_manager("./keystore_" + node_id),
      m_enforcer(enforcer),
      m_mitigation(mitigation),
      m_bridge(bridge),
      m_proof_chain(std::make_shared<crypto::ProofChain>(node_id)),
      m_journal("./journal_" + node_id + ".log"),
      m_webhook_url([]() {
          const char* env = std::getenv("NEURO_WEBHOOK_URL");
          return env ? std::string(env) : "";
      }()),
      m_max_evidence_size([]() -> size_t {
          const char* env = std::getenv("NEURO_PBFT_EVIDENCE_MAX");
          if (!env) return 4096;
          char* end = nullptr;
          long val = std::strtol(env, &end, 10);
          if (*end != '\0' || val <= 0) return 4096;
          return std::min(static_cast<size_t>(val), size_t(65536));
      }())
{
    if (!m_webhook_url.empty()) {
        // Redact credentials from URL before logging to prevent
        // credential leakage in container logs (BUG-10 fix).
        std::string safe_url = m_webhook_url;
        auto scheme_end = safe_url.find("://");
        if (scheme_end != std::string::npos) {
            auto path_start = safe_url.find('/', scheme_end + 3);
            auto at_pos = safe_url.find('@');
            if (at_pos != std::string::npos && (path_start == std::string::npos || at_pos < path_start)) {
                safe_url.replace(scheme_end + 3, at_pos - scheme_end - 3, "***:***");
            }
        }
        std::cout << "[ALERT] Webhook endpoint: " << safe_url << std::endl;
    }

    // Persistent identity — load from keystore on restart, generate only once.
    // Without this, every agent restart produces a new Ed25519 keypair,
    // causing TOFU dual-path MISMATCH on all peers (stale pin vs fresh key).
    auto existing = m_key_manager.load_key(m_node_id + "_ed25519_identity");
    if (existing && existing->private_key) {
        m_private_key = std::move(existing->private_key);
        m_public_key_pem = crypto::IdentityCore::get_pem_from_pubkey(m_private_key.get());
        std::cout << "[INFO] Node " << m_node_id << " loaded persistent Ed25519 identity." << std::endl;
    } else {
        m_private_key = crypto::IdentityCore::generate_ed25519_key();
        m_public_key_pem = crypto::IdentityCore::get_pem_from_pubkey(m_private_key.get());
        // Persist for future restarts
        crypto::UniquePKEY pub_dup(EVP_PKEY_dup(m_private_key.get()));
        crypto::UniquePKEY priv_dup(EVP_PKEY_dup(m_private_key.get()));
        if (pub_dup && priv_dup) {
            crypto::KeyPair kp(m_node_id + "_ed25519_identity",
                               std::move(pub_dup),
                               std::move(priv_dup),
                               crypto::KeyType::Ed25519);
            m_key_manager.store_key(kp);
        }
        std::cout << "[INFO] Node " << m_node_id << " generated new Ed25519 Node Identity." << std::endl;
    }
    m_public_key_b64 = base64_encode(m_public_key_pem);

    // Register self so self-votes pass verification
    m_pbft.register_peer_key(m_node_id, m_public_key_pem);

    // Enable enhanced PBFT features: identity, private key for signing, message chaining
    m_pbft.set_my_identity(m_node_id);
    // Duplicate the key for PBFT — MeshNode keeps its own copy for signing
    // discovery beacons and ANNOUNCE messages.  If dup fails (OOM), generate
    // a fresh key for PBFT so MeshNode's copy is never moved away.
    crypto::UniquePKEY pbft_key(EVP_PKEY_dup(m_private_key.get()));
    if (!pbft_key) {
        std::cerr << "[WARN] EVP_PKEY_dup failed, generating fresh PBFT key" << std::endl;
        pbft_key = crypto::IdentityCore::generate_ed25519_key();
    }
    m_pbft.set_private_key(std::move(pbft_key));

    // Load pre-provisioned peer keys from NEURO_PEER_KEYS env var.
    // Format: "ALPHA:<pem>,BRAVO:<pem>,CHARLIE:<pem>"
    // Pre-provisioned keys bypass TOFU — the peer's key is verified on arrival.
    if (const char* env = std::getenv("NEURO_PEER_KEYS")) {
        std::string env_str(env);
        std::istringstream iss(env_str);
        std::string entry;
        while (std::getline(iss, entry, ',')) {
            auto colon = entry.find(':');
            if (colon == std::string::npos) continue;
            std::string peer_id = entry.substr(0, colon);
            std::string pem = entry.substr(colon + 1);
            // Decode if base64-encoded (PEM contains newlines, often base64 in env)
            if (pem.find("-----BEGIN") == std::string::npos) {
                pem = base64_decode(pem).value_or(pem);
            }
            m_peer_manager.pre_provision_peer_key(peer_id, pem);
            m_pbft.register_peer_key(peer_id, pem);
            m_pbft.increment_peers();
            std::cout << "[INFO] Pre-provisioned peer key for " << peer_id << std::endl;
        }
    }

    // Initialize TLS infrastructure
    auto tls_key = m_key_manager.generate_key(crypto::KeyType::Ed25519, m_node_id + "_tls");
    if (tls_key) {
        m_key_manager.store_key(*tls_key);
        crypto::CertificateConfig cert_cfg;
        cert_cfg.common_name = m_node_id;
        cert_cfg.organization = "Neuro-Mesh";
        cert_cfg.is_server_auth = true;
        cert_cfg.is_client_auth = true;
        cert_cfg.validity_days = 7;
        auto cert = m_key_manager.generate_certificate(*tls_key, cert_cfg, "");
        if (cert) {
            m_key_manager.store_certificate(*cert);
            m_tls_cert_path = "./keystore_" + m_node_id + "/certs/" + cert->key_id + ".crt";
            m_tls_key_path = "./keystore_" + m_node_id + "/" + tls_key->key_id + ".pem";
        }
    }

    m_tls_config.cert_path = m_tls_cert_path;
    m_tls_config.key_path = m_tls_key_path;
    m_tls_config.ca_path = m_tls_cert_path;  // Self-signed cert acts as its own CA
    m_tls_config.verify_client = true;
    m_tls_config.enable_tls13 = true;
    m_tls_config.enable_mtls = true;

    // Compute TLS cert fingerprint for TOFU verification
    if (!m_tls_cert_path.empty()) {
        std::ifstream cert_file(m_tls_cert_path);
        if (cert_file.is_open()) {
            std::string cert_pem((std::istreambuf_iterator<char>(cert_file)),
                                 std::istreambuf_iterator<char>());
            m_tls_cert_pem = cert_pem;
            m_tls_cert_fingerprint = crypto::IdentityCore::sha256_hex(cert_pem);
            std::cout << "[TLS] Cert fingerprint: " << m_tls_cert_fingerprint.substr(0, 16) << "..." << std::endl;
        }
    }

    net::DiscoveryConfig disc_cfg;
    disc_cfg.beacon_port = DISCOVERY_UDP_PORT;
    m_discovery = std::make_unique<net::PeerDiscovery>(disc_cfg, m_node_id, m_public_key_pem);

    try {
        m_transport = std::make_unique<net::TransportLayer>(m_tls_config);
    } catch (const std::exception& e) {
        std::cerr << "[TLS] TransportLayer init failed: " << e.what()
                  << " — falling back to UDP only." << std::endl;
    }

    // Initialize persistent broadcast sockets (reused for all UDP sends)
    m_broadcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_broadcast_fd >= 0) {
        int one = 1;
        setsockopt(m_broadcast_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    } else {
        std::cerr << "[WARN] Failed to create broadcast socket — UDP broadcast disabled." << std::endl;
    }
    m_discovery_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_discovery_fd >= 0) {
        int one = 1;
        setsockopt(m_discovery_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    }
    m_discovery6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (m_discovery6_fd >= 0) {
        struct ipv6_mreq mreq{};
        inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = 0;
        setsockopt(m_discovery6_fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                   &mreq.ipv6mr_interface, sizeof(mreq.ipv6mr_interface));
    }

    m_discovery_mcast_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_discovery_mcast_fd >= 0) {
        int one = 1;
        setsockopt(m_discovery_mcast_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
        struct ip_mreqn mreq{};
        inet_pton(AF_INET, "239.255.255.250", &mreq.imr_multiaddr);
        mreq.imr_address.s_addr = INADDR_ANY;
        mreq.imr_ifindex = 0;
        setsockopt(m_discovery_mcast_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    }

    std::cout << "[DEFENSE] Elite PBFT initialized with equivocation detection and timing obfuscation." << std::endl;
    std::cout << "[TLS] Transport layer ready. Cert/key stored for " << m_node_id << "." << std::endl;
    std::cout << "[JOURNAL] Initialized. Last seq: " << m_journal.last_seq() << std::endl;
}

MeshNode::~MeshNode() {
    stop();
}

// =============================================================================
// Start / Stop — manages all 4 background threads
// =============================================================================

void MeshNode::start() {
    if (m_running) return;
    m_running = true;

    m_listener_thread  = std::thread(&MeshNode::p2p_listener_loop, this);
    m_discovery_thread = std::thread(&MeshNode::discovery_beacon_loop, this);
    m_tcp_thread       = std::thread(&MeshNode::tcp_listener_loop, this);
    m_tls_thread       = std::thread(&MeshNode::tls_acceptor_loop, this);
    m_liveness_thread  = std::thread(&MeshNode::liveness_monitor, this);
    m_tls_worker_thread = std::thread(&MeshNode::tls_worker_loop, this);

    if (m_discovery) m_discovery->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    announce_identity();
}

void MeshNode::stop() {
    m_running = false;
    m_tls_queue_cv.notify_one();
    if (m_discovery) m_discovery->stop();
    if (m_transport) m_transport->shutdown();
    if (m_listener_thread.joinable())  m_listener_thread.join();
    if (m_discovery_thread.joinable()) m_discovery_thread.join();
    if (m_tcp_thread.joinable())       m_tcp_thread.join();
    if (m_tls_thread.joinable())       m_tls_thread.join();
    if (m_liveness_thread.joinable())  m_liveness_thread.join();
    if (m_tls_worker_thread.joinable()) m_tls_worker_thread.join();
    if (m_broadcast_fd >= 0) { ::close(m_broadcast_fd); m_broadcast_fd = -1; }
    if (m_discovery_fd >= 0)  { ::close(m_discovery_fd);  m_discovery_fd = -1; }
    if (m_discovery6_fd >= 0) { ::close(m_discovery6_fd); m_discovery6_fd = -1; }
    if (m_discovery_mcast_fd >= 0) { ::close(m_discovery_mcast_fd); m_discovery_mcast_fd = -1; }
}

int MeshNode::peer_count() const {
    return m_peer_manager.peer_count() + 1;  // +1 for self
}

std::vector<std::string> MeshNode::get_active_peer_ids() const {
    return m_peer_manager.get_all_peer_ids();
}

// =============================================================================
// Identity announcement (UDP broadcast — legacy + discovery compatible)
// =============================================================================

void MeshNode::announce_identity() {
    // Sign the ANNOUNCE blob for TOFU verification
    std::string signed_blob = m_node_id + "|" + m_public_key_pem;
    std::string raw_sig = crypto::IdentityCore::sign_payload(m_private_key.get(), signed_blob);
    std::string b64_sig = base64_encode(raw_sig);

    // ANNOUNCE|node_id|pem|b64_signature
    std::string payload = "ANNOUNCE|" + m_node_id + "|" + m_public_key_pem + "|" + b64_sig;
    send_udp_broadcast(payload);
    std::cout << "[NETWORK] Broadcasted signed identity to local subnet." << std::endl;
}

// =============================================================================
// Discovery Beacon — signed heartbeat broadcast every HEARTBEAT_SEC
// =============================================================================

void MeshNode::send_discovery_beacon() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    auto us = duration_cast<microseconds>(now.time_since_epoch()).count();

    // V3: include the full TLS cert PEM in the signed blob so peers can
    // add it to their OpenSSL trust store. Without the PEM, peers only get
    // the fingerprint — useless for X509 verification. The signature
    // binds (node_id|tcp_port|tls_port|timestamp|tls_fingerprint|cert_pem)
    // so an attacker can't swap the cert for one with the same fingerprint
    // (impossible by hash collision, but defense in depth).
    std::string b64_cert_pem = base64_encode(m_tls_cert_pem);

    std::string signed_blob = m_node_id + "|" + std::to_string(m_tcp_port) + "|"
                            + std::to_string(m_tls_port) + "|" + std::to_string(us) + "|"
                            + m_tls_cert_fingerprint + "|"
                            + b64_cert_pem;
    std::string raw_sig = crypto::IdentityCore::sign_payload(m_private_key.get(), signed_blob);
    std::string b64_sig = base64_encode(raw_sig);

    // Packet: DISCOVERY|<node_id>|<tcp_port>|<tls_port>|<timestamp_us>|<b64_pubkey>|<tls_fingerprint>|<b64_tls_cert_pem>|<b64_sig>
    std::string payload = "DISCOVERY|" + m_node_id + "|"
                        + std::to_string(m_tcp_port) + "|"
                        + std::to_string(m_tls_port) + "|"
                        + std::to_string(us) + "|"
                        + m_public_key_b64 + "|"
                        + m_tls_cert_fingerprint + "|"
                        + b64_cert_pem + "|"
                        + b64_sig;

    send_udp_discovery(payload);

    // Unicast to seed peers for cross-subnet / cloud-VPC environments
    if (!m_seed_peers.empty()) {
        for (const auto& [ip, port] : m_seed_peers) {
            send_udp_unicast(ip, port, payload);
        }
    }
}

void MeshNode::discovery_beacon_loop() {
    // Wait for TCP listener to bind first (need m_tcp_port set)
    for (int i = 0; i < 50 && m_tcp_port == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (m_tcp_port == 0) {
        std::cerr << "[DISCOVERY] TCP port not assigned — beaconing disabled." << std::endl;
        return;
    }

    std::cout << "[DISCOVERY] Beaconing every " << HEARTBEAT_SEC
              << "s on UDP:" << DISCOVERY_UDP_PORT
              << " (TCP PEX port " << m_tcp_port << ")" << std::endl;

    while (m_running) {
        // Phase 3: drain auto-banned peers and propose cross-node BAN_PEER rounds.
        for (const auto& banned_id : m_pbft.drain_recent_bans()) {
            propose_ban(banned_id, "local_auto_ban");
        }
        send_discovery_beacon();
        for (int i = 0; i < HEARTBEAT_SEC && m_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// =============================================================================
// UDP transport helpers
// =============================================================================

// Configurable UDP jitter via env vars. Default: 0 (no jitter) for production.
// Set NEURO_UDP_JITTER_MIN/MAX to enable timing obfuscation.
static std::pair<int, int> get_udp_jitter(const char* env_min, const char* env_max,
                                            int default_min, int default_max) {
    const char* min_env = std::getenv(env_min);
    const char* max_env = std::getenv(env_max);
    int min_val = default_min;
    int max_val = default_max;
    if (min_env) {
        char* end = nullptr;
        long v = std::strtol(min_env, &end, 10);
        if (*end == '\0' && v >= 0) min_val = static_cast<int>(v);
    }
    if (max_env) {
        char* end = nullptr;
        long v = std::strtol(max_env, &end, 10);
        if (*end == '\0' && v >= 0) max_val = static_cast<int>(v);
    }
    return {min_val, max_val};
}

void MeshNode::send_udp_broadcast(const std::string& payload) {
    auto [jmin, jmax] = get_udp_jitter("NEURO_UDP_JITTER_MIN", "NEURO_UDP_JITTER_MAX", 0, 0);
    if (jmax > jmin) {
        static thread_local std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<> dis(jmin, jmax);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    if (m_broadcast_fd < 0) return;

    struct sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(m_udp_port);
    inet_pton(AF_INET, "255.255.255.255", &broadcast_addr.sin_addr);

    ssize_t sent = sendto(m_broadcast_fd, payload.c_str(), payload.length(), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
    if (sent < 0) {
        std::cerr << "[NETWORK] UDP broadcast sendto failed: " << strerror(errno) << std::endl;
    }
}

void MeshNode::send_udp_discovery(const std::string& payload) {
    auto [jmin, jmax] = get_udp_jitter("NEURO_DISCOVERY_JITTER_MIN", "NEURO_DISCOVERY_JITTER_MAX", 0, 0);
    if (jmax > jmin) {
        static thread_local std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<> dis(jmin, jmax);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    if (m_discovery_fd >= 0) {
        struct sockaddr_in broadcast_addr{};
        broadcast_addr.sin_family = AF_INET;
        broadcast_addr.sin_port = htons(DISCOVERY_UDP_PORT);
        inet_pton(AF_INET, "255.255.255.255", &broadcast_addr.sin_addr);

        ssize_t sent = sendto(m_discovery_fd, payload.c_str(), payload.length(), 0,
               (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        if (sent < 0) {
            std::cerr << "[NETWORK] Discovery sendto (v4) failed: " << strerror(errno) << std::endl;
        }
    }

    // IPv4 multicast discovery — fallback for netns/docker where
    // 255.255.255.255 broadcast may lack a route. Uses SSDP group
    // (239.255.255.250) which transits bridges without per-hop routing.
    if (m_discovery_mcast_fd >= 0) {
        struct sockaddr_in mcast_addr{};
        mcast_addr.sin_family = AF_INET;
        mcast_addr.sin_port = htons(DISCOVERY_UDP_PORT);
        inet_pton(AF_INET, "239.255.255.250", &mcast_addr.sin_addr);
        sendto(m_discovery_mcast_fd, payload.c_str(), payload.length(), 0,
               (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
        // Best-effort; failure is not fatal.
    }

    // IPv6 multicast discovery (ff02::1 = all-nodes link-local)
    if (m_discovery6_fd >= 0) {
        struct sockaddr_in6 mcast_addr{};
        mcast_addr.sin6_family = AF_INET6;
        mcast_addr.sin6_port = htons(DISCOVERY_UDP_PORT);
        struct ipv6_mreq mreq{};
        inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr);
        mcast_addr.sin6_addr = mreq.ipv6mr_multiaddr;
        ssize_t sent = sendto(m_discovery6_fd, payload.c_str(), payload.length(), 0,
               (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
        if (sent < 0) {
            std::cerr << "[NETWORK] Discovery sendto (v6) failed: " << strerror(errno) << std::endl;
        }
    }
}

void MeshNode::send_udp_unicast(const std::string& ip, int port, const std::string& payload) {
    auto [jmin, jmax] = get_udp_jitter("NEURO_UNICAST_JITTER_MIN", "NEURO_UNICAST_JITTER_MAX", 0, 0);
    if (jmax > jmin) {
        static thread_local std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<> dis(jmin, jmax);
        std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
    }

    if (m_broadcast_fd < 0) return;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    struct in_addr inaddr;
    if (inet_pton(AF_INET, ip.c_str(), &inaddr) != 1) return;
    addr.sin_addr = inaddr;

    ssize_t sent = sendto(m_broadcast_fd, payload.c_str(), payload.length(), 0,
           (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0) {
        std::cerr << "[NETWORK] Unicast sendto failed: " << strerror(errno) << std::endl;
    }
}

// =============================================================================
// PBFT Consensus UDP listener (port 9999)
// =============================================================================

void MeshNode::p2p_listener_loop() {
    UniqueFD sockfd{socket(AF_INET, SOCK_DGRAM, 0)};
    if (!sockfd.valid()) return;

    int opt = 1;
    setsockopt(sockfd.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(m_udp_port);

    if (bind(sockfd.get(), (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "[FATAL] P2P Bind Failed on port " << m_udp_port << std::endl;
        return;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Also listen for discovery beacons on this socket if DISCOVERY_UDP_PORT
    // differs. We need a separate discovery socket.
    int disc_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (disc_sock >= 0) {
        int reuse = 1;
        setsockopt(disc_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in disc_addr{};
        disc_addr.sin_family = AF_INET;
        disc_addr.sin_addr.s_addr = INADDR_ANY;
        disc_addr.sin_port = htons(DISCOVERY_UDP_PORT);
        if (bind(disc_sock, (struct sockaddr*)&disc_addr, sizeof(disc_addr)) < 0) {
            close(disc_sock);
            disc_sock = -1;
        } else {
            // Drain any leftover UDP packets from previous container runs.
            // Without this, stale beacons with old timestamps can poison discovery.
            struct timeval drain_tv;
            drain_tv.tv_sec = 1;
            drain_tv.tv_usec = 0;
            setsockopt(disc_sock, SOL_SOCKET, SO_RCVTIMEO, &drain_tv, sizeof(drain_tv));
            char junk[4096];
            while (recvfrom(disc_sock, junk, sizeof(junk), 0, nullptr, nullptr) > 0) {}
            // Restore the normal timeout
            struct timeval dtv;
            dtv.tv_sec = 1;
            dtv.tv_usec = 0;
            setsockopt(disc_sock, SOL_SOCKET, SO_RCVTIMEO, &dtv, sizeof(dtv));
        }
    }

    char buffer[65536];
    while (m_running) {
        // Poll PBFT consensus socket
        struct sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd.get(), buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&cliaddr, &len);

        if (n > 0) {
            buffer[n] = '\0';
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &cliaddr.sin_addr, addr_str, sizeof(addr_str));
            process_message(std::string(buffer), addr_str);
        }

        // Poll discovery socket — drain ALL queued datagrams, not just one.
        // Combined DISCOVERY + TELEMETRY traffic exceeds 1 msg/sec, so a
        // single recvfrom() per iteration creates unbounded backlog.
        if (disc_sock >= 0) {
            for (;;) {
                if (!m_running) break;
                struct sockaddr_in daddr{};
                socklen_t dlen = sizeof(daddr);
                int dn = recvfrom(disc_sock, buffer, sizeof(buffer) - 1,
                                  MSG_DONTWAIT, (struct sockaddr*)&daddr, &dlen);
                if (dn <= 0) break;
                buffer[dn] = '\0';

                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &daddr.sin_addr, addr_str, sizeof(addr_str));

                // Per-source-IP rate limiting to prevent CPU exhaustion
                // from forged UDP datagrams (BUG-06 fix).
                if (!m_peer_manager.check_rate_limit(addr_str)) continue;

                std::string dmsg(buffer);
                if (dmsg.rfind("TELEMETRY|", 0) == 0) {
                    process_telemetry_gossip(dmsg, addr_str);
                } else {
                    process_discovery_beacon(dmsg, addr_str);
                }
            }
        }
    }

    if (disc_sock >= 0) close(disc_sock);
}

// =============================================================================
// TCP PEX Listener — accepts handshake connections from peers
// =============================================================================

void MeshNode::tcp_listener_loop() {
    // Auto-bind to first available TCP port starting at TCP_PORT_START
    int listen_fd = -1;
    int active_connections = 0;
    constexpr int MAX_ACTIVE_CONNS = 64;
    constexpr int MAX_ACCEPT_RATE = 20;
    auto rate_window_start = std::chrono::steady_clock::now();
    int accept_count = 0;
    int port = TCP_PORT_START;
    constexpr int MAX_PORT = TCP_PORT_START + 100;

    for (; port < MAX_PORT; ++port) {
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) continue;

        int reuse = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(static_cast<uint16_t>(port));

        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            break;  // success
        }
        close(listen_fd);
        listen_fd = -1;
    }

    if (listen_fd < 0) {
        std::cerr << "[PEX] Failed to bind TCP port in range "
                  << TCP_PORT_START << "-" << MAX_PORT << std::endl;
        return;
    }

    m_tcp_port = port;

    if (listen(listen_fd, 8) < 0) {
        std::cerr << "[PEX] listen() failed on TCP port " << port << std::endl;
        close(listen_fd);
        return;
    }

    std::cout << "[PEX] TCP handshake listener bound to port " << port << std::endl;

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    while (m_running) {
        // Rate limiting: max N accepts per second
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - rate_window_start).count();
        if (elapsed >= 1) {
            rate_window_start = now;
            accept_count = 0;
        }
        if (accept_count >= MAX_ACCEPT_RATE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        if (active_connections >= MAX_ACTIVE_CONNS) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(listen_fd + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        int client = accept(listen_fd, nullptr, nullptr);
        if (client < 0) continue;
        ++accept_count;
        ++active_connections;

        // Set timeouts on accepted socket to prevent slow-peer DoS.
        struct timeval client_tv;
        client_tv.tv_sec = 5;
        client_tv.tv_usec = 0;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &client_tv, sizeof(client_tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &client_tv, sizeof(client_tv));

        // Read PEX message
        char buf[8192];
        ssize_t nr = read(client, buf, sizeof(buf) - 1);
        if (nr > 0) {
            buf[nr] = '\0';
            std::string msg(buf);
            // Format: PEX|<sender_id>|<peer_count>|<peer_list>
            // peer_list: id1:ip1:port1,id2:ip2:port2,...
            auto tokens = split_string(msg, '|');
            if (tokens.size() >= 4 && tokens[0] == "PEX") {
                const std::string& peer_list = tokens[3];

                // Send our peer list back
                std::ostringstream reply;
                reply << "PEX|" << m_node_id << "|";
                {
                    auto peers = m_peer_manager.get_all_peers();
                    reply << peers.size() << "|";
                    bool first = true;
                    for (const auto& entry : peers) {
                        if (!first) reply << ",";
                        reply << entry.node_id << ":" << entry.ip << ":" << entry.tcp_port;
                        first = false;
                    }
                }
                std::string reply_str = reply.str();
                ssize_t unused = write(client, reply_str.c_str(), reply_str.size());
                (void)unused;

                // Parse their peer list and add new ones (PEX acceleration)
                if (!peer_list.empty() && peer_list != "0") {
                    auto entries = split_string(peer_list, ',');
                    for (const auto& entry : entries) {
                        auto parts = split_string(entry, ':');
                        if (parts.size() >= 3) {
                            const std::string& pid = parts[0];
                            const std::string& pip = parts[1];
                            int pport = 0;
                            if (!try_parse_int(parts[2], pport)) continue;
                            if (pid != m_node_id) {
                                bool is_new = m_peer_manager.add_peer(pid, pip, pport, 0, "");
                                if (is_new) {
                                    // Initiate PEX back to this newly discovered peer
                                    perform_pex_handshake(pip, pport, pid);
                                }
                            }
                        }
                    }
                }
            }
        }
        close(client);
        --active_connections;
    }

    close(listen_fd);
}

// =============================================================================
// PEX Handshake — TCP connect to a discovered peer, exchange peer lists
// =============================================================================

bool MeshNode::perform_pex_handshake(const std::string& ip, int port,
                                      const std::string& expected_peer_id) {
    // Validate peer_id against known peers - prevent IP spoofing
    if (!expected_peer_id.empty() && m_peer_manager.has_peer(expected_peer_id)) {
        auto entry = m_peer_manager.get_peer(expected_peer_id);
        if (entry.ip != ip && !entry.ip.empty()) {
            std::cerr << "[PEX] REJECTED: IP mismatch for " << expected_peer_id
                      << " (expected " << entry.ip << ", got " << ip << ")" << std::endl;
            return false;
        }
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    struct in_addr inaddr;
    if (inet_pton(AF_INET, ip.c_str(), &inaddr) != 1) {
        close(sock);
        return false;
    }
    addr.sin_addr = inaddr;

    // 2-second connect timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    // Build our peer list
    std::ostringstream hello;
    hello << "PEX|" << m_node_id << "|";
    {
        auto peers = m_peer_manager.get_all_peers();
        hello << peers.size() << "|";
        bool first = true;
        for (const auto& entry : peers) {
            if (!first) hello << ",";
            hello << entry.node_id << ":" << entry.ip << ":" << entry.tcp_port;
            first = false;
        }
    }
    std::string hello_str = hello.str();
    ssize_t unused = write(sock, hello_str.c_str(), hello_str.size());
    (void)unused;

    // Read response
    char buf[8192];
    ssize_t nr = read(sock, buf, sizeof(buf) - 1);
    close(sock);

    if (nr <= 0) return false;
    buf[nr] = '\0';
    std::string resp(buf);

    auto tokens = split_string(resp, '|');
    if (tokens.size() < 4 || tokens[0] != "PEX") return false;

    const std::string& peer_list = tokens[3];
    if (peer_list.empty() || peer_list == "0") return true;  // no peers to add

    auto entries = split_string(peer_list, ',');
    for (const auto& entry : entries) {
        auto parts = split_string(entry, ':');
        if (parts.size() >= 3) {
            const std::string& pid = parts[0];
            const std::string& pip = parts[1];
            int pport = 0;
            if (!try_parse_int(parts[2], pport)) continue;
            if (pid != m_node_id) {
                m_peer_manager.add_peer(pid, pip, pport, 0, "");
            }
        }
    }

    return true;
}

// =============================================================================
// Discovery Beacon Processing — verifies signature, adds peer, triggers PEX
// =============================================================================

void MeshNode::process_discovery_beacon(const std::string& msg, const std::string& sender_ip) {
    auto tokens = split_string(msg, '|');
    // Accept formats:
    // - Old: 6 tokens (no TLS fingerprint)
    // - V1: 7 tokens (with TLS fingerprint, no signature bind)
    // - V2: 8 tokens (with TLS fingerprint, signature includes fingerprint)
    // - V3: 9 tokens (with TLS cert PEM, signature includes PEM) — current
    if (tokens[0] != "DISCOVERY") return;

    bool has_tls_fingerprint = tokens.size() >= 7;
    bool has_signed_fpr = tokens.size() >= 8;
    bool has_cert_pem  = tokens.size() >= 9;
    if (tokens.size() < 6) return;

    const std::string& peer_id   = tokens[1];
    int peer_tcp_port  = 0;
    int peer_tls_port  = 0;
    int64_t timestamp  = 0;
    if (!try_parse_int(tokens[2], peer_tcp_port)) return;
    if (has_tls_fingerprint && !try_parse_int(tokens[3], peer_tls_port)) return;
    if (!try_parse_long(tokens[has_tls_fingerprint ? 4 : 3], timestamp)) return;
    const std::string& b64_pubkey = tokens[has_tls_fingerprint ? 5 : 4];
    const std::string& tls_fingerprint = has_tls_fingerprint ? tokens[6] : "";
    const std::string& b64_cert_pem = has_cert_pem ? tokens[7] : "";
    const std::string& b64_sig   = has_cert_pem ? tokens[8]
                                : (has_signed_fpr ? tokens[7] : "");

    if (peer_id == m_node_id) return;

    // Decode public key
    std::string peer_pem = base64_decode(b64_pubkey).value_or("");
    if (peer_pem.empty()) return;

    // Verify signature: bind(node_id|tcp_port|tls_port|timestamp|[tls_fpr][|cert_pem])
    std::string signed_blob;
    if (has_cert_pem) {
        // V3 format: signature includes TLS fingerprint AND cert PEM
        signed_blob = peer_id + "|" + std::to_string(peer_tcp_port) + "|"
                    + std::to_string(peer_tls_port) + "|" + std::to_string(timestamp) + "|"
                    + tls_fingerprint + "|" + b64_cert_pem;
    } else if (has_tls_fingerprint && tokens.size() >= 8) {
        // V2 format: signature includes TLS fingerprint
        signed_blob = peer_id + "|" + std::to_string(peer_tcp_port) + "|"
                    + std::to_string(peer_tls_port) + "|" + std::to_string(timestamp) + "|"
                    + tls_fingerprint;
    } else if (has_tls_fingerprint) {
        // V1 format: no signature binding for TLS fingerprint
        signed_blob = peer_id + "|" + std::to_string(peer_tcp_port) + "|"
                    + std::to_string(peer_tls_port) + "|" + std::to_string(timestamp);
    } else {
        // Old format
        signed_blob = peer_id + "|" + std::to_string(timestamp);
    }
    std::string raw_sig = base64_decode(b64_sig).value_or("");
    if (raw_sig.empty()) return;

    auto pubkey = crypto::IdentityCore::get_pubkey_from_pem(peer_pem);
    if (!pubkey) return;

    if (!crypto::IdentityCore::verify_signature(pubkey.get(), signed_blob, raw_sig)) {
        std::cerr << "[DISCOVERY] Signature verification FAILED for " << peer_id << std::endl;
        return;
    }

    // Anti-spoofing: check timestamp is within ±30s of now
    using namespace std::chrono;
    auto now_us = duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
    int64_t drift = (now_us - timestamp) / 1'000'000;
    if (drift > 60 || drift < -60) {
        std::cerr << "[DISCOVERY] Stale beacon from " << peer_id
                  << " (drift=" << drift << "s). Ignored." << std::endl;
        return;
    }

    // TOFU: Store/update TLS cert fingerprint
    if (has_tls_fingerprint && !tls_fingerprint.empty()) {
        if (!m_peer_manager.verify_tls_cert(peer_id, tls_fingerprint)) {
            std::cerr << "[DEFENSE] TLS cert MISMATCH for " << peer_id
                      << " — possible MITM. Use unpin_peer_key() to reset." << std::endl;
            return;
        }
        m_peer_manager.pin_tls_fingerprint(peer_id, tls_fingerprint);
        std::cout << "[TOFU] Pinned TLS cert for " << peer_id << ": " << tls_fingerprint.substr(0, 16) << "..." << std::endl;
    }

    std::string sender_ip_copy = sender_ip;
    std::string peer_id_copy = peer_id;
    std::string peer_pem_copy = peer_pem;

    // add_peer() does atomic check+add under one lock — eliminates TOCTOU race
    // where two concurrent beacons from the same peer both see is_new=true.
    bool is_new = m_peer_manager.add_peer(peer_id, sender_ip, peer_tcp_port, peer_tls_port, peer_pem);

    // Dual-path TOFU: confirm beacon path and check if both paths agree.
    auto confirm = m_peer_manager.confirm_path(peer_id, PeerEntry::PATH_BEACON, peer_pem);
    if (confirm.key_mismatch) {
        std::cerr << "[SECURITY] TOFU dual-path MISMATCH for " << peer_id
                  << " via beacon — rejecting peer." << std::endl;
        return;
    }

    if (!is_new) {
        bool key_rejected = false;
        {
            auto existing = m_peer_manager.get_peer(peer_id);
            if (!peer_pem.empty() && !existing.public_key_pem.empty()
                && existing.public_key_pem != peer_pem) {
                std::cerr << "[SECURITY] TOFU key change REJECTED for " << peer_id
                          << " — use unpin_peer_key() to allow rotation." << std::endl;
                key_rejected = true;
            }
        }
        if (!key_rejected) {
            m_peer_manager.update_peer_heartbeat(peer_id, sender_ip, peer_tcp_port, peer_tls_port, peer_pem);
        }
    }

    if (is_new || confirm.dual_confirmed) {
        if (is_new) {
            std::cout << "[NETWORK] Verified peer " << peer_id_copy
                      << " at " << sender_ip_copy << ":" << peer_tcp_port
                      << " (TLS:" << peer_tls_port << ")"
                      << ". Quorum updated to n=" << peer_count() << "." << std::endl;
        }

        // Register key with PBFT only when BOTH discovery paths confirm the same key.
        // This prevents identity hijack via TOFU race — an attacker must compromise
        // both UDP beacon AND TCP ANNOUNCE simultaneously.
        if (confirm.dual_confirmed && !m_pbft.has_peer(peer_id_copy)) {
            m_pbft.register_peer_key(peer_id_copy, peer_pem_copy);
            m_pbft.increment_peers();
            std::cout << "[TOFU] Dual-path confirmed for " << peer_id_copy
                      << " — registered with PBFT." << std::endl;

            // V3: add the peer's TLS cert to OpenSSL's trust store. Without
            // this, every mTLS handshake fails with "unknown ca" because
            // the cert store only contains our own self-signed cert. The
            // PEM is signed by the peer's Ed25519 identity key inside the
            // discovery beacon — a true cryptographic pin.
            if (has_cert_pem && !b64_cert_pem.empty() && m_transport) {
                std::string peer_cert_pem = base64_decode(b64_cert_pem).value_or("");
                if (!peer_cert_pem.empty() && m_transport->trust_peer_cert(peer_cert_pem)) {
                    std::cout << "[TLS] Trusted peer cert for " << peer_id_copy
                              << " (added to OpenSSL store, " << peer_cert_pem.size()
                              << " bytes)." << std::endl;
                }
            }
        }

        if (m_enforcer) m_enforcer->register_peer_ip(peer_id_copy, sender_ip_copy);
        if (m_enforcer && peer_tcp_port > 0) m_enforcer->register_peer_port(peer_id_copy, peer_tcp_port);

        // Initiate PEX handshake to exchange peer lists (O(log N) discovery)
        // Add random jitter to reduce race condition when two peers discover each other simultaneously
        {
            static thread_local std::mt19937 pex_gen{std::random_device{}()};
            std::uniform_int_distribution<> pex_delay(50, 300);
            std::this_thread::sleep_for(std::chrono::milliseconds(pex_delay(pex_gen)));
            if (m_peer_manager.has_peer(peer_id_copy)) {
                perform_pex_handshake(sender_ip_copy, peer_tcp_port, peer_id_copy);
            }
        }

        // Queue TLS connection task for worker thread (replaces detached thread)
        if (peer_tls_port > 0 && m_transport) {
            std::lock_guard<std::mutex> lock(m_tls_queue_mtx);
            m_tls_connect_queue.push_back({peer_id_copy, sender_ip_copy, peer_tls_port});
            m_tls_queue_cv.notify_one();
        }
    }
}

// =============================================================================
// Telemetry Gossip — decentralizes the control plane
// =============================================================================

void MeshNode::gossip_telemetry(const std::string& telemetry_json) {
    m_peer_manager.set_own_telemetry(telemetry_json);

    std::string unsigned_msg = "TELEMETRY|" + m_node_id + "|" + telemetry_json;
    std::string raw_sig = crypto::IdentityCore::sign_payload(m_private_key.get(), unsigned_msg);
    std::string b64_sig = base64_encode(raw_sig);
    // Signature BEFORE json — base64 cannot contain '|', so the third delimiter
    // unambiguously separates sig from json (which may contain '|').
    std::string msg = "TELEMETRY|" + m_node_id + "|" + b64_sig + "|" + telemetry_json;

    // Broadcast on discovery port — all nodes share this port via SO_REUSEADDR.
    // Broadcast delivers to ALL bound sockets; unicast would hit only one.
    send_udp_discovery(msg);

    // Also push own telemetry to local bridge so dashboard sees this node
    if (m_bridge) {
        (void)m_bridge->push_telemetry(telemetry_json);
    }
}

void MeshNode::gossip_event_json(const std::string& json) {
    // Broadcast arbitrary event JSON to all peers via discovery.
    // Unlike gossip_telemetry, this does NOT overwrite m_own_telemetry.
    // Format: TELEMETRY|<m_node_id>|<b64_signature>|<json>
    std::string unsigned_msg = "TELEMETRY|" + m_node_id + "|" + json;
    std::string raw_sig = crypto::IdentityCore::sign_payload(m_private_key.get(), unsigned_msg);
    std::string b64_sig = base64_encode(raw_sig);
    std::string msg = "TELEMETRY|" + m_node_id + "|" + b64_sig + "|" + json;
    send_udp_discovery(msg);

    // Also push to local bridge so locally-connected dashboards see it
    if (m_bridge) {
        (void)m_bridge->push_telemetry(json);
    }
}

void MeshNode::process_telemetry_gossip(const std::string& msg, const std::string& /*sender_ip*/) {
    // Format: TELEMETRY|<node_id>|<b64_signature>|<json>
    // Signature comes BEFORE json — base64 cannot contain '|', so the
    // third delimiter unambiguously separates sig from json.
    size_t first_delim = msg.find('|');
    if (first_delim == std::string::npos) return;
    size_t second_delim = msg.find('|', first_delim + 1);
    if (second_delim == std::string::npos) return;

    std::string peer_id = msg.substr(first_delim + 1, second_delim - first_delim - 1);
    if (peer_id.empty() || peer_id == m_node_id) return;
    if (peer_id.size() > 64) return;

    // Extract signature and json
    size_t third_delim = msg.find('|', second_delim + 1);
    std::string json;
    std::string b64_sig;
    if (third_delim == std::string::npos) {
        // Unsigned (legacy) — accept but do not verify
        json = msg.substr(second_delim + 1);
    } else {
        b64_sig = msg.substr(second_delim + 1, third_delim - second_delim - 1);
        json = msg.substr(third_delim + 1);
    }

    // Verify signature if present
    if (!b64_sig.empty()) {
        std::string peer_pem = m_peer_manager.get_peer_key(peer_id);
        if (peer_pem.empty()) {
            // Signed message from unknown peer — reject to prevent spoofing.
            // Only unsigned (legacy) telemetry is accepted from unregistered peers.
            std::cerr << "[TELEMETRY] Signed message from unregistered peer " << peer_id
                      << " — rejected. Complete peer discovery first." << std::endl;
            return;
        }
        auto pubkey = crypto::IdentityCore::get_pubkey_from_pem(peer_pem);
        if (pubkey) {
            std::string unsigned_msg = "TELEMETRY|" + peer_id + "|" + json;
            std::string raw_sig = base64_decode(b64_sig).value_or("");
            if (!raw_sig.empty() &&
                !crypto::IdentityCore::verify_signature(pubkey.get(), unsigned_msg, raw_sig)) {
                std::cerr << "[TELEMETRY] Signature verification FAILED for " << peer_id << std::endl;
                return;
            }
        }
    }

    m_peer_manager.set_peer_telemetry(peer_id, json);

    // Push to local bridge so dashboard sees this peer
    if (m_bridge) {
        (void)m_bridge->push_telemetry(json);
    }
}

std::string MeshNode::get_mesh_telemetry() const {
    return m_peer_manager.get_all_telemetry();
}

// =============================================================================
// Message validation — reject malformed/attacker-controlled input
// =============================================================================

bool MeshNode::validate_message(const std::string& msg) const {
    // Size bounds
    if (msg.empty() || msg.size() > 65536) return false;
    // Reject null bytes (corrupted/attack)
    if (msg.find('\0') != std::string::npos) return false;
    // Reject control chars except delimiters | \n \r
    for (char c : msg) {
        if (c < 32 && c != '|' && c != '\n' && c != '\r') return false;
    }
    return true;
}

// =============================================================================
// Message processing (consensus port)
// =============================================================================

void MeshNode::process_message(const std::string& msg, const std::string& sender_ip) {
    // ---- Rate limit FIRST ----
    // Without this ordering, an adversarial peer sending invalid messages
    // bypasses the rate limiter and floods stderr with "Invalid message
    // rejected" logs at line rate (Belt-and-suspenders with the discovery
    // socket which already rate-limits; the consensus port does not).
    if (!m_peer_manager.check_rate_limit(sender_ip)) return;

    // ---- Input validation ----
    if (!validate_message(msg)) {
        std::cerr << "[DEFENSE] Invalid message rejected from " << sender_ip << std::endl;
        return;
    }

    std::vector<std::string> tokens = split_string(msg, '|');
    if (tokens.size() < 3) return;

    const std::string& cmd = tokens[0];

    if (cmd == "ANNOUNCE") {
        // ANNOUNCE|node_id|pem|b64_signature
        if (tokens.size() < 4) {
            std::cerr << "[DEFENSE] ANNOUNCE: malformed (too few tokens) from " << sender_ip << std::endl;
            return;
        }
        const std::string& peer_id = tokens[1];
        const std::string& peer_pem = tokens[2];
        const std::string& sig_b64 = tokens[3];

        // Input validation: reject malformed announcements
        if (peer_id.empty() || peer_id.size() > 64) return;
        if (peer_pem.empty() || peer_pem.find("-----BEGIN PUBLIC KEY-----") == std::string::npos) return;
        if (peer_id == m_node_id) return;

        // === TOFU: Verify signature or accept first-time ===
        std::string decoded_sig = base64_decode(sig_b64).value_or("");
        if (decoded_sig.empty()) {
            std::cerr << "[DEFENSE] ANNOUNCE: invalid signature from " << peer_id << std::endl;
            return;
        }

        // Verify the signature
        auto pub_key = crypto::IdentityCore::get_pubkey_from_pem(peer_pem);
        if (!pub_key) {
            std::cerr << "[DEFENSE] ANNOUNCE: invalid public key from " << peer_id << std::endl;
            return;
        }

        std::string signed_blob = peer_id + "|" + peer_pem;
        if (!crypto::IdentityCore::verify_signature(pub_key.get(), signed_blob, decoded_sig)) {
            std::cerr << "[DEFENSE] ANNOUNCE: signature verification FAILED from " << peer_id
                      << " — rejecting unverifiable key" << std::endl;
            return;
        }

        bool is_new_peer = !m_peer_manager.is_known_ip(peer_id);
        m_peer_manager.add_known_ip(peer_id);

        // Ensure peer exists in PeerManager registry for dual-path tracking.
        // add_peer() is a no-op if peer already exists (returns false).
        m_peer_manager.add_peer(peer_id, sender_ip, 0, 0, peer_pem);

        if (is_new_peer) {
            std::cout << "[NETWORK] Discovered verified peer: " << peer_id << " at " << sender_ip << std::endl;
        }

        // Dual-path TOFU: confirm ANNOUNCE path and check if both paths agree.
        auto confirm = m_peer_manager.confirm_path(peer_id, PeerEntry::PATH_ANNOUNCE, peer_pem);
        if (confirm.key_mismatch) {
            std::cerr << "[SECURITY] TOFU dual-path MISMATCH for " << peer_id
                      << " via ANNOUNCE — rejecting peer." << std::endl;
            return;
        }

        // Register key with PBFT only when BOTH discovery paths confirm the same key.
        if (confirm.dual_confirmed && !m_pbft.has_peer(peer_id)) {
            m_pbft.register_peer_key(peer_id, peer_pem);
            m_pbft.increment_peers();
            std::cout << "[TOFU] Dual-path confirmed for " << peer_id
                      << " — registered with PBFT." << std::endl;
        }

        if (m_enforcer) m_enforcer->register_peer_ip(peer_id, sender_ip);

        if (!is_new_peer) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_announce_time).count();
            if (elapsed >= 2) {
                m_last_announce_time = now;
                announce_identity();
            }
        } else {
            announce_identity();
        }
    }
    else if (cmd == "VOTE" && tokens.size() >= 9) {
        const std::string& stage_str    = tokens[1];
        const std::string& sender_id    = tokens[2];
        const std::string& seq_str      = tokens[3];
        const std::string& view_str     = tokens[4];
        const std::string& target_id    = tokens[5];
        const std::string& prev_hash    = tokens[7];
        const std::string& sig_b64      = tokens[8];

        if (stage_str.empty() || sender_id.empty() || target_id.empty()) return;
        if (sender_id.size() > 64 || target_id.size() > 64) return;

        // Check base64-encoded evidence size before decoding to prevent
        // unbounded memory allocation from untrusted UDP input.
        // Base64 expands by ~4/3; allow a small margin for padding.
        if (tokens[6].size() > m_max_evidence_size * 4 / 3 + 4) return;

        std::string evidence_decoded = base64_decode(tokens[6]).value_or("");
        if (evidence_decoded.empty() || evidence_decoded.size() > m_max_evidence_size) return;
        if (evidence_decoded[0] != '{') return;
        if (stage_str != "PRE_PREPARE" && stage_str != "PREPARE" && stage_str != "COMMIT" && stage_str != "BAN_PEER") return;

        uint64_t seq = 0;
        int view = 0;
        try {
            seq = std::stoull(seq_str);
            view = std::stoi(view_str);
        } catch (...) {
            std::cerr << "[PBFT] Invalid seq/view from " << sender_id << std::endl;
            return;
        }

        std::string decoded_sig = base64_decode(sig_b64).value_or("");
        if (decoded_sig.empty()) {
            std::cerr << "[PBFT] Failed to decode signature from " << sender_id << std::endl;
            return;
        }
        P2PMessage incoming_msg{stage_str, sender_id, target_id, evidence_decoded, decoded_sig, prev_hash, seq, view};
        if (incoming_msg.sender_id == m_node_id) return;

        if (incoming_msg.target_id == m_node_id) {
            std::lock_guard<std::mutex> lock(m_targeted_mtx);
            m_last_targeted_at = std::chrono::steady_clock::now();
        }

        std::cout << "[PBFT] Received " << incoming_msg.stage_str << " from " << incoming_msg.sender_id
                  << " targeting " << incoming_msg.target_id << std::endl;

        if (m_pbft.verify_message(incoming_msg)) {
            PBFTStage next_stage = m_pbft.advance_state(incoming_msg);

            if (next_stage == PBFTStage::PREPARE) {
                std::cout << "[PBFT] -> Advanced to PREPARE, broadcasting..." << std::endl;
                broadcast_pbft_stage("PREPARE", incoming_msg.target_id, incoming_msg.evidence_json);
            }
            else if (next_stage == PBFTStage::COMMIT) {
                std::cout << "[PBFT] -> Advanced to COMMIT, broadcasting..." << std::endl;
                m_journal.append("COMMIT", incoming_msg.target_id, incoming_msg.evidence_json);
                if (m_bridge) {
                    std::ignore = m_bridge->push_telemetry(
                        "{\"event\":\"entropy_spike\",\"value\":0.98,\"threshold\":0.65,"
                        "\"target\":\"" + incoming_msg.target_id + "\","
                        "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + ","
                    "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\",\"T1090\"]}");
                }
                broadcast_pbft_stage("COMMIT", incoming_msg.target_id, incoming_msg.evidence_json);
            }
             else if (next_stage == PBFTStage::EXECUTED) {
                // Phase 3: handle BAN_PEER EXECUTED. Check evidence_json for
                // the ban action marker — the round type is encoded in evidence,
                // not the stage_str (which changes from PRE_PREPARE to PREPARE
                // to COMMIT as the round progresses). Also accept legacy
                // stage_str=="BAN_PEER" for backward compat with older nodes.
                bool is_ban_round = incoming_msg.evidence_json.find("\"action\":\"ban\"") != std::string::npos;
                if (is_ban_round || incoming_msg.stage_str == "BAN_PEER") {
                    std::string ban_reason = incoming_msg.evidence_json;
                    if (incoming_msg.stage_str == "BAN_PEER") {
                        ban_reason = "cross_node_bft: " + incoming_msg.evidence_json;
                    }
                    m_pbft.ban_peer_local(incoming_msg.target_id, ban_reason);
                    m_journal.append("BAN_PEER_EXECUTED",
                                     incoming_msg.target_id,
                                     incoming_msg.evidence_json);
                    std::cout << "[BAN_PEER] Cross-node ban EXECUTED for "
                              << incoming_msg.target_id << std::endl;
                    return;
                }

                // Require at least one external peer for consensus.
                // With n=1 (self only), quorum=1 and a single node could
                // unilaterally isolate any target — bypassing BFT entirely.
                if (m_peer_manager.peer_count() < 1) {
                    std::cerr << "[DEFENSE] EXECUTED blocked — no external peers for consensus (n="
                              << m_pbft.peer_count() << ", quorum=" << m_pbft.quorum_size() << ")" << std::endl;
                    return;
                }
                auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();

                std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << incoming_msg.target_id
                          << " — executing MitigationEngine response." << std::endl;
                m_journal.append("EXECUTED", incoming_msg.target_id, incoming_msg.evidence_json);

                // Append to proof chain for verifiable audit trail
                if (m_proof_chain) {
                    std::string round_key = crypto::IdentityCore::sha256_hex(
                        incoming_msg.evidence_json + "|" + incoming_msg.target_id);
                    std::string commit_sig = m_pbft.get_round_commit_sig(round_key);
                    m_proof_chain->append(crypto::ProofEventType::CONSENSUS_REACHED,
                        incoming_msg.target_id, incoming_msg.evidence_json,
                        commit_sig);
                    m_proof_chain->export_file();
                    // Push proof data to dashboard via telemetry bridge
                    if (m_bridge) {
                        std::string proof_json = "{\"proof_chain\":" + m_proof_chain->get_latest_json() + "}";
                        std::ignore = m_bridge->push_telemetry(proof_json);
                    }
                }

                // Fire alert webhook (fork+exec curl — non-blocking at OS level)
                if (!m_webhook_url.empty()) {
                    notify_webhook(m_webhook_url, incoming_msg.target_id,
                                   incoming_msg.evidence_json, m_pbft.quorum_size(), now_us);
                }

                if (m_bridge) {
                    std::ignore = m_bridge->push_telemetry(
                        "{\"event\":\"entropy_spike\",\"value\":0.98,\"threshold\":0.65,"
                        "\"target\":\"" + incoming_msg.target_id + "\","
                        "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + ","
                    "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\",\"T1090\"]}");
                    std::ignore = m_bridge->push_telemetry(
                        "{\"event\":\"heartbeat\","
                        "\"node\":\"" + incoming_msg.target_id + "\","
                        "\"threat\":\"CRITICAL\","
                        "\"status\":\"FLAGGED\","
                        "\"entropy\":0.98,"
                        "\"cpu\":85.5,"
                        "\"mem_mb\":512,"
                        "\"peers\":0,"
                        "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\"]}");
                }
                // Execute mitigation (fork+exec iptables — non-blocking at OS level)
                if (m_mitigation) {
                    try {
                        m_mitigation->execute_response(incoming_msg.evidence_json,
                                                       incoming_msg.target_id);
                    } catch (const std::exception& e) {
                        std::cerr << "[MITIGATION ERROR] " << e.what() << std::endl;
                    }
                }
            }
        } else {
            std::cerr << "[PBFT] Signature verification FAILED for " << incoming_msg.stage_str
                      << " from " << incoming_msg.sender_id << std::endl;
        }
    }
}

// =============================================================================
// PBFT consensus helpers
// =============================================================================

bool MeshNode::propose_ban(const std::string& target_id, const std::string& reason) {
    if (target_id.empty() || target_id == m_node_id) return false;

    // Cross-node BFT ban propagation: broadcast a normal PRE_PREPARE PBFT
    // round with evidence encoding the ban action. The round type is carried
    // in the evidence_json (not the stage_str), so it survives PREPARE →
    // COMMIT → EXECUTED transitions. At EXECUTED, nodes check evidence_json
    // for "\"action\":\"ban\"" to distinguish ban rounds from isolation.
    std::string ban_evidence = "{\"action\":\"ban\",\"reason\":\"" + reason + "\"}";
    broadcast_pbft_stage("PRE_PREPARE", target_id, ban_evidence);

    if (m_pbft.is_banned(target_id)) return true;  // already banned locally

    m_pbft.ban_peer_local(target_id, reason);
    m_journal.append("BAN_PEER_LOCAL", target_id, reason);
    std::cout << "[BAN_PEER] Local ban proposed for " << target_id
              << " reason=" << reason << std::endl;

    return true;
}

bool MeshNode::is_banned(const std::string& peer_id) const {
    return m_pbft.is_banned(peer_id);
}

void MeshNode::initiate_consensus(const std::string& target_id, const std::string& evidence_json) {
    if (m_peer_manager.is_on_cooldown(target_id)) {
        std::cerr << "[DEFENSE] Consensus rate-limited for " << target_id << std::endl;
        return;
    }
    m_peer_manager.set_cooldown(target_id);

    std::cout << "[DEFENSE] Initiating PBFT Consensus for target: " << target_id << std::endl;
    broadcast_pbft_stage("PRE_PREPARE", target_id, evidence_json);
}

void MeshNode::broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json) {
    // relaxed: sequence counter is monotonic, no cross-thread ordering dependency
    uint64_t seq = m_sequence_number.fetch_add(1, std::memory_order_relaxed) + 1;
    int view = m_pbft.current_view();

    std::string prev_hash = m_pbft.get_last_sent_hash(m_node_id);

    P2PMessage msg;
    msg.stage_str = stage_str;
    msg.sender_id = m_node_id;
    msg.target_id = target_id;
    msg.evidence_json = evidence_json;
    msg.sequence_number = seq;
    msg.view = view;
    msg.prev_message_hash = prev_hash;

    std::string signature = m_pbft.sign_message(msg);
    if (stage_str == "COMMIT") {
        m_pbft.set_round_commit_sig(
            crypto::IdentityCore::sha256_hex(evidence_json + "|" + target_id),
            signature);
    }
    std::string encoded_sig = base64_encode(signature);

    std::string b64_evidence = base64_encode(evidence_json);
    std::string payload = "VOTE|" + stage_str + "|" + m_node_id + "|" + std::to_string(seq) + "|" +
                          std::to_string(view) + "|" + target_id + "|" + b64_evidence + "|" +
                          prev_hash + "|" + encoded_sig;

    // Prefer TLS to known peers, always broadcast via UDP as well
    // (duplicates are deduplicated via m_seen_messages and vote registry).
    {
        auto peer_ids = m_peer_manager.get_all_peer_ids();
        for (const auto& peer_id : peer_ids) {
            int fd = -1;
            if (m_peer_manager.get_peer_tls_fd(peer_id, fd) && m_transport) {
                ssize_t sent = m_transport->send(fd, payload.data(), payload.size());
                if (sent != static_cast<ssize_t>(payload.size())) {
                    m_peer_manager.set_peer_tls_fd(peer_id, -1);
                }
            }
        }
    }
    send_udp_broadcast(payload);

    P2PMessage self_msg{stage_str, m_node_id, target_id, evidence_json, signature, prev_hash, seq, view};
    if (m_pbft.verify_message(self_msg)) {
        PBFTStage next_stage = m_pbft.advance_state(self_msg);

        if (next_stage == PBFTStage::PREPARE) {
            std::cout << "[PBFT] -> Advanced to PREPARE (seq=" << seq << "), broadcasting..." << std::endl;
            broadcast_pbft_stage("PREPARE", target_id, evidence_json);
        } else if (next_stage == PBFTStage::COMMIT) {
            std::cout << "[PBFT] -> Advanced to COMMIT (seq=" << seq << "), broadcasting..." << std::endl;
            m_journal.append("COMMIT", target_id, evidence_json);
            if (m_bridge) {
                std::ignore = m_bridge->push_telemetry(
                    "{\"event\":\"entropy_spike\",\"value\":0.98,\"threshold\":0.65,"
                    "\"target\":\"" + target_id + "\","
                    "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + ","
                    "\"mitre_attack\":[\"T1059\",\"T1021\",\"T1571\",\"T1090\"]}");
            }
            broadcast_pbft_stage("COMMIT", target_id, evidence_json);
 } else if (next_stage == PBFTStage::EXECUTED) {
        // Phase 3: handle BAN_PEER EXECUTED in self-vote path.
        // Same evidence-based detection as process_message's handler.
        bool is_ban_round = evidence_json.find("\"action\":\"ban\"") != std::string::npos;
        if (is_ban_round || stage_str == "BAN_PEER") {
            std::string ban_reason = evidence_json;
            if (stage_str == "BAN_PEER") {
                ban_reason = "cross_node_bft: " + evidence_json;
            }
            m_pbft.ban_peer_local(target_id, ban_reason);
            m_journal.append("BAN_PEER_EXECUTED", target_id, evidence_json);
            std::cout << "[BAN_PEER] Cross-node ban EXECUTED for "
                      << target_id << std::endl;
            return;
        }
        // Require at least one external peer for consensus.
            // With n=1 (self only), quorum=1 and a single node could
            // unilaterally isolate any target — bypassing BFT entirely.
            if (m_peer_manager.peer_count() < 1) {
                std::cerr << "[DEFENSE] Self-vote EXECUTED blocked — no external peers for consensus (n="
                          << m_pbft.peer_count() << ", quorum=" << m_pbft.quorum_size() << ")" << std::endl;
                return;
            }
            std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << target_id
                      << " (seq=" << seq << ") — executing MitigationEngine response." << std::endl;
            m_journal.append("EXECUTED", target_id, evidence_json);

            // Append to proof chain for verifiable audit trail
            if (m_proof_chain) {
                m_proof_chain->append(crypto::ProofEventType::CONSENSUS_REACHED,
                    target_id, evidence_json,
                    signature);
                m_proof_chain->export_file();
            }

            // Execute mitigation (fork+exec iptables — non-blocking at OS level)
            if (m_mitigation) {
                try {
                    m_mitigation->execute_response(evidence_json, target_id);
                } catch (const std::exception& e) {
                    std::cerr << "[MITIGATION ERROR] " << e.what() << std::endl;
                }
            }
        }
    }
}

// =============================================================================
// TLS Acceptor — accepts incoming TLS connections from peers
// =============================================================================

void MeshNode::tls_acceptor_loop() {
    if (!m_transport) return;

    for (int port = TLS_PORT_START; port < TLS_PORT_START + 100; ++port) {
        if (m_transport->bind("0.0.0.0", static_cast<uint16_t>(port))) {
            m_tls_port = port;
            break;
        }
    }

    if (m_tls_port == 0) {
        std::cerr << "[TLS] Failed to bind TLS acceptor." << std::endl;
        return;
    }

    if (!m_transport->listen(8)) {
        std::cerr << "[TLS] listen() failed on TLS port " << m_tls_port << std::endl;
        return;
    }

    std::cout << "[TLS] Acceptor listening on port " << m_tls_port << std::endl;

    while (m_running) {
        int fd = m_transport->accept();
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto conn_info = m_transport->get_connection_info(fd);
        bool matched = false;
        if (conn_info && conn_info->verified) {
            auto peers = m_peer_manager.get_all_peers();
            for (const auto& entry : peers) {
                if (entry.ip == conn_info->peer_ip && entry.tls_port == conn_info->peer_port) {
                    int old_fd = -1;
                    if (m_peer_manager.get_peer_tls_fd(entry.node_id, old_fd) && old_fd >= 0) {
                        m_transport->close(old_fd);
                    }
                    m_peer_manager.set_peer_tls_fd(entry.node_id, fd);
                    std::cout << "[TLS] Accepted connection from " << entry.node_id
                              << " (" << conn_info->peer_ip << ":" << conn_info->peer_port << ")" << std::endl;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            std::cout << "[TLS] Rejecting unmatched/unverified connection on fd " << fd << std::endl;
            m_transport->close(fd);
        }
    }
}

// =============================================================================
// TLS Connection Helpers
// =============================================================================

bool MeshNode::connect_tls_to_peer(const std::string& peer_id, const std::string& ip, int port) {
    if (!m_transport) return false;

    int existing_fd = -1;
    if (m_peer_manager.get_peer_tls_fd(peer_id, existing_fd)) return true;

    int fd = m_transport->connect(ip, static_cast<uint16_t>(port));
    if (fd < 0) return false;

    m_peer_manager.set_peer_tls_fd(peer_id, fd);
    return true;
}

void MeshNode::disconnect_tls_peer(const std::string& peer_id) {
    int fd = -1;
    if (m_peer_manager.get_peer_tls_fd(peer_id, fd)) {
        if (m_transport) m_transport->close(fd);
        m_peer_manager.set_peer_tls_fd(peer_id, -1);
    }
}

// =============================================================================
// TLS Connection Worker — processes queued TLS connect tasks
// Replaces detached threads with a single managed worker thread
// =============================================================================

void MeshNode::tls_worker_loop() {
    while (m_running) {
        TLSConnectTask task;
        {
            std::unique_lock<std::mutex> lock(m_tls_queue_mtx);
            m_tls_queue_cv.wait(lock, [this] {
                return !m_tls_connect_queue.empty() || !m_running;
            });
            if (!m_running && m_tls_connect_queue.empty()) return;
            task = m_tls_connect_queue.front();
            m_tls_connect_queue.erase(m_tls_connect_queue.begin());
        }
        if (!m_running) return;
        connect_tls_to_peer(task.peer_id, task.ip, task.port);
    }
}

// =============================================================================
// Liveness Monitor — prunes peers with stale heartbeats (> LIVENESS_SEC)
// =============================================================================

void MeshNode::liveness_monitor() {
    auto last_prune = std::chrono::steady_clock::now();
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::steady_clock::now();
        if (!m_running) break;
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_prune).count() >= HEARTBEAT_SEC) {
            prune_stale_peers();

            // Check for stalled consensus rounds and trigger view change
            // if needed (BUG-11 fix: needs_view_change was defined but never called).
            auto peer_ids = m_peer_manager.get_all_peer_ids();
            for (const auto& peer_id : peer_ids) {
                std::string evidence = "{\"liveness\":\"check\"}";
                if (m_pbft.needs_view_change(evidence, peer_id)) {
                    std::cout << "[PBFT] View change triggered for stalled round with "
                              << peer_id << std::endl;
                    m_pbft.advance_view();
                }
            }

            last_prune = now;
        }
    }
}

void MeshNode::prune_stale_peers() {
    auto to_prune = m_peer_manager.get_stale_peers();
    if (to_prune.empty()) return;

    int n_after = 0;
    {
        for (const auto& id : to_prune) {
            int fd = -1;
            if (m_peer_manager.get_peer_tls_fd(id, fd) && fd >= 0 && m_transport) {
                m_transport->close(fd);
            }
            m_peer_manager.remove_peer(id);
            // Phase 3: do NOT prune pre-provisioned peers from PBFT.
            // Pre-provisioned peers (set via NEURO_PEER_KEYS) are known
            // attackers used for adversarial testing. Pruning them from
            // PBFT's key registry breaks auto-ban detection, since
            // verify_message silently drops messages from unregistered peers.
            if (!m_peer_manager.is_peer_pre_provisioned(id)) {
                m_pbft.prune_peer(id);
            }
        }
        n_after = m_peer_manager.peer_count() + 1;
    }

    for (const auto& id : to_prune) {
        std::cout << "[NETWORK] Pruned stale peer " << id
                  << ". Quorum updated to n=" << n_after << "." << std::endl;
    }
}

// =============================================================================
// Attack Detection — true while this node is the target of a recent PBFT round
// =============================================================================

bool MeshNode::is_targeted_recently() const {
    std::lock_guard<std::mutex> lock(m_targeted_mtx);
    if (m_last_targeted_at == std::chrono::steady_clock::time_point{}) return false;
    auto elapsed = std::chrono::steady_clock::now() - m_last_targeted_at;
    return std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < 12;
}

// =============================================================================
// TOFU: TLS Certificate Verification
// =============================================================================

// verify_peer_tls_cert is now handled by PeerManager

// =============================================================================
// Seed Peers — unicast discovery fallback for cross-subnet mesh
// =============================================================================

void MeshNode::set_seed_peers(const std::vector<std::pair<std::string, int>>& seeds) {
    m_seed_peers = seeds;
    if (!seeds.empty()) {
        std::cout << "[DISCOVERY] Configured " << seeds.size()
                  << " seed peer(s) for unicast discovery." << std::endl;
        for (const auto& [ip, port] : seeds) {
            std::cout << "[DISCOVERY]   Seed: " << ip << ":" << port << std::endl;
        }
    }
}

// =============================================================================
// TOFU Key Management — unpin a peer's key for legitimate rotation
// =============================================================================

void MeshNode::unpin_peer_key(const std::string& node_id) {
    if (!m_peer_manager.has_peer(node_id)) {
        std::cerr << "[SECURITY] unpin_peer_key: unknown peer " << node_id << std::endl;
        return;
    }
    m_peer_manager.unpin_peer_key(node_id);
    std::cout << "[SECURITY] Key and TLS cert unpinned for " << node_id
              << " — next beacon will accept new key and cert." << std::endl;
}

// =============================================================================
// Background child reaper — replaces detached threads to prevent thread leak.
// A single static thread collects PIDs from a queue and calls waitpid() on each.
// =============================================================================

namespace {
    static std::mutex s_reaper_mtx;
    static std::condition_variable s_reaper_cv;
    static std::vector<pid_t> s_reaper_queue;
    static std::thread s_reaper_thread;
    static std::atomic<bool> s_reaper_running{false};
    static std::once_flag s_reaper_once;

    static void reaper_loop() {
        while (s_reaper_running.load(std::memory_order_acquire)) {
            pid_t pid;
            {
                std::unique_lock<std::mutex> lock(s_reaper_mtx);
                s_reaper_cv.wait(lock, [] {
                    return !s_reaper_queue.empty() || !s_reaper_running.load(std::memory_order_relaxed);
                });
                if (!s_reaper_running.load(std::memory_order_relaxed) && s_reaper_queue.empty()) return;
                pid = s_reaper_queue.back();
                s_reaper_queue.pop_back();
            }
            int status;
            if (waitpid(pid, &status, 0) == pid) {
                if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                    std::cerr << "[ALERT] Webhook POST failed (exit="
                              << WEXITSTATUS(status) << ")" << std::endl;
                }
            }
        }
    }

    static void start_reaper() {
        std::call_once(s_reaper_once, [] {
            s_reaper_running.store(true, std::memory_order_release);
            s_reaper_thread = std::thread(reaper_loop);
        });
    }

    static void enqueue_reap(pid_t pid) {
        start_reaper();
        std::lock_guard<std::mutex> lock(s_reaper_mtx);
        s_reaper_queue.push_back(pid);
        s_reaper_cv.notify_one();
    }
} // namespace

// =============================================================================
// Utility
// =============================================================================

void MeshNode::notify_webhook(const std::string& url, const std::string& target_id,
                              const std::string& evidence_json, int quorum, int64_t timestamp_us) {
    if (url.empty()) return;

    // Build JSON payload
    std::string escaped_evidence = evidence_json;
    for (size_t i = 0; i < escaped_evidence.size(); ++i) {
        char c = escaped_evidence[i];
        if (c == '"' || c == '\\') {
            escaped_evidence.insert(i++, 1, '\\');
        } else if (c == '\n') {
            escaped_evidence.replace(i, 1, "\\n");
            ++i;
        } else if (c == '\t') {
            escaped_evidence.replace(i, 1, "\\t");
            ++i;
        } else if (c == '\r') {
            escaped_evidence.replace(i, 1, "\\r");
            ++i;
        } else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            int n = std::snprintf(buf, sizeof(buf), "\\u%04x", c);
            escaped_evidence.replace(i, 1, std::string(buf, n));
            i += n - 1;
        }
    }

    std::ostringstream payload;
    payload << "{"
            << "\"event\":\"isolation\","
            << "\"target\":\"" << target_id << "\","
            << "\"quorum\":" << quorum << ","
            << "\"timestamp_us\":" << timestamp_us << ","
            << "\"evidence\":" << escaped_evidence
            << "}";

    // Validate URL: reject spaces, control chars, and non-http(s) schemes
    if (url.empty() || url.find(' ') != std::string::npos ||
        (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0)) {
        std::cerr << "[ALERT] Webhook URL rejected (invalid): " << url.substr(0, 64) << std::endl;
        return;
    }

    // SSRF guard: reject private/metadata IP ranges.
    // Also capture the first resolved IP to pin curl via --resolve,
    // preventing DNS rebinding between our check and curl's connection.
    std::string resolved_ip_for_curl;
    std::string host;
    size_t url_host_start = (url.rfind("https://", 0) == 0) ? 8 : 7;
    {
        size_t end = url.size();
        size_t slash = url.find('/', url_host_start);
        size_t colon = url.find(':', url_host_start);
        if (slash != std::string::npos) end = slash;
        if (colon != std::string::npos && colon < end) end = colon;
        host = url.substr(url_host_start, end - url_host_start);

        struct addrinfo hints{};
        struct addrinfo* res = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
            bool blocked = false;
            for (struct addrinfo* rp = res; rp && !blocked; rp = rp->ai_next) {
                void* addr = nullptr;
                if (rp->ai_family == AF_INET) {
                    addr = &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
                } else if (rp->ai_family == AF_INET6) {
                    addr = &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
                } else continue;

                if (rp->ai_family == AF_INET) {
                    uint32_t ipv4 = ntohl(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
                    // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    // 169.254.0.0/16 (incl. 169.254.169.254), 100.64.0.0/10
                    if ((ipv4 & 0xFF000000) == 0x7F000000 ||
                        (ipv4 & 0xFF000000) == 0x0A000000 ||
                        (ipv4 & 0xFFF00000) == 0xAC100000 ||
                        (ipv4 & 0xFFFF0000) == 0xC0A80000 ||
                        (ipv4 & 0xFFFF0000) == 0xA9FE0000 ||
                        (ipv4 & 0xFFC00000) == 0x64400000) {
                        blocked = true;
                    }
                } else if (rp->ai_family == AF_INET6) {
                    // Link-local (fe80::/10) and unique-local (fc00::/7)
                    uint8_t* p = ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr;
                    if (IN6_IS_ADDR_LOOPBACK((struct in6_addr*)addr) ||
                        (p[0] == 0xFE && (p[1] & 0xC0) == 0x80) ||
                        (p[0] == 0xFC || p[0] == 0xFD)) {
                        blocked = true;
                    }
                }
            }
            // Capture first safe IP for --resolve pinning
            if (!blocked) {
                for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
                    char ipbuf[INET6_ADDRSTRLEN];
                    if (rp->ai_family == AF_INET) {
                        if (inet_ntop(AF_INET, &((struct sockaddr_in*)rp->ai_addr)->sin_addr,
                                      ipbuf, sizeof(ipbuf))) {
                            resolved_ip_for_curl = ipbuf;
                            break;
                        }
                    } else if (rp->ai_family == AF_INET6) {
                        if (inet_ntop(AF_INET6, &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr,
                                      ipbuf, sizeof(ipbuf))) {
                            resolved_ip_for_curl = "[" + std::string(ipbuf) + "]";
                            break;
                        }
                    }
                }
            }
            freeaddrinfo(res);
            if (blocked) {
                std::cerr << "[ALERT] Webhook URL rejected (private IP): " << url.substr(0, 64) << std::endl;
                return;
            }
        }
    }

    // fork+exec curl with absolute path to prevent PATH hijacking.
    // If we resolved a safe IP, pin curl to it via --resolve to prevent
    // DNS rebinding between our SSRF check and curl's connection.
    std::string payload_str = payload.str();
    std::vector<const char*> curl_args = {
        "/usr/bin/curl", "-s", "-X", "POST",
        "-H", "Content-Type: application/json",
    };

    if (!resolved_ip_for_curl.empty()) {
        // Extract port from URL (default 80 for http, 443 for https)
        int port = (url.rfind("https://", 0) == 0) ? 443 : 80;
        size_t colon_pos = url.find(':', url_host_start);
        size_t slash_pos = url.find('/', url_host_start);
        if (colon_pos != std::string::npos && (slash_pos == std::string::npos || colon_pos < slash_pos)) {
            try { port = std::stoi(url.substr(colon_pos + 1, slash_pos - colon_pos - 1)); } catch (...) {}
        }
        std::string resolve_arg = host + ":" + std::to_string(port) + ":" + resolved_ip_for_curl;
        curl_args.push_back("--resolve");
        curl_args.push_back(resolve_arg.c_str());
    }

    curl_args.push_back("-d");
    curl_args.push_back(payload_str.c_str());
    curl_args.push_back(url.c_str());
    curl_args.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        // Close all inherited FDs >= 3 to prevent FD leak to child.
        // Use close_range() atomically instead of a racy per-FD loop.
        int max_fd = std::min<int>(sysconf(_SC_OPEN_MAX), 1024 * 1024);
        syscall(SYS_close_range, 3, static_cast<unsigned int>(max_fd), 0U);
        execv(curl_args[0], const_cast<char* const*>(curl_args.data()));
        _exit(1);
    } else if (pid > 0) {
        // Enqueue PID for the background reaper thread — replaces detached
        // threads to prevent thread accumulation under sustained webhook firing.
        enqueue_reap(pid);
        std::cout << "[ALERT] Webhook POST initiated asynchronously (pid=" << pid << ")" << std::endl;
    }
}

std::vector<std::string> MeshNode::split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) tokens.push_back(token);
    return tokens;
}

bool MeshNode::try_parse_int(const std::string& s, int& out) noexcept {
    try {
        size_t pos = 0;
        int val = std::stoi(s, &pos);
        if (pos != s.size()) return false;
        out = val;
        return true;
    } catch (...) {
        return false;
    }
}

bool MeshNode::try_parse_long(const std::string& s, int64_t& out) noexcept {
    try {
        size_t pos = 0;
        int64_t val = std::stoll(s, &pos);
        if (pos != s.size()) return false;
        out = val;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace neuro_mesh
