#include "consensus/MeshNode.hpp"
#include "common/UniqueFD.hpp"
#include "common/Base64.hpp"
#include "jailer/MitigationEngine.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace neuro_mesh {

// =============================================================================
// Construction
// =============================================================================

MeshNode::MeshNode(const std::string& node_id,
                   SystemJailer* jailer, MitigationEngine* mitigation,
                   TelemetryBridge* bridge)
    : m_node_id(node_id),
      m_udp_port(9999),
      m_tcp_port(0),
      m_running(false),
      m_pbft(1),   // start with n=1 (self), scale up via discovery
      m_jailer(jailer),
      m_mitigation(mitigation),
      m_bridge(bridge),
      m_journal("./journal_" + node_id + ".log")
{
    m_private_key = crypto::IdentityCore::generate_ed25519_key();
    m_public_key_pem = crypto::IdentityCore::get_pem_from_pubkey(m_private_key.get());
    m_public_key_b64 = base64_encode(m_public_key_pem);
    std::cout << "[INFO] Node " << m_node_id << " generated Ed25519 Sovereign Identity." << std::endl;

    // Register self so self-votes pass verification
    m_pbft.register_peer_key(m_node_id, m_public_key_pem);

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
    m_liveness_thread  = std::thread(&MeshNode::liveness_monitor, this);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    announce_identity();
}

void MeshNode::stop() {
    m_running = false;
    if (m_listener_thread.joinable())  m_listener_thread.join();
    if (m_discovery_thread.joinable()) m_discovery_thread.join();
    if (m_tcp_thread.joinable())       m_tcp_thread.join();
    if (m_liveness_thread.joinable())  m_liveness_thread.join();
}

int MeshNode::peer_count() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    return static_cast<int>(m_peers.size()) + 1;  // +1 for self
}

std::vector<std::string> MeshNode::get_active_peer_ids() const {
    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
    std::vector<std::string> ids;
    ids.reserve(m_peers.size());
    for (const auto& [id, info] : m_peers) {
        ids.push_back(id);
    }
    return ids;
}

// =============================================================================
// Identity announcement (UDP broadcast — legacy + discovery compatible)
// =============================================================================

void MeshNode::announce_identity() {
    std::string payload = "ANNOUNCE|" + m_node_id + "|" + m_public_key_pem;
    send_udp_broadcast(payload);
    std::cout << "[NETWORK] Broadcasted identity to local subnet." << std::endl;
}

// =============================================================================
// Discovery Beacon — signed heartbeat broadcast every HEARTBEAT_SEC
// =============================================================================

void MeshNode::send_discovery_beacon() {
    using namespace std::chrono;
    auto now = steady_clock::now();
    auto us = duration_cast<microseconds>(now.time_since_epoch()).count();

    // Signed blob binds node_id + tcp_port + timestamp
    std::string signed_blob = m_node_id + "|" + std::to_string(m_tcp_port) + "|" + std::to_string(us);
    std::string raw_sig = crypto::IdentityCore::sign_payload(m_private_key.get(), signed_blob);
    std::string b64_sig = base64_encode(raw_sig);

    // Packet: DISCOVERY|<node_id>|<tcp_port>|<timestamp_us>|<b64_pubkey>|<b64_sig>
    std::string payload = "DISCOVERY|" + m_node_id + "|"
                        + std::to_string(m_tcp_port) + "|"
                        + std::to_string(us) + "|"
                        + m_public_key_b64 + "|"
                        + b64_sig;

    send_udp_discovery(payload);
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
        send_discovery_beacon();
        for (int i = 0; i < HEARTBEAT_SEC && m_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// =============================================================================
// UDP transport helpers
// =============================================================================

void MeshNode::send_udp_broadcast(const std::string& payload) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return;

    int broadcast_enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    struct sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(m_udp_port);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    sendto(sockfd, payload.c_str(), payload.length(), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    close(sockfd);
}

void MeshNode::send_udp_discovery(const std::string& payload) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return;

    int broadcast_enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    struct sockaddr_in broadcast_addr{};
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DISCOVERY_UDP_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");

    sendto(sockfd, payload.c_str(), payload.length(), 0,
           (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

    close(sockfd);
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
            process_message(std::string(buffer), inet_ntoa(cliaddr.sin_addr));
        }

        // Poll discovery socket
        if (disc_sock >= 0) {
            struct sockaddr_in daddr{};
            socklen_t dlen = sizeof(daddr);
            int dn = recvfrom(disc_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&daddr, &dlen);
            if (dn > 0) {
                buffer[dn] = '\0';
                process_discovery_beacon(std::string(buffer), inet_ntoa(daddr.sin_addr));
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
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listen_fd, &fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(listen_fd + 1, &fds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        int client = accept(listen_fd, nullptr, nullptr);
        if (client < 0) continue;

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
                    std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
                    reply << m_peers.size() << "|";
                    bool first = true;
                    for (const auto& [id, info] : m_peers) {
                        if (!first) reply << ",";
                        reply << id << ":" << info.ip << ":" << info.tcp_port;
                        first = false;
                    }
                }
                std::string reply_str = reply.str();
                write(client, reply_str.c_str(), reply_str.size());

                // Parse their peer list and add new ones (PEX acceleration)
                if (!peer_list.empty() && peer_list != "0") {
                    auto entries = split_string(peer_list, ',');
                    for (const auto& entry : entries) {
                        auto parts = split_string(entry, ':');
                        if (parts.size() >= 3) {
                            const std::string& pid = parts[0];
                            const std::string& pip = parts[1];
                            int pport = std::stoi(parts[2]);
                            if (pid != m_node_id) {
                                // Add as unverified — will be verified on next beacon
                                bool is_new = false;
                                {
                                    std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
                                    if (m_peers.find(pid) == m_peers.end()) {
                                        PeerInfo pi;
                                        pi.node_id = pid;
                                        pi.ip = pip;
                                        pi.tcp_port = pport;
                                        pi.last_heartbeat = std::chrono::steady_clock::now();
                                        m_peers[pid] = pi;
                                        is_new = true;
                                    }
                                }
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
    }

    close(listen_fd);
}

// =============================================================================
// PEX Handshake — TCP connect to a discovered peer, exchange peer lists
// =============================================================================

bool MeshNode::perform_pex_handshake(const std::string& ip, int port,
                                      const std::string& /*expected_peer_id*/) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_aton(ip.c_str(), &addr.sin_addr);

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
        std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
        hello << m_peers.size() << "|";
        bool first = true;
        for (const auto& [id, info] : m_peers) {
            if (!first) hello << ",";
            hello << id << ":" << info.ip << ":" << info.tcp_port;
            first = false;
        }
    }
    std::string hello_str = hello.str();
    write(sock, hello_str.c_str(), hello_str.size());

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
            int pport = std::stoi(parts[2]);
            if (pid != m_node_id) {
                std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
                if (m_peers.find(pid) == m_peers.end()) {
                    PeerInfo pi;
                    pi.node_id = pid;
                    pi.ip = pip;
                    pi.tcp_port = pport;
                    pi.last_heartbeat = std::chrono::steady_clock::now();
                    m_peers[pid] = pi;
                }
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
    if (tokens.size() < 6 || tokens[0] != "DISCOVERY") return;

    const std::string& peer_id   = tokens[1];
    int peer_tcp_port            = std::stoi(tokens[2]);
    int64_t timestamp            = std::stoll(tokens[3]);
    const std::string& b64_pubkey = tokens[4];
    const std::string& b64_sig    = tokens[5];

    if (peer_id == m_node_id) return;

    // Decode public key
    std::string peer_pem = base64_decode(b64_pubkey);
    if (peer_pem.empty()) return;

    // Verify signature: bind(node_id | tcp_port | timestamp)
    std::string signed_blob = peer_id + "|" + std::to_string(peer_tcp_port) + "|" + std::to_string(timestamp);
    std::string raw_sig = base64_decode(b64_sig);
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

    // Capture copies before entering the lock — perform_pex_handshake
    // also acquires m_peers_mtx, so we must release our lock first.
    std::string sender_ip_copy = sender_ip;
    std::string peer_id_copy = peer_id;
    std::string peer_pem_copy = peer_pem;

    bool is_new = false;
    {
        std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
        auto it = m_peers.find(peer_id);
        if (it == m_peers.end()) {
            PeerInfo pi;
            pi.node_id = peer_id;
            pi.ip = sender_ip;
            pi.tcp_port = peer_tcp_port;
            pi.public_key_pem = peer_pem;
            pi.last_heartbeat = steady_clock::now();
            pi.verified = true;
            m_peers[peer_id] = pi;
            is_new = true;
        } else {
            it->second.last_heartbeat = steady_clock::now();
            it->second.ip = sender_ip;        // update IP (may change)
            it->second.tcp_port = peer_tcp_port;
            // Update key if the peer re-announces with a new identity (e.g. simulator restarts)
            if (!peer_pem.empty()) {
                it->second.public_key_pem = peer_pem;
                it->second.verified = true;
                m_pbft.register_peer_key(peer_id, peer_pem);
            }
        }
    }  // m_peers_mtx RELEASED — safe to call perform_pex_handshake now

    if (is_new) {
        std::cout << "[NETWORK] Verified peer " << peer_id_copy
                  << " at " << sender_ip_copy << ":" << peer_tcp_port
                  << ". Quorum updated to n=" << peer_count() << "." << std::endl;

        // Register key with PBFT and IP with jailer
        m_pbft.register_peer_key(peer_id_copy, peer_pem_copy);
        m_pbft.increment_peers();

        if (m_jailer) m_jailer->register_peer_ip(peer_id_copy, sender_ip_copy);

        // Initiate PEX handshake to exchange peer lists (O(log N) discovery)
        // Called OUTSIDE the unique_lock to avoid self-deadlock on m_peers_mtx
        perform_pex_handshake(sender_ip_copy, peer_tcp_port, peer_id_copy);
    }
}

// =============================================================================
// Message processing (consensus port)
// =============================================================================

void MeshNode::process_message(const std::string& msg, const std::string& sender_ip) {
    std::vector<std::string> tokens = split_string(msg, '|');
    if (tokens.size() < 3) return;

    const std::string& cmd = tokens[0];

    if (cmd == "ANNOUNCE") {
        const std::string& peer_id = tokens[1];
        const std::string& peer_pem = tokens[2];
        if (peer_id == m_node_id) return;

        bool is_new_peer = false;
        {
            std::lock_guard<std::mutex> lock(m_peer_mtx);
            if (m_known_peer_ips.find(peer_id) == m_known_peer_ips.end()) {
                m_known_peer_ips.insert(peer_id);
                is_new_peer = true;
                std::cout << "[NETWORK] Discovered peer: " << peer_id << " at " << sender_ip << std::endl;
            }
            m_pbft.register_peer_key(peer_id, peer_pem);
        }

        if (m_jailer) m_jailer->register_peer_ip(peer_id, sender_ip);

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
    else if (cmd == "VOTE" && tokens.size() >= 6) {
        std::string decoded_sig = base64_decode(tokens[5]);
        if (decoded_sig.empty()) {
            std::cerr << "[PBFT] Failed to decode signature from " << tokens[2] << std::endl;
            return;
        }
        P2PMessage incoming_msg{tokens[1], tokens[2], tokens[3], tokens[4], decoded_sig};
        if (incoming_msg.sender_id == m_node_id) return;

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
                        "{\"event\":\"pbft_round_complete\",\"stage\":\"COMMIT\","
                        "\"target\":\"" + incoming_msg.target_id + "\","
                        "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + "}");
                }
                broadcast_pbft_stage("COMMIT", incoming_msg.target_id, incoming_msg.evidence_json);
            }
            else if (next_stage == PBFTStage::EXECUTED) {
                std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << incoming_msg.target_id
                          << " — executing MitigationEngine response." << std::endl;
                m_journal.append("EXECUTED", incoming_msg.target_id, incoming_msg.evidence_json);
                if (m_bridge) {
                    std::ignore = m_bridge->push_telemetry(
                        "{\"event\":\"pbft_round_complete\",\"stage\":\"EXECUTED\","
                        "\"target\":\"" + incoming_msg.target_id + "\","
                        "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + "}");
                }
                std::string ev = incoming_msg.evidence_json;
                std::string tgt = incoming_msg.target_id;
                std::thread([this, ev, tgt]() {
                    try {
                        if (m_mitigation) m_mitigation->execute_response(ev, tgt);
                    } catch (const std::exception& e) {
                        std::cerr << "[MITIGATION ERROR] " << e.what() << std::endl;
                    }
                }).detach();
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

void MeshNode::initiate_threat_consensus(const std::string& target_id, const std::string& evidence_json) {
    std::cout << "[DEFENSE] Initiating PBFT Consensus for target: " << target_id << std::endl;
    broadcast_pbft_stage("PRE_PREPARE", target_id, evidence_json);
}

void MeshNode::broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json) {
    std::string signed_blob = stage_str + "|" + target_id + "|" + evidence_json;
    std::string signature = crypto::IdentityCore::sign_payload(m_private_key.get(), signed_blob);
    std::string encoded_sig = base64_encode(signature);
    std::string payload = "VOTE|" + stage_str + "|" + m_node_id + "|" + target_id + "|" + evidence_json + "|" + encoded_sig;
    send_udp_broadcast(payload);

    P2PMessage self_msg{stage_str, m_node_id, target_id, evidence_json, signature};
    if (m_pbft.verify_message(self_msg)) {
        PBFTStage next_stage = m_pbft.advance_state(self_msg);

        if (next_stage == PBFTStage::PREPARE) {
            std::cout << "[PBFT] -> Advanced to PREPARE, broadcasting..." << std::endl;
            broadcast_pbft_stage("PREPARE", target_id, evidence_json);
        } else if (next_stage == PBFTStage::COMMIT) {
            std::cout << "[PBFT] -> Advanced to COMMIT, broadcasting..." << std::endl;
            m_journal.append("COMMIT", target_id, evidence_json);
            if (m_bridge) {
                std::ignore = m_bridge->push_telemetry(
                    "{\"event\":\"pbft_round_complete\",\"stage\":\"COMMIT\","
                    "\"target\":\"" + target_id + "\","
                    "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + "}");
            }
            broadcast_pbft_stage("COMMIT", target_id, evidence_json);
        } else if (next_stage == PBFTStage::EXECUTED) {
            std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << target_id
                      << " — executing MitigationEngine response." << std::endl;
            m_journal.append("EXECUTED", target_id, evidence_json);
            if (m_bridge) {
                std::ignore = m_bridge->push_telemetry(
                    "{\"event\":\"pbft_round_complete\",\"stage\":\"EXECUTED\","
                    "\"target\":\"" + target_id + "\","
                    "\"quorum\":" + std::to_string(m_pbft.quorum_size()) + "}");
            }
            std::string ev = evidence_json;
            std::string tgt = target_id;
            std::thread([this, ev, tgt]() {
                try {
                    if (m_mitigation) m_mitigation->execute_response(ev, tgt);
                } catch (const std::exception& e) {
                    std::cerr << "[MITIGATION ERROR] " << e.what() << std::endl;
                }
            }).detach();
        }
    }
}

// =============================================================================
// Liveness Monitor — prunes peers with stale heartbeats (> LIVENESS_SEC)
// =============================================================================

void MeshNode::liveness_monitor() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(HEARTBEAT_SEC));
        prune_stale_peers();
    }
}

void MeshNode::prune_stale_peers() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_prune;

    {
        std::shared_lock<std::shared_mutex> lock(m_peers_mtx);
        for (const auto& [id, info] : m_peers) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                               now - info.last_heartbeat).count();
            if (elapsed > LIVENESS_SEC) {
                to_prune.push_back(id);
            }
        }
    }

    if (to_prune.empty()) return;

    // Erase under exclusive lock — do NOT call peer_count() inside (it acquires m_peers_mtx)
    int n_after = 0;
    {
        std::unique_lock<std::shared_mutex> lock(m_peers_mtx);
        for (const auto& id : to_prune) {
            m_peers.erase(id);
            m_pbft.prune_peer(id);
        }
        n_after = static_cast<int>(m_peers.size()) + 1;
    }  // lock RELEASED — safe to call std::cout now

    for (const auto& id : to_prune) {
        std::cout << "[NETWORK] Pruned stale peer " << id
                  << ". Quorum updated to n=" << n_after << "." << std::endl;
    }
}

// =============================================================================
// Utility
// =============================================================================

std::vector<std::string> MeshNode::split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) tokens.push_back(token);
    return tokens;
}

} // namespace neuro_mesh
