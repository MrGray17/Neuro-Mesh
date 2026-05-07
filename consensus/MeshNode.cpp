#include "consensus/MeshNode.hpp"
#include "common/UniqueFD.hpp"
#include "common/Base64.hpp"
#include "jailer/MitigationEngine.hpp"
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace neuro_mesh {

MeshNode::MeshNode(const std::string& node_id, int total_mesh_size,
                   SystemJailer* jailer, MitigationEngine* mitigation)
    : m_node_id(node_id),
      m_udp_port(9999),
      m_running(false),
      m_pbft(total_mesh_size),
      m_jailer(jailer),
      m_mitigation(mitigation)
{
    m_private_key = crypto::IdentityCore::generate_ed25519_key();
    m_public_key_pem = crypto::IdentityCore::get_pem_from_pubkey(m_private_key.get());
    std::cout << "[INFO] Node " << m_node_id << " generated Ed25519 Sovereign Identity." << std::endl;

    m_pbft.register_peer_key(m_node_id, m_public_key_pem);
}

MeshNode::~MeshNode() {
    stop();
}

void MeshNode::start() {
    if (m_running) return;
    m_running = true;
    m_listener_thread = std::thread(&MeshNode::p2p_listener_loop, this);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    announce_identity();
}

void MeshNode::stop() {
    m_running = false;
    if (m_listener_thread.joinable()) {
        m_listener_thread.join();
    }
}

void MeshNode::announce_identity() {
    std::string payload = "ANNOUNCE|" + m_node_id + "|" + m_public_key_pem;
    send_udp_broadcast(payload);
    std::cout << "[NETWORK] Broadcasted identity to local subnet." << std::endl;
}

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

        // Auto-chain state transitions: when self-vote advances the round,
        // broadcast the next stage immediately (same as process_message logic)
        if (next_stage == PBFTStage::PREPARE) {
            std::cout << "[PBFT] -> Advanced to PREPARE, broadcasting..." << std::endl;
            broadcast_pbft_stage("PREPARE", target_id, evidence_json);
        } else if (next_stage == PBFTStage::COMMIT) {
            std::cout << "[PBFT] -> Advanced to COMMIT, broadcasting..." << std::endl;
            broadcast_pbft_stage("COMMIT", target_id, evidence_json);
        } else if (next_stage == PBFTStage::EXECUTED) {
            std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << target_id
                      << " — executing MitigationEngine response." << std::endl;
            if (m_mitigation) m_mitigation->execute_response(evidence_json, target_id);
        }
    }
}

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

    auto last_view_check = std::chrono::steady_clock::now();
    char buffer[65536];
    while (m_running) {
        struct sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd.get(), buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&cliaddr, &len);

        if (n > 0) {
            buffer[n] = '\0';
            std::string msg(buffer);
            process_message(msg, inet_ntoa(cliaddr.sin_addr));
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_view_check).count() >= 10) {
            last_view_check = now;
        }
    }
}

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

        // Register peer IP for logical ID → IP resolution in SystemJailer
        if (m_jailer) m_jailer->register_peer_ip(peer_id, sender_ip);

        // Always respond to ANNOUNCE (rate-limited) to ensure bidirectional
        // discovery. Without this, a new node joining a mesh of existing nodes
        // would never receive their keys if its ID was previously known.
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
                broadcast_pbft_stage("COMMIT", incoming_msg.target_id, incoming_msg.evidence_json);
            }
            else if (next_stage == PBFTStage::EXECUTED) {
                std::cout << "[CRITICAL] PBFT Final Quorum Reached! Target " << incoming_msg.target_id
                          << " — executing MitigationEngine response." << std::endl;
                if (m_mitigation) m_mitigation->execute_response(incoming_msg.evidence_json, incoming_msg.target_id);
            }
        } else {
            std::cerr << "[PBFT] Signature verification FAILED for " << incoming_msg.stage_str
                      << " from " << incoming_msg.sender_id << std::endl;
        }
    }
}

std::vector<std::string> MeshNode::split_string(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) tokens.push_back(token);
    return tokens;
}

} // namespace neuro_mesh
