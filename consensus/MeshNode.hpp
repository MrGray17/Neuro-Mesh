#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <set>
#include <chrono>
#include "consensus/PBFT.hpp"
#include "crypto/CryptoCore.hpp"
#include "jailer/SystemJailer.hpp"

namespace neuro_mesh {

class MitigationEngine;

class MeshNode {
public:
    // Inject SystemJailer and MitigationEngine dependencies via the constructor
    MeshNode(const std::string& node_id, int total_mesh_size,
             SystemJailer* jailer, MitigationEngine* mitigation);
    ~MeshNode();

    void start();
    void stop();
    void initiate_threat_consensus(const std::string& target_id, const std::string& evidence_json);

private:
    void p2p_listener_loop();
    void process_message(const std::string& msg, const std::string& sender_ip);
    
    void broadcast_pbft_stage(const std::string& stage_str, const std::string& target_id, const std::string& evidence_json);
    void send_udp_broadcast(const std::string& payload);
    void announce_identity();
    std::vector<std::string> split_string(const std::string& str, char delimiter);

    std::string m_node_id;
    int m_udp_port;
    std::atomic<bool> m_running;
    std::thread m_listener_thread;
    std::chrono::steady_clock::time_point m_last_announce_time;

    crypto::UniquePKEY m_private_key;
    std::string m_public_key_pem;
    PBFTConsensus m_pbft;
    
    SystemJailer* m_jailer;         // Network isolation execution module
    MitigationEngine* m_mitigation;  // Verdict consumption + process termination

    std::mutex m_peer_mtx;
    std::set<std::string> m_known_peer_ips;
};

} // namespace neuro_mesh
