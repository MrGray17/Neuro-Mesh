#ifndef NEURO_MESH_PROOF_CHAIN_HPP
#define NEURO_MESH_PROOF_CHAIN_HPP

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <fstream>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace neuro_mesh::crypto {

enum class ProofEventType : uint8_t {
    ANOMALY_DETECTED   = 0,
    PBFT_PRE_PREPARE   = 1,
    PBFT_PREPARE       = 2,
    PBFT_COMMIT        = 3,
    CONSENSUS_REACHED  = 4,
    ISOLATION_EXECUTED = 5,
    TELEMETRY_GOSSIP   = 6,
    RECORDING_FRAME    = 7
};

struct ProofLink {
    uint64_t         sequence;
    ProofEventType   event_type;
    std::string      node_id;
    std::string      target_id;
    std::string      data_hash;
    std::string      parent_hash;
    std::string      link_hash;
    int64_t          timestamp_us;
    std::string      signature_hex;

    std::string to_string() const {
        std::ostringstream oss;
        oss << sequence << '|' << static_cast<int>(event_type) << '|'
            << node_id << '|' << target_id << '|' << data_hash << '|' << parent_hash;
        return oss.str();
    }

    static std::string sha256_hex(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return {};
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, data.data(), data.size());
        unsigned int len = SHA256_DIGEST_LENGTH;
        EVP_DigestFinal_ex(ctx, hash, &len);
        EVP_MD_CTX_free(ctx);
        std::ostringstream oss;
        for (unsigned int i = 0; i < len; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        return oss.str();
    }
};

class ProofChain {
public:
    static constexpr size_t MAX_CHAIN = 4096;
    static constexpr const char* CHAIN_PATH_PREFIX = "/tmp/neuro_proof_";

    explicit ProofChain(const std::string& node_id)
        : m_node_id(node_id), m_seq(0) {}

    void append(ProofEventType type, const std::string& target_id,
                const std::string& data, const std::string& sig_hex) {
        std::lock_guard<std::mutex> lock(m_mtx);
        auto now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        uint64_t seq = m_seq++;

        std::string ph;
        if (!m_links.empty()) ph = m_links.back().link_hash;

        ProofLink link;
        link.sequence = seq;
        link.event_type = type;
        link.node_id = m_node_id;
        link.target_id = target_id;
        link.data_hash = ProofLink::sha256_hex(data);
        link.parent_hash = ph;
        link.timestamp_us = now;
        link.signature_hex = sig_hex;
        std::string canonical = link.to_string();
        link.link_hash = ProofLink::sha256_hex(canonical);
        m_links.push_back(std::move(link));
        if (m_links.size() > MAX_CHAIN) m_links.erase(m_links.begin());
        m_merkle_dirty = true;
    }

    std::string get_latest_json() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (m_links.empty()) return "{}";
        const auto& l = m_links.back();
        std::ostringstream oss;
        oss << "{\"seq\":" << l.sequence
            << ",\"event\":" << static_cast<int>(l.event_type)
            << ",\"node\":\"" << l.node_id
            << "\",\"target\":\"" << l.target_id
            << "\",\"data_hash\":\"" << l.data_hash
            << "\",\"link_hash\":\"" << l.link_hash
            << "\",\"parent_hash\":\"" << l.parent_hash
            << "\",\"sig\":\"" << l.signature_hex
            << "\",\"ts_us\":" << l.timestamp_us << "}";
        return oss.str();
    }

    std::string get_root_hash() {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (m_links.empty()) return {};
        rebuild_merkle();
        return m_merkle_root;
    }

    std::vector<std::string> get_proof_path(uint64_t seq) {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::vector<std::string> siblings;
        if (seq >= m_links.size()) return siblings;
        rebuild_merkle();
        compute_sibling_path(seq, siblings);
        return siblings;
    }

    static bool verify_proof(const std::string& root_hash,
                             const std::string& leaf_hash,
                             const std::vector<std::string>& siblings) {
        std::string cur = leaf_hash;
        for (const auto& s : siblings) {
            if (!s.empty() && s[0] == 'L')
                cur = ProofLink::sha256_hex(s.substr(1) + cur);
            else if (!s.empty() && s[0] == 'R')
                cur = ProofLink::sha256_hex(cur + s.substr(1));
            else
                cur = ProofLink::sha256_hex(cur + s);
        }
        return cur == root_hash;
    }

    bool export_proof_to_file(uint64_t seq) {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (seq >= m_links.size()) return false;
        rebuild_merkle();
        std::vector<std::string> siblings;
        compute_sibling_path(seq, siblings);
        std::string root = m_merkle_root;
        std::string path = std::string(CHAIN_PATH_PREFIX) + m_node_id
                         + "_proof_" + std::to_string(seq) + ".json";
        std::ofstream ofs(path);
        if (!ofs) return false;
        ofs << "{\"node_id\":\"" << m_node_id
            << "\",\"seq\":" << seq
            << ",\"leaf_hash\":\"" << m_links[seq].link_hash
            << "\",\"root_hash\":\"" << root
            << "\",\"siblings\":[";
        for (size_t i = 0; i < siblings.size(); ++i) {
            if (i) ofs << ",";
            ofs << "\"" << siblings[i] << "\"";
        }
        ofs << "]}\n";
        return true;
    }

    bool export_file() {
        std::lock_guard<std::mutex> lock(m_mtx);
        std::string path = std::string(CHAIN_PATH_PREFIX) + m_node_id + ".proof";
        std::ofstream ofs(path);
        if (!ofs) return false;
        ofs << "{\n  \"node_id\": \"" << m_node_id << "\",\n";
        ofs << "  \"links\": [\n";
        for (size_t i = 0; i < m_links.size(); ++i) {
            const auto& l = m_links[i];
            ofs << "    {\"seq\":" << l.sequence
                << ",\"event\":" << static_cast<int>(l.event_type)
                << ",\"node\":\"" << l.node_id
                << "\",\"target\":\"" << l.target_id
                << "\",\"data_hash\":\"" << l.data_hash
                << "\",\"link_hash\":\"" << l.link_hash
                << "\",\"parent_hash\":\"" << l.parent_hash
                << "\",\"sig\":\"" << l.signature_hex
                << "\",\"ts_us\":" << l.timestamp_us << "}";
            if (i < m_links.size() - 1) ofs << ",";
            ofs << "\n";
        }
        ofs << "  ]\n}\n";
        return true;
    }

    const std::vector<ProofLink>& links() const { return m_links; }

    size_t size() const { std::lock_guard<std::mutex> lock(m_mtx); return m_links.size(); }
    std::string latest_link_hash() const {
        std::lock_guard<std::mutex> lock(m_mtx);
        if (m_links.empty()) return {};
        return m_links.back().link_hash;
    }

private:
    std::string m_node_id;
    std::vector<ProofLink> m_links;
    std::atomic<uint64_t> m_seq;
    mutable std::mutex m_mtx;
    bool m_merkle_dirty = false;
    std::string m_merkle_root;

    void rebuild_merkle() {
        if (!m_merkle_dirty || m_links.empty()) return;
        std::vector<std::string> layer;
        for (const auto& link : m_links)
            layer.push_back(link.link_hash);
        while (layer.size() > 1) {
            std::vector<std::string> next;
            for (size_t i = 0; i < layer.size(); i += 2) {
                if (i + 1 < layer.size())
                    next.push_back(ProofLink::sha256_hex(layer[i] + layer[i+1]));
                else
                    next.push_back(ProofLink::sha256_hex(layer[i]));
            }
            layer = std::move(next);
        }
        m_merkle_root = layer.empty() ? "" : layer[0];
        m_merkle_dirty = false;
    }

    void compute_sibling_path(size_t leaf_idx,
                              std::vector<std::string>& siblings) {
        std::vector<std::string> layer;
        for (const auto& link : m_links)
            layer.push_back(link.link_hash);
        size_t idx = leaf_idx;
        while (layer.size() > 1) {
            std::vector<std::string> next;
            for (size_t i = 0; i < layer.size(); i += 2) {
                if (i + 1 < layer.size()) {
                    if (i == idx) {
                        siblings.push_back("R" + layer[i+1]);
                    } else if (i + 1 == idx) {
                        siblings.push_back("L" + layer[i]);
                    }
                    next.push_back(ProofLink::sha256_hex(layer[i] + layer[i+1]));
                } else {
                    next.push_back(ProofLink::sha256_hex(layer[i]));
                }
                if (i <= idx && idx < i + 2) idx = i / 2;
            }
            layer = std::move(next);
        }
    }
};

} // namespace neuro_mesh::crypto
#endif
