// ============================================================
// NEURO-MESH AGENT : STAFF ENGINEER EDITION (V5.2 RESTORED)
// ============================================================

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    #define CLOSE_SOCKET closesocket
    #define SLEEP_MS(x) Sleep(x)
    #define GET_PID _getpid
    #define SHUT_RDWR SD_BOTH
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/sysinfo.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <ifaddrs.h>
    #include <signal.h>
    #include <poll.h>
    #include <netdb.h>
    #define CLOSE_SOCKET close
    #define SLEEP_MS(x) usleep((x) * 1000)
    #define GET_PID getpid
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <ctime>
#include <limits.h>
#include <vector>
#include <thread>
#include <csignal>
#include <chrono>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <deque>
#include <numeric>
#include <cmath>
#include <map>
#include <set>
#include <list>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

void broadcast_p2p(const std::string& msg);
std::string get_telemetry(const std::string& node_id);
std::string get_neighbors_list();
int recv_full(int sock, char* buffer, size_t total_len, int flags = 0);
void handle_pbft_message(const json& msg);
void pbft_cleanup_and_retransmit();

// ---------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------
#define RSA_KEY_BITS        2048
#define RSA_PADDING         RSA_PKCS1_OAEP_PADDING
#define RSA_OAEP_MD         EVP_sha256()
#define RSA_MGF1_MD         EVP_sha256()
#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define P2P_MULTICAST_IP    "239.0.0.1"
#define P2P_MULTICAST_PORT  9999
#define C2_PORT             8080
#define MAX_BACKOFF_MS      60000
#define MAX_HONEYPOT_CONNECTIONS 100

#define IA_HISTORY_LIMIT    50
#define IA_LEARNING_WARMUP  5
#define IA_ZSCORE_THRESHOLD 15.0 

#define PBFT_PHASE_TIMEOUT_MS  3000
#define PBFT_MAX_ROUNDS        3
#define MSG_TIMESTAMP_TTL_SEC  5

// 🔥 THE FIX: Startup Mask Duration
#define SYSTEM_ARMING_DELAY_SEC 45

std::atomic<bool> keep_running{true};
std::atomic<bool> honeypot_triggered{false};
std::atomic<bool> is_isolated{false};
std::atomic<int> report_interval{5000}; 
std::atomic<unsigned int> active_honeypot_threads{0};
std::atomic<bool> signal_pending{false};
std::atomic<bool> heal_pending{false};

unsigned char session_key[AES_KEY_LEN];

int g_udp_send_sock = -1;
std::mutex g_udp_send_mutex;

#ifdef __linux__
std::unique_ptr<std::ifstream> g_netdev;
std::unique_ptr<std::ifstream> g_diskstats;
std::unique_ptr<std::ifstream> g_filenr;
std::unique_ptr<std::ifstream> g_proc_stat;
#endif

std::string get_agent_auth_token() {
    const char* env_token = std::getenv("NEURO_MESH_SECRET");
    if (!env_token || std::strlen(env_token) == 0) {
        std::cerr << "\033[1;41;37m[FATAL] NEURO_MESH_SECRET missing!\033[0m\n";
        exit(EXIT_FAILURE);
    }
    return std::string(env_token);
}

class LocalTelemetryEmitter {
private:
    int m_sock{-1};
    struct sockaddr_in m_ia_addr{};

public:
    LocalTelemetryEmitter(const std::string& ip, uint16_t port) {
        m_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_sock < 0) throw std::runtime_error("[FATAL] Socket init failed.");
        m_ia_addr.sin_family = AF_INET;
        m_ia_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &m_ia_addr.sin_addr);
    }
    ~LocalTelemetryEmitter() { if (m_sock >= 0) CLOSE_SOCKET(m_sock); }
    void emit(const std::string& payload) const noexcept {
        if (m_sock >= 0) sendto(m_sock, payload.c_str(), payload.length(), 0, (struct sockaddr*)&m_ia_addr, sizeof(m_ia_addr));
    }
};

void init_system_metrics() {
#ifdef __linux__
    g_netdev = std::make_unique<std::ifstream>("/proc/net/dev");
    g_diskstats = std::make_unique<std::ifstream>("/proc/diskstats");
    g_filenr = std::make_unique<std::ifstream>("/proc/sys/fs/file-nr");
    g_proc_stat = std::make_unique<std::ifstream>("/proc/stat");
#endif
}

void init_p2p_socket() {
    g_udp_send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udp_send_sock < 0) throw std::runtime_error("Erreur socket UDP");
    int loopback = 1;
    setsockopt(g_udp_send_sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&loopback, sizeof(loopback));
}

struct MetricSample {
    long ram_mb; double cpu_load; long long net_tx_bs; long long net_rx_bs;
    long long disk_io_bs; long proc_count; long file_open_rate;
};
std::deque<MetricSample> history;
std::mutex history_mutex;
std::atomic<bool> ia_warmup_done{false};

double running_mean[7] = {0};
double running_M2[7] = {0};
int running_count = 0;

struct Neighbor { std::string id; std::string ip; int priority_score; time_t last_seen; };
enum AgentState { NORMAL, ELECTION_MODE, COORDINATOR_MODE };
std::atomic<AgentState> current_state{NORMAL};
std::atomic<bool> received_ok{false};
std::string current_leader_id = "";
std::vector<Neighbor> active_mesh;
std::mutex mesh_mutex;

std::string base64_decode(const std::string& input) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[b64[i]] = i;
    unsigned int val = 0; int valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        if (T[c] == -1) continue;
        val = (val << 6) + T[c]; valb += 6;
        if (valb >= 0) { out.push_back(char((val >> valb) & 0xFF)); valb -= 8; }
    }
    return out;
}

std::string base64_encode(const unsigned char* input, int length) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result; int i = 0; unsigned char c3[3], c4[4];
    while (length--) {
        c3[i++] = *(input++);
        if (i == 3) {
            c4[0] = (c3[0] & 0xfc) >> 2; c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
            c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6); c4[3] = c3[2] & 0x3f;
            for (i = 0; i < 4; i++) result += b64[c4[i]];
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 3; j++) c3[j] = '\0';
        c4[0] = (c3[0] & 0xfc) >> 2; c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
        c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
        for (int j = 0; j < i + 1; j++) result += b64[c4[j]];
        while (i++ < 3) result += '=';
    }
    return result;
}

namespace pbft {
    struct Identity { std::string node_id; EVP_PKEY* privkey; std::string pubkey_pem; };
    struct PeerInfo { std::string id; EVP_PKEY* pubkey; time_t last_seen; };
    enum PBFType { HEARTBEAT = 0, REQUEST, PRE_PREPARE, PREPARE, COMMIT, REPLY };
    enum Phase { IDLE, WAITING_PREPARE, WAITING_COMMIT, DECIDED };

    struct Consensus {
        uint64_t view; uint64_t seq; std::string digest; std::string proposal; Phase phase;
        std::chrono::steady_clock::time_point start_time;
        std::set<std::string> prepare_votes; std::set<std::string> commit_votes;
        bool decided; bool decision_value; int round;
    };

    std::mutex crypto_mutex;
    Identity my_identity;
    std::map<std::string, PeerInfo> known_peers;
    std::mutex peers_mutex;
    std::list<Consensus> active_instances;
    std::mutex instances_mutex;
    std::atomic<uint64_t> next_seq{1};
    std::atomic<uint64_t> current_view{0};

    size_t get_required_quorum() {
        size_t total_nodes = known_peers.size() + 1;
        if (total_nodes < 4) return total_nodes; 
        size_t f = (total_nodes - 1) / 3;
        return (2 * f) + 1;
    }

    std::string sign_data(EVP_PKEY* privkey, const std::string& data) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "";
        if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, privkey) != 1) { EVP_MD_CTX_free(ctx); return ""; }
        size_t sig_len = 0;
        if (EVP_DigestSign(ctx, nullptr, &sig_len, (const unsigned char*)data.c_str(), data.size()) != 1) { EVP_MD_CTX_free(ctx); return ""; }
        std::vector<unsigned char> sig(sig_len);
        if (EVP_DigestSign(ctx, sig.data(), &sig_len, (const unsigned char*)data.c_str(), data.size()) != 1) { EVP_MD_CTX_free(ctx); return ""; }
        EVP_MD_CTX_free(ctx);
        return std::string((char*)sig.data(), sig_len);
    }

    bool verify_sig(EVP_PKEY* pubkey, const std::string& data, const std::string& signature) {
        if (EVP_PKEY_id(pubkey) != EVP_PKEY_ED25519) return false;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pubkey) != 1) { EVP_MD_CTX_free(ctx); return false; }
        int ok = EVP_DigestVerify(ctx, (const unsigned char*)signature.c_str(), signature.size(),
                                  (const unsigned char*)data.c_str(), data.size());
        EVP_MD_CTX_free(ctx);
        return (ok == 1);
    }

    EVP_PKEY* generate_ed25519_key() {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!pctx) return nullptr;
        if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return nullptr; }
        EVP_PKEY* key = nullptr;
        if (EVP_PKEY_keygen(pctx, &key) != 1) { EVP_PKEY_CTX_free(pctx); return nullptr; }
        EVP_PKEY_CTX_free(pctx);
        return key;
    }

    std::string pubkey_to_pem(EVP_PKEY* key) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return "";
        if (PEM_write_bio_PUBKEY(bio, key) != 1) { BIO_free(bio); return ""; }
        char* data; long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len); BIO_free(bio);
        return pem;
    }

    EVP_PKEY* pem_to_pubkey(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());
        if (!bio) return nullptr;
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        return key;
    }

    std::string sha256(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)data.c_str(), data.size(), hash);
        return std::string((char*)hash, SHA256_DIGEST_LENGTH);
    }
}

std::string format_pbft_msg(pbft::PBFType type, uint64_t view, uint64_t seq,
                            const std::string& digest, const std::string& sender,
                            const std::string& signature, uint64_t timestamp) {
    json j; j["type"] = (int)type; j["view"] = view; j["seq"] = seq; j["digest"] = digest; j["sender"] = sender;
    j["sig"] = base64_encode((const unsigned char*)signature.c_str(), signature.size()); j["timestamp"] = timestamp;
    return j.dump();
}

std::string data_to_sign(pbft::PBFType type, uint64_t view, uint64_t seq, const std::string& digest, const std::string& sender, uint64_t timestamp) {
    std::ostringstream oss; oss << (int)type << "|" << view << "|" << seq << "|" << digest << "|" << sender << "|" << timestamp;
    return oss.str();
}

void pbft_init_identity(const std::string& node_id) {
    pbft::my_identity.node_id = node_id;
    pbft::my_identity.privkey = pbft::generate_ed25519_key();
    if (!pbft::my_identity.privkey) { exit(EXIT_FAILURE); }
    pbft::my_identity.pubkey_pem = pbft::pubkey_to_pem(pbft::my_identity.privkey);
}

void pbft_broadcast_heartbeat() {
    std::lock_guard<std::mutex> lock(pbft::crypto_mutex);
    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string data = data_to_sign(pbft::HEARTBEAT, 0, 0, "", pbft::my_identity.node_id, ts);
    std::string sig = pbft::sign_data(pbft::my_identity.privkey, data);
    json j; j["type"] = (int)pbft::HEARTBEAT; j["node_id"] = pbft::my_identity.node_id;
    j["pubkey"] = pbft::my_identity.pubkey_pem; j["sig"] = base64_encode((const unsigned char*)sig.c_str(), sig.size());
    j["timestamp"] = ts; broadcast_p2p("PBFT:" + j.dump());
}

void pbft_propose_isolation(const std::string& suspect_id) {
    if (is_isolated) return;
    uint64_t view = ++pbft::current_view; uint64_t seq = pbft::next_seq++;
    std::string proposal = "ISOLATE:" + suspect_id; std::string digest = pbft::sha256(proposal);
    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    pbft::Consensus cons; cons.view = view; cons.seq = seq; cons.digest = digest; cons.proposal = proposal;
    cons.phase = pbft::WAITING_PREPARE; cons.start_time = std::chrono::steady_clock::now(); cons.decided = false; cons.decision_value = true; cons.round = 1;
    { std::lock_guard<std::mutex> lock(pbft::instances_mutex); pbft::active_instances.push_back(cons); }

    std::lock_guard<std::mutex> lock(pbft::crypto_mutex);
    std::string data_to_sig = data_to_sign(pbft::PRE_PREPARE, view, seq, digest, pbft::my_identity.node_id, ts);
    std::string sig = pbft::sign_data(pbft::my_identity.privkey, data_to_sig);
    broadcast_p2p("PBFT:" + format_pbft_msg(pbft::PRE_PREPARE, view, seq, digest, pbft::my_identity.node_id, sig, ts));
}

void handle_pbft_message(const json& msg) {
    try {
        if (!msg.contains("timestamp")) return;
        uint64_t msg_ts = msg["timestamp"];
        uint64_t now_ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (std::abs((int64_t)now_ts - (int64_t)msg_ts) > MSG_TIMESTAMP_TTL_SEC) return;

        pbft::PBFType type = (pbft::PBFType)msg.at("type").get<int>();
        uint64_t view = msg.at("view"); uint64_t seq = msg.at("seq");
        std::string digest = msg.at("digest"); std::string sender = msg.at("sender");
        std::string sig = base64_decode(msg.at("sig").get<std::string>());

        std::lock_guard<std::mutex> peer_lock(pbft::peers_mutex);
        if (pbft::known_peers.find(sender) == pbft::known_peers.end()) return;
        EVP_PKEY* sender_pub = pbft::known_peers[sender].pubkey;

        std::string data_to_check = data_to_sign(type, view, seq, digest, sender, msg_ts);
        {
            std::lock_guard<std::mutex> crypto_lock(pbft::crypto_mutex);
            if (!pbft::verify_sig(sender_pub, data_to_check, sig)) return;
        }

        switch (type) {
            case pbft::PRE_PREPARE: {
                if (sender == pbft::my_identity.node_id) break;
                std::lock_guard<std::mutex> inst_lock(pbft::instances_mutex);
                bool found = false;
                for (auto& inst : pbft::active_instances) {
                    if (inst.seq == seq && inst.view == view && inst.digest == digest) {
                        found = true;
                        if (inst.phase == pbft::IDLE || inst.phase == pbft::WAITING_PREPARE) {
                            inst.phase = pbft::WAITING_COMMIT;
                            std::lock_guard<std::mutex> cl(pbft::crypto_mutex);
                            uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                            std::string ds = data_to_sign(pbft::PREPARE, view, seq, digest, pbft::my_identity.node_id, ts);
                            std::string s = pbft::sign_data(pbft::my_identity.privkey, ds);
                            broadcast_p2p("PBFT:" + format_pbft_msg(pbft::PREPARE, view, seq, digest, pbft::my_identity.node_id, s, ts));
                        }
                        break;
                    }
                }
                if (!found) {
                    pbft::Consensus new_inst; new_inst.view = view; new_inst.seq = seq; new_inst.digest = digest;
                    new_inst.proposal = "?"; new_inst.phase = pbft::WAITING_COMMIT;
                    new_inst.start_time = std::chrono::steady_clock::now(); new_inst.decided = false; new_inst.round = 1;
                    pbft::active_instances.push_back(new_inst);
                    std::lock_guard<std::mutex> cl(pbft::crypto_mutex);
                    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    std::string ds = data_to_sign(pbft::PREPARE, view, seq, digest, pbft::my_identity.node_id, ts);
                    std::string s = pbft::sign_data(pbft::my_identity.privkey, ds);
                    broadcast_p2p("PBFT:" + format_pbft_msg(pbft::PREPARE, view, seq, digest, pbft::my_identity.node_id, s, ts));
                }
                break;
            }
            case pbft::PREPARE: {
                if (sender == pbft::my_identity.node_id) break;
                std::lock_guard<std::mutex> inst_lock(pbft::instances_mutex);
                for (auto& inst : pbft::active_instances) {
                    if (inst.seq == seq && inst.view == view && inst.digest == digest) {
                        inst.prepare_votes.insert(sender);
                        size_t quorum = pbft::get_required_quorum();
                        if (inst.prepare_votes.size() >= quorum && inst.phase == pbft::WAITING_COMMIT) {
                            inst.phase = pbft::DECIDED;
                            std::lock_guard<std::mutex> cl(pbft::crypto_mutex);
                            uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                            std::string ds = data_to_sign(pbft::COMMIT, view, seq, digest, pbft::my_identity.node_id, ts);
                            std::string s = pbft::sign_data(pbft::my_identity.privkey, ds);
                            broadcast_p2p("PBFT:" + format_pbft_msg(pbft::COMMIT, view, seq, digest, pbft::my_identity.node_id, s, ts));
                        }
                        break;
                    }
                }
                break;
            }
            case pbft::COMMIT: {
                if (sender == pbft::my_identity.node_id) break;
                std::lock_guard<std::mutex> inst_lock(pbft::instances_mutex);
                for (auto& inst : pbft::active_instances) {
                    if (inst.seq == seq && inst.view == view && inst.digest == digest) {
                        inst.commit_votes.insert(sender);
                        size_t quorum = pbft::get_required_quorum();
                        if (inst.commit_votes.size() >= quorum && !inst.decided) {
                            inst.decided = true; inst.decision_value = true;
                            if (inst.proposal.find("ISOLATE:" + pbft::my_identity.node_id) == 0 && !is_isolated) {
                                is_isolated = true; report_interval = 1000; current_state = NORMAL;
                            }
                        }
                        break;
                    }
                }
                break;
            }
            default: break;
        }
    } catch (...) {}
}

void pbft_cleanup_and_retransmit() {
    {
        std::lock_guard<std::mutex> inst_lock(pbft::instances_mutex);
        auto now = std::chrono::steady_clock::now();
        for (auto it = pbft::active_instances.begin(); it != pbft::active_instances.end(); ) {
            if (it->decided) { it = pbft::active_instances.erase(it); continue; }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->start_time).count();
            if (elapsed > PBFT_PHASE_TIMEOUT_MS * it->round) {
                if (it->round < PBFT_MAX_ROUNDS) {
                    std::lock_guard<std::mutex> cl(pbft::crypto_mutex);
                    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    std::string ds = data_to_sign((it->phase == pbft::WAITING_COMMIT) ? pbft::PREPARE : pbft::PRE_PREPARE,
                                                  it->view, it->seq, it->digest, pbft::my_identity.node_id, ts);
                    std::string s = pbft::sign_data(pbft::my_identity.privkey, ds);
                    broadcast_p2p("PBFT:" + format_pbft_msg((it->phase == pbft::WAITING_COMMIT) ? pbft::PREPARE : pbft::PRE_PREPARE,
                                                            it->view, it->seq, it->digest, pbft::my_identity.node_id, s, ts));
                    it->round++; it->start_time = now; ++it;
                } else {
                    it = pbft::active_instances.erase(it);
                }
            } else { ++it; }
        }
    }
    {
        std::lock_guard<std::mutex> peer_lock(pbft::peers_mutex);
        time_t now = time(nullptr);
        for (auto it = pbft::known_peers.begin(); it != pbft::known_peers.end(); ) {
            if (now - it->second.last_seen > 300) { EVP_PKEY_free(it->second.pubkey); it = pbft::known_peers.erase(it); }
            else { ++it; }
        }
    }
}

// ---------------------------------------------------------
// CRYPTOGRAPHY CORE
// ---------------------------------------------------------
std::string encrypt_aes256_gcm(const std::string& plaintext, const unsigned char* key, unsigned char* iv_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "ERREUR";

    if (RAND_bytes(iv_out, AES_GCM_IV_LEN) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_GCM_TAG_LEN); int len = 0, ciphertext_len = 0;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv_out) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.c_str(), plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    ciphertext_len += len;
    
    unsigned char tag[AES_GCM_TAG_LEN]; 
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    EVP_CIPHER_CTX_free(ctx);
    
    std::string result((char*)iv_out, AES_GCM_IV_LEN);
    result.append((char*)ciphertext.data(), ciphertext_len); 
    result.append((char*)tag, AES_GCM_TAG_LEN);
    return result;
}

std::string decrypt_aes256_gcm(const unsigned char* full_msg, size_t full_len, const unsigned char* key) {
    if (full_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) return "ERREUR";
    unsigned char iv[AES_GCM_IV_LEN]; memcpy(iv, full_msg, AES_GCM_IV_LEN);
    const unsigned char* ciphertext = full_msg + AES_GCM_IV_LEN;
    size_t ciphertext_len = full_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const unsigned char* tag = full_msg + AES_GCM_IV_LEN + ciphertext_len;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "ERREUR";

    std::vector<unsigned char> plaintext(ciphertext_len); int len = 0, plaintext_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    plaintext_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    
    plaintext_len += len; EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

std::string rsa_encrypt(EVP_PKEY* pub_key, const unsigned char* data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) return "ERREUR";
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return "ERREUR"; }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, RSA_OAEP_MD);
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, RSA_MGF1_MD);

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, data, data_len) <= 0) { EVP_PKEY_CTX_free(ctx); return "ERREUR"; }
    unsigned char* out = new unsigned char[outlen];
    if (EVP_PKEY_encrypt(ctx, out, &outlen, data, data_len) <= 0) { delete[] out; EVP_PKEY_CTX_free(ctx); return "ERREUR"; }

    std::string result((char*)out, outlen); delete[] out; EVP_PKEY_CTX_free(ctx);
    return result;
}

// ---------------------------------------------------------
// LOCAL TARPIT HONEYPOT
// ---------------------------------------------------------
void tarpit_honeypot(std::stop_token stoken) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    struct sockaddr_in address; address.sin_family = AF_INET; address.sin_addr.s_addr = INADDR_ANY;
    int port = 2222; address.sin_port = htons(port);
    while (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) { port++; address.sin_port = htons(port); if (port > 2250) return; }
    listen(server_fd, 100);

    int flags = fcntl(server_fd, F_GETFL, 0); fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
    std::vector<struct pollfd> fds; fds.push_back({server_fd, POLLIN, 0});
    std::map<int, int> client_ticks; const char* banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n";

    while (!stoken.stop_requested() && keep_running) {
        int ret = poll(fds.data(), fds.size(), 2000); if (ret < 0) break;
        if (fds[0].revents & POLLIN) {
            if (fds.size() >= MAX_HONEYPOT_CONNECTIONS) continue;
            struct sockaddr_in client_addr; socklen_t addrlen = sizeof(client_addr);
            int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
            if (client_socket >= 0) {
                int cflags = fcntl(client_socket, F_GETFL, 0); fcntl(client_socket, F_SETFL, cflags | O_NONBLOCK);
                send(client_socket, banner, strlen(banner), 0);
                fds.push_back({client_socket, POLLOUT, 0});
                client_ticks[client_socket] = 300; honeypot_triggered = true;
            }
        }
        for (size_t i = 1; i < fds.size(); ) {
            int fd = fds[i].fd; bool remove_fd = false;
            if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) { remove_fd = true; } 
            else if (fds[i].revents & POLLOUT) {
                char poison[16]; for (int j = 0; j < 16; ++j) poison[j] = rand() % 256;
                int sent = send(fd, poison, 16, 0);
                if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) { remove_fd = true; } 
                else { client_ticks[fd]--; if (client_ticks[fd] <= 0) remove_fd = true; }
            }
            if (remove_fd) { CLOSE_SOCKET(fd); client_ticks.erase(fd); fds.erase(fds.begin() + i); } else { ++i; }
        }
        active_honeypot_threads = fds.size() - 1;
    }
    for (auto& pfd : fds) CLOSE_SOCKET(pfd.fd);
}

// ---------------------------------------------------------
// TELEMETRY & Z-SCORE
// ---------------------------------------------------------
void collect_local_metrics(long& ram, double& cpu, long long& net_tx, long long& net_rx,
                           long long& disk_io, long& proc_count, long& file_rate) {
#ifdef __linux__
    struct sysinfo memInfo; sysinfo(&memInfo);
    ram = (memInfo.totalram - memInfo.freeram) / (1024 * 1024);
    double loads[1]; cpu = (getloadavg(loads, 1) != -1) ? loads[0] : 0.0;

    proc_count = std::thread::hardware_concurrency(); if (proc_count == 0) proc_count = 1;

    file_rate = 0;
    if (g_filenr && g_filenr->is_open()) { g_filenr->clear(); g_filenr->seekg(0); long a, b, c; (*g_filenr) >> a >> b >> c; file_rate = a; }

    static unsigned long long last_tx = 0, last_rx = 0, last_disk = 0; 
    static auto last_time = std::chrono::steady_clock::now();
    unsigned long long tx = 0, rx = 0, current_disk = 0;
    
    if (g_netdev && g_netdev->is_open()) {
        g_netdev->clear(); g_netdev->seekg(0); std::string line; std::getline(*g_netdev, line); std::getline(*g_netdev, line);
        while (std::getline(*g_netdev, line)) {
            size_t c = line.find(':'); if (c == std::string::npos) continue;
            std::string iface = line.substr(0, c); if (iface.find("lo") != std::string::npos) continue;
            std::istringstream iss(line.substr(c + 1));
            unsigned long long r_b, r_p, r_e, r_d, r_f, r_fr, r_c, r_m, t_b;
            iss >> r_b >> r_p >> r_e >> r_d >> r_f >> r_fr >> r_c >> r_m >> t_b;
            rx += r_b; tx += t_b;
        }
    }
    
    if (g_diskstats && g_diskstats->is_open()) {
        g_diskstats->clear(); g_diskstats->seekg(0); std::string line;
        while (std::getline(*g_diskstats, line)) {
            if (line.find("sda") != std::string::npos || line.find("nvme0n1") != std::string::npos) {
                std::istringstream iss(line); long long d, rs, ws; std::string dev;
                iss >> d >> d >> dev >> d >> d >> rs >> d >> d >> d >> ws;
                current_disk = (rs + ws) * 512; break;
            }
        }
    }

    auto now = std::chrono::steady_clock::now(); double elapsed = std::chrono::duration<double>(now - last_time).count();
    if (elapsed > 0.0) { net_tx = (tx - last_tx) / elapsed; net_rx = (rx - last_rx) / elapsed; disk_io = (current_disk >= last_disk) ? (current_disk - last_disk) / elapsed : 0; } 
    else { net_tx = net_rx = disk_io = 0; }
    
    last_tx = tx; last_rx = rx; last_disk = current_disk; last_time = now;
#else
    ram = cpu = net_tx = net_rx = disk_io = proc_count = file_rate = 0;
#endif
}

void update_ia_history(long ram, double cpu, long long net_tx, long long net_rx,
                       long long disk_io, long proc_count, long file_rate) {
    std::lock_guard<std::mutex> lock(history_mutex);
    MetricSample sample = {ram, cpu, net_tx, net_rx, disk_io, proc_count, file_rate};
    history.push_back(sample); if (history.size() > IA_HISTORY_LIMIT) history.pop_front();
    if (history.size() >= IA_LEARNING_WARMUP) ia_warmup_done.store(true);

    running_count++;
    double values[7] = {(double)ram, cpu, (double)net_tx, (double)net_rx, (double)disk_io, (double)proc_count, (double)file_rate};
    for (int i = 0; i < 7; i++) {
        double delta = values[i] - running_mean[i];
        running_mean[i] += delta / running_count;
        running_M2[i] += delta * (values[i] - running_mean[i]);
    }
}

bool ia_check_anomaly(long ram, double cpu, long long net_tx, long long net_rx,
                      long long disk_io, long proc_count, long file_rate) {
    if (!ia_warmup_done.load() || running_count < 2) return false;
    double cur[7] = {(double)ram, cpu, (double)net_tx, (double)net_rx, (double)disk_io, (double)proc_count, (double)file_rate};

    double min_variance_floor[7] = {
        500.0, 5.0, 52428800.0, 52428800.0, 52428800.0, 50.0, 20000.0
    }; 

    for (int i = 0; i < 7; i++) {
        double stddev = std::max(std::sqrt(running_M2[i] / (running_count - 1)), min_variance_floor[i]);
        if (cur[i] > running_mean[i]) {
            double z_score = (cur[i] - running_mean[i]) / stddev;
            if (z_score > IA_ZSCORE_THRESHOLD) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------
// BULLY ELECTION & P2P
// ---------------------------------------------------------
void broadcast_p2p(const std::string& msg) {
    if (g_udp_send_sock < 0) return;
    struct sockaddr_in mcast_addr; mcast_addr.sin_family = AF_INET; mcast_addr.sin_port = htons(P2P_MULTICAST_PORT); mcast_addr.sin_addr.s_addr = inet_addr(P2P_MULTICAST_IP);
    std::lock_guard<std::mutex> lock(g_udp_send_mutex);
    sendto(g_udp_send_sock, msg.c_str(), msg.length(), 0, (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
}

void broadcast_bully_signed(const std::string& type, const std::string& payload) {
    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string pk_b64 = base64_encode((const unsigned char*)pbft::my_identity.pubkey_pem.c_str(), pbft::my_identity.pubkey_pem.size());
    std::string full_msg = type + "|" + pbft::my_identity.node_id + "|" + payload + "|" + std::to_string(ts) + "|" + pk_b64;
    std::string sig = pbft::sign_data(pbft::my_identity.privkey, full_msg);
    broadcast_p2p("BULLY:" + full_msg + "|" + base64_encode((unsigned char*)sig.c_str(), sig.size()));
}

int calculate_priority() {
    static int tie_breaker = -1;
    if (tie_breaker == -1) { unsigned char rb; RAND_bytes(&rb, 1); tie_breaker = rb; }
    long usedRAM = 0; int procs = 0;
#ifdef __linux__
    struct sysinfo memInfo; sysinfo(&memInfo);
    usedRAM = (memInfo.totalram - memInfo.freeram) * memInfo.mem_unit / (1024 * 1024); procs = memInfo.procs;
#endif
    return (procs * 1000) + (int)usedRAM + tie_breaker;
}

void start_bully_election(std::string my_id) {
    if (is_isolated) return;
    current_state = ELECTION_MODE; received_ok = false; int my_score = calculate_priority();
    srand(time(nullptr) + GET_PID()); int jitter_ms = 3000 + (rand() % 4000); 

    std::cout << "\033[1;33m[VOTE]\033[0m Élection dans " << jitter_ms << " ms\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_ms));
    if(!keep_running) return;
    broadcast_bully_signed("MSG_VOTE", std::to_string(my_score));
    std::this_thread::sleep_for(std::chrono::seconds(5));
    if(!keep_running) return;

    if (!received_ok && !is_isolated) {
        current_state = COORDINATOR_MODE; current_leader_id = my_id;
        std::cout << "\033[1;45;37m [SYSTEME] NOUVEAU LEADER \033[0m\n";
        broadcast_bully_signed("MSG_COORDINATOR", "");
    } else { current_state = NORMAL; }
}

void listen_for_neighbors(std::stop_token stoken, std::string my_id) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int opt = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#ifndef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&opt, sizeof(opt));
#endif
    struct sockaddr_in recv_addr; recv_addr.sin_family = AF_INET; recv_addr.sin_port = htons(P2P_MULTICAST_PORT); recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr));
    struct ip_mreq mreq; mreq.imr_multiaddr.s_addr = inet_addr(P2P_MULTICAST_IP); mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));

    int flags = fcntl(sock, F_GETFL, 0); fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    struct TokenBucket { double tokens; time_t last_update; const double rate = 50.0; const double capacity = 50.0; };
    std::map<std::string, TokenBucket> rate_limiters;

    while (!stoken.stop_requested() && keep_running) {
        char buffer[65536] = {0}; struct sockaddr_in sender_addr; socklen_t sender_len = sizeof(sender_addr);
        int bytes = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&sender_addr, &sender_len);
        
        if (bytes <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
        if (is_isolated) continue;

        std::string sender_ip = inet_ntoa(sender_addr.sin_addr);
        std::string sender_key = sender_ip + ":" + std::to_string(ntohs(sender_addr.sin_port));
        time_t now_sec = time(nullptr);
        
        auto& bucket = rate_limiters[sender_key];
        if (bucket.last_update == 0) { bucket.tokens = bucket.capacity; bucket.last_update = now_sec; }
        double elapsed = difftime(now_sec, bucket.last_update);
        bucket.tokens = std::min(bucket.capacity, bucket.tokens + (elapsed * bucket.rate));
        bucket.last_update = now_sec;

        if (bucket.tokens < 1.0) continue; 
        bucket.tokens -= 1.0;

        std::string msg(buffer, bytes);
        if (msg.rfind("BULLY:", 0) == 0) {
            try {
                std::string content = msg.substr(6);
                size_t last_pipe = content.rfind('|'); if (last_pipe == std::string::npos) continue;
                std::string signed_part = content.substr(0, last_pipe);
                std::string sig = base64_decode(content.substr(last_pipe + 1));

                std::vector<std::string> parts; size_t pos = 0;
                while (pos < signed_part.size()) {
                    size_t pipe = signed_part.find('|', pos);
                    if (pipe == std::string::npos) { parts.push_back(signed_part.substr(pos)); break; }
                    parts.push_back(signed_part.substr(pos, pipe - pos)); pos = pipe + 1;
                }
                if (parts.size() != 5) continue;

                std::string type = parts[0], sender = parts[1], payload = parts[2], pk_b64 = parts[4];
                uint64_t msg_ts = std::stoull(parts[3]);
                uint64_t now_ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (std::abs((long long)now_ts - (long long)msg_ts) > MSG_TIMESTAMP_TTL_SEC) continue;

                bool sig_ok = false;
                {
                    std::lock_guard<std::mutex> peer_lock(pbft::peers_mutex);
                    if (pbft::known_peers.find(sender) == pbft::known_peers.end()) {
                        std::string pem = base64_decode(pk_b64); EVP_PKEY* pub = pbft::pem_to_pubkey(pem);
                        if (pub) pbft::known_peers[sender] = {sender, pub, time(nullptr)};
                    } else { pbft::known_peers[sender].last_seen = time(nullptr); }
                    auto it = pbft::known_peers.find(sender);
                    if (it != pbft::known_peers.end()) {
                        std::lock_guard<std::mutex> crypto_lock(pbft::crypto_mutex);
                        sig_ok = pbft::verify_sig(it->second.pubkey, signed_part, sig);
                    }
                }
                if (!sig_ok) continue;

                if (type == "MSG_VOTE" && sender != my_id) {
                    int sender_score = std::stoi(payload); int my_score = calculate_priority();
                    if (my_score > sender_score) {
                        broadcast_bully_signed("MSG_OK", "");
                        if (current_state != ELECTION_MODE) std::thread(start_bully_election, my_id).detach();
                    } else if (my_score < sender_score) { received_ok = true; current_state = NORMAL; }
                } else if (type == "MSG_OK" && sender != my_id) { received_ok = true;
                } else if (type == "MSG_COORDINATOR" && sender != my_id) { current_leader_id = sender; current_state = NORMAL; }
            } catch (...) { continue; }
        }

        if (msg.rfind("PBFT:", 0) == 0) {
            try {
                json pbft_msg = json::parse(msg.substr(5));
                if (pbft_msg.contains("type") && pbft_msg["type"] == (int)pbft::HEARTBEAT) {
                    std::string node_id = pbft_msg["node_id"];
                    if (node_id != my_id) {
                        std::lock_guard<std::mutex> plock(pbft::peers_mutex);
                        if (pbft::known_peers.find(node_id) == pbft::known_peers.end()) {
                            EVP_PKEY* pub = pbft::pem_to_pubkey(pbft_msg["pubkey"]);
                            if (pub) pbft::known_peers[node_id] = {node_id, pub, time(nullptr)};
                        } else { pbft::known_peers[node_id].last_seen = time(nullptr); }

                        std::lock_guard<std::mutex> mlock(mesh_mutex); bool found_m = false;
                        for (auto& n : active_mesh) { if (n.id == node_id) { n.last_seen = time(nullptr); found_m = true; break; } }
                        if (!found_m) active_mesh.push_back({node_id, "P2P", 0, time(nullptr)});
                    }
                } else { handle_pbft_message(pbft_msg); }
            } catch (...) {}
        }
    }
    CLOSE_SOCKET(sock);
}

std::string get_neighbors_list() {
    std::lock_guard<std::mutex> lock(mesh_mutex); std::string neighbors;
    for (size_t i = 0; i < active_mesh.size(); ++i) {
        if (i > 0) neighbors += ","; neighbors += active_mesh[i].id;
    }
    return neighbors;
}

std::string get_telemetry(const std::string& id) {
    long r, p_c, f_r; double c; long long tx, rx, d_io;
    collect_local_metrics(r, c, tx, rx, d_io, p_c, f_r);
    char host[256]; gethostname(host, 256);
    json j; j["ID"] = id; j["HOST"] = host; j["RAM_MB"] = r; j["CPU_LOAD"] = c; j["PROCS"] = p_c;
    j["NET_OUT"] = tx; j["NET_RX"] = rx; j["DISK_IO"] = d_io; j["FILE_RATE"] = f_r;
    j["NEIGHBORS"] = get_neighbors_list();
    j["STATUS"] = is_isolated.load() ? "SELF_ISOLATED" : "STABLE";
    j["ATTACK"] = honeypot_triggered.load() ? "TRUE" : "FALSE";
    j["STATE"] = (current_state == COORDINATOR_MODE) ? "COORDINATOR" : "NORMAL";
    return j.dump();
}

// ---------------------------------------------------------
// OS SIGNALS
// ---------------------------------------------------------
void isolation_signal_handler(int) { signal_pending = true; }
void heal_signal_handler(int) { heal_pending = true; } 
void graceful_shutdown_handler(int) { keep_running = false; }

int recv_full(int sock, char* buffer, size_t total_len, int flags) {
    size_t r = 0; while (r < total_len) { int res = recv(sock, buffer + r, total_len - r, flags); if (res <= 0) return -1; r += res; }
    return (int)r;
}

// ---------------------------------------------------------
// MAIN EXECUTION LOOP
// ---------------------------------------------------------
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, isolation_signal_handler);
    signal(SIGUSR2, heal_signal_handler); 
    signal(SIGINT, graceful_shutdown_handler);
    signal(SIGTERM, graceful_shutdown_handler);
#endif
    OpenSSL_add_all_algorithms(); srand(time(nullptr));

    try { init_system_metrics(); init_p2p_socket(); }
    catch (const std::exception& e) { return EXIT_FAILURE; }

    std::string auto_id = "NODE_" + std::to_string(GET_PID());
    pbft_init_identity(auto_id);

    // Track when the agent booted
    auto agent_boot_time = std::chrono::steady_clock::now();

    // RESTORED: All critical background threads
    std::jthread honeypot_thread(tarpit_honeypot);
    std::jthread p2p_listener_thread(listen_for_neighbors, auto_id);

    std::jthread pbft_heartbeat_thread([](std::stop_token stoken) { 
        while (!stoken.stop_requested() && keep_running) { 
            if (!is_isolated) pbft_broadcast_heartbeat(); 
            std::this_thread::sleep_for(std::chrono::milliseconds(5000)); 
        } 
    });

    std::jthread pbft_cleanup_thread([](std::stop_token stoken) { 
        while (!stoken.stop_requested() && keep_running) { 
            pbft_cleanup_and_retransmit(); 
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); 
        } 
    });

    std::jthread telemetry_thread([auto_id, agent_boot_time](std::stop_token stoken) {
        std::unique_ptr<LocalTelemetryEmitter> telemetry_emitter;
        try { telemetry_emitter = std::make_unique<LocalTelemetryEmitter>("127.0.0.1", 9998); } 
        catch (const std::exception& e) { keep_running = false; return; }

        while (!stoken.stop_requested() && keep_running) {
            
            auto now = std::chrono::steady_clock::now();
            int uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(now - agent_boot_time).count();
            
            // 🔥 THE FIX: The Startup Transient Mask
            // The agent will not trigger auto-isolation during the first 45 seconds
            // to absorb the massive CPU/File IO spike caused by React compiling.
            bool system_armed = (uptime_sec >= SYSTEM_ARMING_DELAY_SEC);

            if (signal_pending) {
                signal_pending = false; 
                if (system_armed) {
                    std::cout << "\033[1;41;37m[KERNEL eBPF]\033[0m Menace confirmée. Isolation...\n";
                    is_isolated = true; pbft_propose_isolation(auto_id);
                } else {
                    std::cout << "\033[1;33m[BOOT MASK]\033[0m Signal noyau ignoré (Transient OS Load).\n";
                }
            }

            if (heal_pending) {
                heal_pending = false; is_isolated = false; honeypot_triggered = false;
                report_interval = 5000; current_state = NORMAL;
            }

            long r, p_c, f_r; double c; long long tx, rx, d_io;
            collect_local_metrics(r, c, tx, rx, d_io, p_c, f_r);
            update_ia_history(r, c, tx, rx, d_io, p_c, f_r);

            if (ia_check_anomaly(r, c, tx, rx, d_io, p_c, f_r) && !is_isolated) {
                if (system_armed) {
                    std::cout << "\033[1;41;37m[Z-SCORE]\033[0m Anomalie confirmée. Isolation...\n";
                    pbft_propose_isolation(auto_id);
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                } else {
                    std::cout << "\033[1;33m[BOOT MASK]\033[0m Anomalie Z-Score ignorée (Transient OS Load).\n";
                }
            }

            std::string t_data = get_telemetry(auto_id);
            std::string payload = "TELEMETRY:" + t_data;
            telemetry_emitter->emit(payload);

            std::this_thread::sleep_for(std::chrono::milliseconds(report_interval.load()));
        }
    });

    std::string agent_auth_token = get_agent_auth_token();

    while (keep_running) {
        int backoff = 1000; bool c2_connected = false;
        while (keep_running) {
            if (c2_connected) { SLEEP_MS(backoff); backoff = std::min(backoff * 2, MAX_BACKOFF_MS); c2_connected = false; }
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) { SLEEP_MS(backoff); backoff = std::min(backoff * 2, MAX_BACKOFF_MS); continue; }

            struct sockaddr_in serv; serv.sin_family = AF_INET; serv.sin_port = htons(C2_PORT);
            inet_pton(AF_INET, "127.0.0.1", &serv.sin_addr);

            if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
                CLOSE_SOCKET(sock); SLEEP_MS(backoff); backoff = std::min(backoff * 2, MAX_BACKOFF_MS); continue;
            }

            char pk_b[4096]; int pk_l = recv(sock, pk_b, 4095, 0);
            if (pk_l <= 0) { CLOSE_SOCKET(sock); continue; }
            pk_b[pk_l] = '\0'; 

            BIO* bio = BIO_new_mem_buf(pk_b, pk_l); EVP_PKEY* pk = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr); BIO_free(bio);
            if (!pk) { CLOSE_SOCKET(sock); continue; } 

            unsigned char aes[32]; unsigned char iv[12]; 
            if (RAND_bytes(aes, 32) != 1 || RAND_bytes(iv, 12) != 1) { EVP_PKEY_free(pk); CLOSE_SOCKET(sock); continue; }

            unsigned char mat[44]; memcpy(mat, aes, 32); memcpy(mat+32, iv, 12);
            std::string enc_mat = rsa_encrypt(pk, mat, 44); EVP_PKEY_free(pk);
            if (enc_mat == "ERREUR" || send(sock, enc_mat.c_str(), enc_mat.size(), 0) <= 0) { CLOSE_SOCKET(sock); continue; }

            memcpy(session_key, aes, 32);
            std::string auth = encrypt_aes256_gcm("AUTH:" + agent_auth_token, session_key, iv);
            if (auth == "ERREUR") { CLOSE_SOCKET(sock); continue; }

            uint32_t al = htonl(auth.size()); send(sock, &al, 4, 0); send(sock, auth.c_str(), auth.size(), 0);
            SLEEP_MS(200); c2_connected = true;

            while (c2_connected && keep_running) {
                std::string data = get_telemetry(auto_id);
                unsigned char iv_m[12]; std::string enc = encrypt_aes256_gcm(data, session_key, iv_m);
                if (enc == "ERREUR") break;

                uint32_t ml = htonl(enc.size());
                if (send(sock, &ml, 4, 0) != 4 || send(sock, enc.c_str(), enc.size(), 0) != (int)enc.size()) break;

                fd_set read_fds; FD_ZERO(&read_fds); FD_SET(sock, &read_fds);
                struct timeval timeout; timeout.tv_sec = 0; timeout.tv_usec = 100000;

                int sel_res = select(sock + 1, &read_fds, nullptr, nullptr, &timeout);
                if (sel_res > 0) {
                    uint32_t cl; int r = recv_full(sock, (char*)&cl, 4);
                    if (r == 4) {
                        cl = ntohl(cl); std::vector<char> cb(cl);
                        if (recv_full(sock, cb.data(), cl) != (int)cl) break;

                        std::string decrypted_cmd = decrypt_aes256_gcm((unsigned char*)cb.data(), cl, session_key);
                        if (decrypted_cmd != "ERREUR") {
                            std::string cmd_part = decrypted_cmd;
                            size_t pipe_pos = decrypted_cmd.find('|');
                            if (pipe_pos != std::string::npos) cmd_part = decrypted_cmd.substr(0, pipe_pos);

                            if (cmd_part == "CMD:REJOIN" && is_isolated) {
                                is_isolated = false; honeypot_triggered = false;
                                report_interval = 5000; current_state = NORMAL;
                            }
                        }
                    } else if (r <= 0) { break; }
                } else if (sel_res < 0) { break; }

                SLEEP_MS(report_interval.load());
            }
            CLOSE_SOCKET(sock);
        }
    }

    if (g_udp_send_sock >= 0) CLOSE_SOCKET(g_udp_send_sock);
    return 0;
}
