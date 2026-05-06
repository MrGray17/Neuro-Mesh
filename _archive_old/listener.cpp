// ============================================================
// NEURO-MESH C2 : STAFF ENGINEER EDITION (ATOMIC I/O & RESILIENCE)
// ============================================================
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <csignal>
#include <ctime>
#include <chrono>
#include <map>
#include <set>
#include <mutex>
#include <atomic>
#include <deque>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <fcntl.h>
#include <sys/file.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void log_event_safe(const std::string& message);
void export_to_json();

#define RSA_KEY_BITS        2048
#define RSA_PADDING         RSA_PKCS1_OAEP_PADDING
#define RSA_OAEP_MD         EVP_sha256()
#define RSA_MGF1_MD         EVP_sha256()
#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define SESSION_MATERIAL_LEN (AES_KEY_LEN + AES_GCM_IV_LEN)
#define RECV_BUFFER_SIZE    65536
#define RSA_ENCRYPTED_LEN   256
#define MAX_LOG_ENTRIES     1000
#define JSON_FILE           "api.json"
#define WS_PORT             8081
#define MAX_C2_CONNECTIONS  500

struct AgentNode {
    std::string id = "PENDING";
    std::string hostname = "UNKNOWN";
    std::string ip = "0.0.0.0";
    std::string neighbors = "";
    long ram_mb = 0;
    double cpu_load = 0.0;
    int procs = 0;
    long latency = 0;
    long net_out = 0;
    long long net_tx_bs = 0;
    long long net_rx_bs = 0;
    long long disk_io_bs = 0;
    long file_rate = 0;
    std::string status = "HANDSHAKE";
    std::string p2p_state = "NORMAL";
    unsigned char session_key[AES_KEY_LEN];

    ~AgentNode() {
        OPENSSL_cleanse(session_key, AES_KEY_LEN);
    }
};

std::map<int, AgentNode> active_nodes;
std::map<std::string, AgentNode> historical_alerts;

std::deque<std::string> security_logs;
std::mutex system_mutex;
std::mutex log_mutex;
EVP_PKEY *server_rsa_key = nullptr;
std::atomic<unsigned int> active_c2_connections{0};

std::set<int> ws_clients;
std::mutex ws_mutex;

struct ConnectionGuard {
    std::atomic<unsigned int>& counter;
    ConnectionGuard(std::atomic<unsigned int>& c) : counter(c) { counter++; }
    ~ConnectionGuard() { if (counter > 0) counter--; }
};

std::string get_c2_auth_token() {
    const char* env_token = std::getenv("NEURO_MESH_SECRET");
    if (!env_token || std::strlen(env_token) == 0) {
        std::cerr << "\033[1;41;37m[FATAL] NEURO_MESH_SECRET environment variable is missing on C2!\033[0m\n";
        exit(EXIT_FAILURE);
    }
    return std::string(env_token);
}

std::string base64_encode(const unsigned char* input, int length) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result; int i = 0; unsigned char char_array_3[3], char_array_4[4];
    while (length--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) result += b64[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (int j = 0; j < i + 1; j++) result += b64[char_array_4[j]];
        while (i++ < 3) result += '=';
    }
    return result;
}

std::string websocket_accept_key(const std::string& key) {
    std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = key + magic; unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)combined.c_str(), combined.size(), sha);
    return base64_encode(sha, SHA_DIGEST_LENGTH);
}

void ws_send(int fd, const std::string& message) {
    std::vector<unsigned char> frame;
    frame.push_back(0x81);
    size_t len = message.size();
    if (len <= 125) { frame.push_back(len); } 
    else if (len <= 65535) { frame.push_back(126); frame.push_back((len >> 8) & 0xFF); frame.push_back(len & 0xFF); } 
    else { frame.push_back(127); for (int i = 7; i >= 0; i--) frame.push_back((len >> (i * 8)) & 0xFF); }
    frame.insert(frame.end(), message.begin(), message.end());
    if (send(fd, (char*)frame.data(), frame.size(), MSG_NOSIGNAL) <= 0) close(fd);
}

void cleanup_dead_websockets() {
    std::lock_guard<std::mutex> lock(ws_mutex);
    for (auto it = ws_clients.begin(); it != ws_clients.end(); ) {
        int fd = *it; char buf;
        ssize_t r = recv(fd, &buf, 1, MSG_DONTWAIT | MSG_PEEK);
        if (r == 0 || (r == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            close(fd); it = ws_clients.erase(it);
        } else { ++it; }
    }
}

void broadcast_websocket(const std::string& json_content) {
    std::lock_guard<std::mutex> lock(ws_mutex);
    for (int fd : ws_clients) ws_send(fd, json_content);
}

void websocket_server_thread() {
    int ws_fd = socket(AF_INET, SOCK_STREAM, 0); if (ws_fd < 0) return;
    int opt = 1; setsockopt(ws_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(ws_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_addr.s_addr = INADDR_ANY; addr.sin_port = htons(WS_PORT);
    if (bind(ws_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(ws_fd); return; }
    listen(ws_fd, 10);
    log_event_safe("[WEBSOCKET] Serveur actif sur le port " + std::to_string(WS_PORT));

    auto last_cleanup = std::chrono::steady_clock::now();
    while (true) {
        struct sockaddr_in client_addr; socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(ws_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;

        auto now = std::chrono::steady_clock::now();
        if (now - last_cleanup > std::chrono::seconds(5)) { cleanup_dead_websockets(); last_cleanup = now; }

        char buffer[4096] = {0}; recv(client_fd, buffer, sizeof(buffer)-1, 0);
        std::string request(buffer); std::string req_lower = request;
        std::transform(req_lower.begin(), req_lower.end(), req_lower.begin(), ::tolower);
        size_t key_pos = req_lower.find("sec-websocket-key: ");
        if (key_pos != std::string::npos) {
            size_t start_val = key_pos + 19; size_t end_val = request.find("\r\n", start_val);
            if (end_val == std::string::npos) end_val = request.find("\n", start_val);
            std::string key = request.substr(start_val, end_val - start_val);
            while(!key.empty() && (key.back() == '\r' || key.back() == '\n' || key.back() == ' ')) key.pop_back();

            std::string accept_key = websocket_accept_key(key);
            std::string response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
            send(client_fd, response.c_str(), response.size(), 0);

            { std::lock_guard<std::mutex> lock(ws_mutex); ws_clients.insert(client_fd); }

            std::ifstream json_file(JSON_FILE);
            if (json_file.is_open()) {
                std::string content((std::istreambuf_iterator<char>(json_file)), std::istreambuf_iterator<char>());
                json_file.close(); ws_send(client_fd, content);
            }
        } else { close(client_fd); }
    }
    close(ws_fd);
}

int recv_full(int sock, char* buffer, size_t total_len, int flags = 0) {
    size_t received = 0;
    while (received < total_len) {
        ssize_t r = recv(sock, buffer + received, total_len - received, flags);
        if (r <= 0) return -1;
        received += r;
    }
    return static_cast<int>(received);
}

void log_event_safe(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    time_t now = time(0); struct tm tstruct = *localtime(&now); char buf[80];
    strftime(buf, sizeof(buf), "[%H:%M:%S]", &tstruct);
    std::string full_msg = std::string(buf) + " " + message;
    
    if (security_logs.size() >= MAX_LOG_ENTRIES) security_logs.pop_front();
    security_logs.push_back(full_msg); 
    std::cout << "\033[1;30m" << full_msg << "\033[0m" << std::endl;
}

// ============================================================
// DATA EXPORT (Lock-Free I/O Optimization & Atomic Renames)
// ============================================================
void export_to_json() {
    static auto last_export = std::chrono::steady_clock::now() - std::chrono::milliseconds(1000);
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_export).count() < 100) return;
    last_export = now;

    std::ifstream cmd_file("ia_commands.txt");
    if (cmd_file.is_open()) {
        std::string line;
        std::lock_guard<std::mutex> lock(system_mutex);
        while (std::getline(cmd_file, line)) {
            if (line.find("CMD_IA:ISOLATE|") != std::string::npos) {
                std::string target_id = line.substr(15);
                for (auto& pair : active_nodes) {
                    if (pair.second.id == target_id) {
                        pair.second.status = "COMPROMIS";
                    }
                }
            }
        }
        cmd_file.close();
    }

    std::vector<AgentNode> snapshot_nodes;
    std::vector<AgentNode> snapshot_alerts;
    std::vector<std::string> snapshot_logs;

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        for (const auto& p : active_nodes) snapshot_nodes.push_back(p.second);
        for (const auto& p : historical_alerts) snapshot_alerts.push_back(p.second);
    }
    
    {
        std::lock_guard<std::mutex> lock(log_mutex);
        size_t start = (security_logs.size() > 15) ? security_logs.size() - 15 : 0;
        for (size_t i = start; i < security_logs.size(); ++i) snapshot_logs.push_back(security_logs[i]);
    }

    json j;
    j["architecture"] = "NEURO-MESH (Sovereign Distributed C2)";
    j["system_status"] = "ONLINE";
    j["active_nodes"] = json::array();

    for (const auto& node : snapshot_nodes) {
        json node_json;
        node_json["id"] = node.id; node_json["hostname"] = node.hostname; node_json["ip"] = node.ip;
        node_json["ram_mb"] = node.ram_mb; node_json["cpu_load"] = node.cpu_load; node_json["procs"] = node.procs;
        node_json["latency"] = node.latency; node_json["net_out_bytes_s"] = node.net_out; node_json["net_tx_bs"] = node.net_tx_bs;
        node_json["net_rx_bs"] = node.net_rx_bs; node_json["disk_io_bs"] = node.disk_io_bs; node_json["file_rate"] = node.file_rate;
        node_json["neighbors"] = node.neighbors; node_json["status"] = node.status; node_json["p2p_state"] = node.p2p_state;
        j["active_nodes"].push_back(node_json);
    }

    for (const auto& node : snapshot_alerts) {
        json node_json;
        node_json["id"] = node.id; node_json["hostname"] = node.hostname; node_json["ip"] = node.ip;
        node_json["ram_mb"] = node.ram_mb; node_json["cpu_load"] = node.cpu_load; node_json["procs"] = node.procs;
        node_json["latency"] = node.latency; node_json["net_out_bytes_s"] = node.net_out; node_json["net_tx_bs"] = node.net_tx_bs;
        node_json["net_rx_bs"] = node.net_rx_bs; node_json["disk_io_bs"] = node.disk_io_bs; node_json["file_rate"] = node.file_rate;
        node_json["neighbors"] = node.neighbors; node_json["status"] = node.status; node_json["p2p_state"] = "ISOLATED";
        j["active_nodes"].push_back(node_json);
    }

    j["logs"] = json::array();
    for (const auto& log : snapshot_logs) j["logs"].push_back(log);

    std::string dump_content = j.dump();

    // 🛡️ THE FIX: Thread-unique temporary files + Atomic rename to prevent TOCTOU tears
    std::ostringstream tmp_filename;
    tmp_filename << "api_tmp_" << std::this_thread::get_id() << ".json";
    std::string unique_tmp_file = tmp_filename.str();

    std::ofstream file(unique_tmp_file);
    if (file.is_open()) { 
        file << dump_content; 
        file.close(); 
        std::rename(unique_tmp_file.c_str(), JSON_FILE); 
    }
    
    broadcast_websocket(dump_content);
}

std::string rsa_decrypt(EVP_PKEY* priv_key, const unsigned char* encrypted_data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) return "";
    if (EVP_PKEY_decrypt_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return ""; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, RSA_OAEP_MD) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, RSA_MGF1_MD) <= 0) { EVP_PKEY_CTX_free(ctx); return ""; }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted_data, data_len) <= 0) { EVP_PKEY_CTX_free(ctx); return ""; }
    unsigned char* out = new unsigned char[outlen];
    if (EVP_PKEY_decrypt(ctx, out, &outlen, encrypted_data, data_len) <= 0) { delete[] out; EVP_PKEY_CTX_free(ctx); return ""; }
    std::string result(reinterpret_cast<char*>(out), outlen); OPENSSL_cleanse(out, outlen); delete[] out; EVP_PKEY_CTX_free(ctx);
    return result;
}

EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); return nullptr; }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

std::string get_public_key_pem(EVP_PKEY* pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) { BIO_free(bio); return ""; }
    char *data = nullptr; long len = BIO_get_mem_data(bio, &data); std::string result(data, len); BIO_free(bio);
    return result;
}

std::string encrypt_aes256_gcm(const std::string& plaintext, const unsigned char* key, unsigned char* iv_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    RAND_bytes(iv_out, AES_GCM_IV_LEN); std::vector<unsigned char> ciphertext(plaintext.size() + AES_GCM_TAG_LEN);
    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv_out) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.c_str(), plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); return ""; }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return ""; }
    ciphertext_len += len; unsigned char tag[AES_GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return ""; }
    EVP_CIPHER_CTX_free(ctx);
    std::string result((char*)iv_out, AES_GCM_IV_LEN); result.append((char*)ciphertext.data(), ciphertext_len); result.append((char*)tag, AES_GCM_TAG_LEN);
    return result;
}

std::string decrypt_aes256_gcm(const unsigned char* full_msg, size_t full_len, const unsigned char* key) {
    if (full_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) return "ERREUR";
    unsigned char iv[AES_GCM_IV_LEN]; memcpy(iv, full_msg, AES_GCM_IV_LEN);
    const unsigned char* ciphertext = full_msg + AES_GCM_IV_LEN;
    size_t ciphertext_len = full_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const unsigned char* tag = full_msg + AES_GCM_IV_LEN + ciphertext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return "ERREUR";
    std::vector<unsigned char> plaintext(ciphertext_len); int len = 0, plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    plaintext_len += len; EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

std::string get_neighbor_list_unsafe(int requester_sock) {
    std::string list = "NEIGHBORS:";
    for (auto const& [sock, node] : active_nodes) {
        if (sock != requester_sock && node.status != "HANDSHAKE") list += node.ip + ",";
    }
    return list;
}

void broadcast_alert_unsafe(int compromised_socket, const std::string& threat_host) {
    log_event_safe("[SAGESSE COLLECTIVE] Propagation de l'alerte r├®seau. Cible initiale : " + threat_host);
    for (auto const& [sock, node] : active_nodes) {
        if (sock != compromised_socket && node.status == "STABLE") {
            std::string alert_msg = "CMD:GLOBAL_ALERT|" + threat_host;
            unsigned char iv[AES_GCM_IV_LEN];
            std::string encrypted = encrypt_aes256_gcm(alert_msg, node.session_key, iv);
            uint32_t out_len = htonl(encrypted.size());
            if (send(sock, &out_len, 4, 0) == 4) send(sock, encrypted.c_str(), encrypted.size(), 0);
        }
    }
}

void handle_client(int client_socket, struct sockaddr_in client_addr) {
    if (active_c2_connections >= MAX_C2_CONNECTIONS) { close(client_socket); return; }
    ConnectionGuard guard(active_c2_connections);

    char client_ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    AgentNode this_node; this_node.ip = std::string(client_ip);

    struct timeval tv; tv.tv_sec = 40; tv.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    std::string pub_key_pem = get_public_key_pem(server_rsa_key);
    if (send(client_socket, pub_key_pem.c_str(), pub_key_pem.length(), 0) < 0) { close(client_socket); return; }

    unsigned char rsa_buffer[RSA_ENCRYPTED_LEN]; int total_received = 0;
    while (total_received < RSA_ENCRYPTED_LEN) {
        int bytes = recv(client_socket, rsa_buffer + total_received, RSA_ENCRYPTED_LEN - total_received, 0);
        if (bytes <= 0) { close(client_socket); return; }
        total_received += bytes;
    }

    std::string decrypted_session = rsa_decrypt(server_rsa_key, rsa_buffer, RSA_ENCRYPTED_LEN);
    if (decrypted_session.size() < SESSION_MATERIAL_LEN) { close(client_socket); return; }
    memcpy(this_node.session_key, decrypted_session.c_str(), AES_KEY_LEN); OPENSSL_cleanse((void*)decrypted_session.data(), decrypted_session.size());

    this_node.status = "STABLE"; this_node.latency = 5000;

    uint32_t auth_len;
    if (recv_full(client_socket, (char*)&auth_len, 4) == 4) {
        auth_len = ntohl(auth_len);
        if (auth_len > 0 && auth_len <= 4096) {
            std::vector<char> auth_buf(auth_len);
            if (recv_full(client_socket, auth_buf.data(), auth_len) == (int)auth_len) {
                std::string decrypted_auth = decrypt_aes256_gcm((unsigned char*)auth_buf.data(), auth_len, this_node.session_key);
                std::string expected_auth = "AUTH:" + get_c2_auth_token();
                if (decrypted_auth != expected_auth) {
                    log_event_safe("\033[1;41;37m[ALERT] Invalid auth token from " + std::string(client_ip) + "!\033[0m");
                    close(client_socket); 
                    return;
                }
            } else { close(client_socket); return; }
        } else { close(client_socket); return; }
    } else { close(client_socket); return; }

    {
        std::lock_guard<std::mutex> lock(system_mutex); active_nodes[client_socket] = this_node;
    }
    log_event_safe("[ACC├êS] Connexion TCP ├®tablie et synchronis├®e : " + std::string(client_ip));
    export_to_json();

    bool is_first_message = true; auto last_msg_time = std::chrono::steady_clock::now();

    while (true) {
        uint32_t msg_len; if (recv_full(client_socket, (char*)&msg_len, 4) != 4) break;
        msg_len = ntohl(msg_len); if (msg_len == 0 || msg_len > 65536) break;
        std::vector<char> enc_buf(msg_len); if (recv_full(client_socket, enc_buf.data(), msg_len) != (int)msg_len) break;

        std::string decrypted = decrypt_aes256_gcm((unsigned char*)enc_buf.data(), msg_len, this_node.session_key);
        if (decrypted == "ERREUR") continue;

        try {
            json j = json::parse(decrypted);
            if (j.contains("ID") && j["ID"].is_string()) this_node.id = j["ID"].get<std::string>();
            if (j.contains("HOST") && j["HOST"].is_string()) this_node.hostname = j["HOST"].get<std::string>();
            if (j.contains("RAM_MB") && j["RAM_MB"].is_number()) this_node.ram_mb = j["RAM_MB"].get<long>();
            if (j.contains("CPU_LOAD") && j["CPU_LOAD"].is_number()) this_node.cpu_load = j["CPU_LOAD"].get<double>();
            if (j.contains("PROCS") && j["PROCS"].is_number()) this_node.procs = j["PROCS"].get<int>();
            if (j.contains("NET_OUT") && j["NET_OUT"].is_number()) this_node.net_out = j["NET_OUT"].get<long>();
            if (j.contains("NEIGHBORS") && j["NEIGHBORS"].is_string()) this_node.neighbors = j["NEIGHBORS"].get<std::string>();
            if (j.contains("net_tx_bs") && j["net_tx_bs"].is_number()) this_node.net_tx_bs = j["net_tx_bs"].get<long long>();
            if (j.contains("net_rx_bs") && j["net_rx_bs"].is_number()) this_node.net_rx_bs = j["net_rx_bs"].get<long long>();
            if (j.contains("disk_io_bs") && j["disk_io_bs"].is_number()) this_node.disk_io_bs = j["disk_io_bs"].get<long long>();
            if (j.contains("file_rate") && j["file_rate"].is_number()) this_node.file_rate = j["file_rate"].get<long>();

            if (j.contains("ATTACK") && j["ATTACK"].is_string() && j["ATTACK"] == "TRUE") this_node.status = "COMPROMIS";
            if (j.contains("STATUS") && j["STATUS"].is_string() && j["STATUS"] == "SELF_ISOLATED") {
                this_node.status = "COMPROMIS"; log_event_safe("\033[1;41;37m[SELF-ISOLATION]\033[0m Agent " + this_node.id + " s'est auto-isol├®.");
            }
            if (j.contains("STATE") && j["STATE"].is_string()) {
                std::string state = j["STATE"].get<std::string>();
                if (state == "COORDINATOR" && this_node.p2p_state != "COORDINATOR") {
                    this_node.p2p_state = "COORDINATOR";
                    log_event_safe("\033[1;36m[R├ëSILIENCE]\033[0m L'agent " + this_node.id + " a maintenu le maillage !");
                } else { this_node.p2p_state = state; }
            }
        } catch (...) { continue; }

        auto current_time = std::chrono::steady_clock::now();
        long diff = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_msg_time).count();
        last_msg_time = current_time; if (is_first_message) { diff = 5000; is_first_message = false; }
        this_node.latency = diff;

        std::string command_to_send;
        {
            std::lock_guard<std::mutex> lock(system_mutex);
            auto it = active_nodes.find(client_socket);
            if (it != active_nodes.end() && it->second.status == "COMPROMIS") { this_node.status = "COMPROMIS"; }
            if (this_node.status == "COMPROMIS" || diff < 400) {
                bool was_stable = (active_nodes[client_socket].status != "COMPROMIS");
                this_node.status = "COMPROMIS"; command_to_send = "CMD:ISOLATE_NETWORK"; active_nodes[client_socket] = this_node;
                if (was_stable) { 
                    log_event_safe("\033[1;41;37m[INTRUSION]\033[0m Menace confirm├®e sur " + this_node.hostname); 
                    broadcast_alert_unsafe(client_socket, this_node.hostname); 
                }
            } else { 
                this_node.status = "STABLE"; 
                command_to_send = "CMD:STANDBY|" + get_neighbor_list_unsafe(client_socket); 
                active_nodes[client_socket] = this_node; 
            }
        }
        
        export_to_json();

        unsigned char iv_out[AES_GCM_IV_LEN]; std::string encrypted_cmd = encrypt_aes256_gcm(command_to_send, this_node.session_key, iv_out);
        uint32_t out_len = htonl(encrypted_cmd.size());
        if (send(client_socket, &out_len, 4, 0) != 4) break;
        if (send(client_socket, encrypted_cmd.c_str(), encrypted_cmd.size(), 0) != (ssize_t)encrypted_cmd.size()) break;
    }

    shutdown(client_socket, SHUT_WR); char drain_buf[128]; while(recv(client_socket, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0) {} close(client_socket);

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        if (active_nodes.count(client_socket)) {
            if (active_nodes[client_socket].status == "COMPROMIS" || active_nodes[client_socket].status == "SELF_ISOLATED") {
                AgentNode saved_node = active_nodes[client_socket]; saved_node.status = "DISCONNECTED_ALERT"; historical_alerts[saved_node.id] = saved_node;
            }
            active_nodes.erase(client_socket);
        }
    }
    export_to_json();
}

void hide_process_name(int argc, char* argv[]) {
#ifdef __linux__
    if (argc > 0) { char* p = argv[0]; size_t len = strlen(p); const char* fake_name = "[kworker/u4:2]"; size_t fake_len = strlen(fake_name); if (fake_len <= len) { strcpy(p, fake_name); for (size_t i = fake_len; i < len; ++i) p[i] = ' '; } }
#else
    (void)argc; (void)argv;
#endif
}

int main(int argc, char* argv[]) {
    hide_process_name(argc, argv);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0); int opt = 1; setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in address; address.sin_family = AF_INET; address.sin_addr.s_addr = INADDR_ANY; address.sin_port = htons(8080);
    bind(server_fd, (struct sockaddr*)&address, sizeof(address)); listen(server_fd, 50);

    server_rsa_key = generate_rsa_key(); log_event_safe("C2 Backend en route sur le port 8080.");

    std::thread(websocket_server_thread).detach();

    while (true) {
        struct sockaddr_in client_addr; socklen_t client_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (new_socket >= 0) { std::thread([fd = new_socket, addr = client_addr]() { handle_client(fd, addr); }).detach(); }
    }
    return 0;
}
