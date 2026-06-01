/**
 * tools/attack_injector.cpp
 *
 * UDP attack injector for neuro-mesh adversarial testing.
 * Sends forged VOTE|PRE_PREPARE|... messages to 127.0.0.1:9999
 * with random sender_ids, invalid signatures, and minimal evidence.
 *
 * Build: make bin/attack_injector
 * Run:   ./bin/attack_injector [--duration S] [--rate N] [--target TARGET_NODE]
 */

#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common/Base64.hpp"

using namespace neuro_mesh;

static const char* TARGET_IP = "127.0.0.1";
static const int TARGET_PORT = 9999;
static const int DEFAULT_DURATION = 5;
static const int DEFAULT_RATE = 50;       // msgs/sec (stays under 100/s per-IP limit)
static const int DEFAULT_THREADS = 4;     // threads (each with own socket/IP variation)

static const char* NODES[] = {"ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO"};
static const int NUM_NODES = 5;

static std::string make_evidence() {
    // Minimal valid evidence JSON
    return base64_encode(R"({"e":"attack_flood","ts":0,"entropy":6.28})");
}

static std::string make_fake_sig() {
    // 64 bytes of random data, base64 encoded (Ed25519 sig is 64 bytes)
    static std::mt19937_64 rng(std::random_device{}());
    std::string raw(64, '\0');
    for (int i = 0; i < 64; ++i) raw[i] = static_cast<char>(rng() & 0xFF);
    return base64_encode(raw);
}

static void attack_thread(int thread_id, int duration_s, int rate,
                          const std::string& target_node, const std::string& attacker_id) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { std::cerr << "socket failed\n"; return; }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TARGET_PORT);
    inet_pton(AF_INET, TARGET_IP, &addr.sin_addr);

    std::mt19937_64 rng(std::random_device{}() + thread_id * 10007);
    auto t0 = std::chrono::steady_clock::now();
    int budget = rate * duration_s;

    for (int i = 0; i < budget; ++i) {
        std::string sender = attacker_id.empty()
            ? (std::string("STRESS_T") + std::to_string(thread_id) + "_M" + std::to_string(i))
            : attacker_id;

        // Random seq/view
        uint64_t seq = rng();
        int view = static_cast<int>(rng() % 1000);

        // Random target from known nodes
        const char* tgt = (target_node.empty() || target_node == "RANDOM")
            ? NODES[rng() % NUM_NODES]
            : target_node.c_str();

        std::string msg = "VOTE|PRE_PREPARE|" + sender +
            "|" + std::to_string(seq) +
            "|" + std::to_string(view) +
            "|" + tgt +
            "|" + make_evidence() +
            "|deadbeef0123456789abcdefdeadbeef0123456789abcdefdeadbeef0123456789abcdef" +
            "|" + make_fake_sig();

        sendto(sock, msg.data(), msg.size(), 0,
               reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        if (i > 0 && i % (rate * 2) == 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            int expected = static_cast<int>(1000.0 * i / rate);
            if (elapsed < expected) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(expected - elapsed));
            }
        }
    }

    close(sock);
}

int main(int argc, char** argv) {
    int duration = DEFAULT_DURATION;
    int rate = DEFAULT_RATE;
    int threads = DEFAULT_THREADS;
    std::string target = "RANDOM";
    std::string attacker_id;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--duration" && i + 1 < argc) duration = std::stoi(argv[++i]);
        else if (arg == "--rate" && i + 1 < argc) rate = std::stoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc) threads = std::stoi(argv[++i]);
        else if (arg == "--target" && i + 1 < argc) target = argv[++i];
        else if (arg == "--attacker-id" && i + 1 < argc) attacker_id = argv[++i];
    }

    int total = threads * rate * duration;
    std::cout << "[ATTACK] Sending " << total << " forged VOTE messages to "
              << TARGET_IP << ":" << TARGET_PORT
              << " (" << threads << " x " << rate << "/s x " << duration << "s)" << std::endl;
    if (!target.empty() && target != "RANDOM")
        std::cout << "[ATTACK] All messages target: " << target << std::endl;
    if (!attacker_id.empty())
        std::cout << "[ATTACK] Fixed sender_id: " << attacker_id << std::endl;

    std::vector<std::thread> workers;
    auto t0 = std::chrono::steady_clock::now();
    for (int t = 0; t < threads; t++) {
        workers.emplace_back(attack_thread, t, duration, rate, target, attacker_id);
    }
    for (auto& w : workers) w.join();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    std::cout << "[ATTACK] Done. " << elapsed << "ms elapsed." << std::endl;
    return 0;
}
