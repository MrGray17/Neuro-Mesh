/**
 * tools/register_attacker.cpp
 *
 * Generates Ed25519 keypair, prints PEM to stdout (for NEURO_PEER_KEYS env var),
 * and sends a signed ANNOUNCE message to 127.0.0.1:9999 to register the attacker
 * with pre-provisioned peers.
 *
 * Build: make bin/register_attacker
 * Usage:  ./bin/register_attacker ATTACKER_ID
 */

#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "common/Base64.hpp"
#include "crypto/CryptoCore.hpp"

using namespace neuro_mesh;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: register_attacker <ATTACKER_ID>" << std::endl;
        return 1;
    }
    std::string id(argv[1]);

    auto priv = crypto::IdentityCore::generate_ed25519_key();
    if (!priv) { std::cerr << "Key gen failed" << std::endl; return 1; }

    std::string pub_pem = crypto::IdentityCore::get_pem_from_pubkey(priv.get());

    // Print PEM for NEURO_PEER_KEYS env var
    std::string pem_b64 = base64_encode(pub_pem);
    std::cout << "NEURO_PEER_KEYS=" << id << ":" << pem_b64 << std::endl;

    std::string blob = id + "|" + pub_pem;
    std::string sig = crypto::IdentityCore::sign_payload(priv.get(), blob);
    std::string announce = "ANNOUNCE|" + id + "|" + pub_pem + "|" + base64_encode(sig);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int n = sendto(sock, announce.data(), announce.size(), 0,
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(sock);

    std::cout << "[REGISTER] Sent ANNOUNCE for " << id
              << " (" << n << " bytes)" << std::endl;
    return 0;
}
