#pragma once

#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>
#include <string>

namespace neuro_mesh {
namespace net {

// Resolves a hostname to an IPv4 dotted-decimal string.
// Fast path: if `host` is already a numeric IP, returns it unchanged.
// Slow path: one-time DNS lookup via getaddrinfo().
// Returns the original host string on failure so the caller can handle it.
inline std::string resolve_host(const std::string& host) {
    struct in_addr ip_buf;
    if (inet_pton(AF_INET, host.c_str(), &ip_buf) == 1) {
        return host;
    }

    struct addrinfo hints{}, *res{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG;

    int ret = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (ret == 0 && res) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr,
                  ip_str, sizeof(ip_str));
        std::string resolved(ip_str);
        freeaddrinfo(res);
        return resolved;
    }

    std::cerr << "[ERROR] DNS resolution failed for: " << host
              << " (" << gai_strerror(ret) << ")" << std::endl;
    return host;
}

}  // namespace net
}  // namespace neuro_mesh
