// Fuzz target for beacon parser (built via make fuzz)
#include <cstdint>
#include <cstddef>
#include <string>
#include "net/TransportLayer.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    neuro_mesh::net::PeerDiscovery discovery("FUZZ_NODE");

    std::string input(reinterpret_cast<const char*>(data), size);

    // Call handle_incoming_beacon with arbitrary data
    // This should never crash, even with malformed input
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_port = htons(12345);
    src.sin_addr.s_addr = htonl(0x7f000001);

    discovery.handle_incoming_beacon(input.data(), input.size(), src);

    return 0;
}
