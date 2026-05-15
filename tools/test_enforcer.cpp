#include "enforcer/PolicyEnforcer.hpp"
#include <iostream>
#include <cassert>

using namespace neuro_mesh;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        std::cout << "  " << (name) << "... "; \
        try

#define END_TEST() \
        std::cout << "PASSED" << std::endl; \
        ++tests_passed; \
        } catch (const std::exception& e) { \
            std::cout << "FAILED: " << e.what() << std::endl; \
            ++tests_failed; \
        } \
    } while(0)

int main() {
    std::cout << "[ENFORCER] Running PolicyEnforcer unit tests..." << std::endl;

    // =========================================================================
    TEST("is_valid_ipv4 accepts standard dotted-quad") {
        assert(PolicyEnforcer::is_valid_ipv4("192.168.1.1"));
        assert(PolicyEnforcer::is_valid_ipv4("10.0.0.1"));
        assert(PolicyEnforcer::is_valid_ipv4("127.0.0.1"));
        assert(PolicyEnforcer::is_valid_ipv4("0.0.0.0"));
        assert(PolicyEnforcer::is_valid_ipv4("255.255.255.255"));
    END_TEST();

    // =========================================================================
    TEST("is_valid_ipv4 rejects non-standard formats") {
        // inet_aton would accept these, but our strict check rejects them
        assert(!PolicyEnforcer::is_valid_ipv4("1.2.3"));        // 3-octet shorthand
        assert(!PolicyEnforcer::is_valid_ipv4("0x7f000001"));   // hex format
        assert(!PolicyEnforcer::is_valid_ipv4("2130706433"));    // decimal integer
        assert(!PolicyEnforcer::is_valid_ipv4("1"));             // single octet
        assert(!PolicyEnforcer::is_valid_ipv4(""));              // empty
        assert(!PolicyEnforcer::is_valid_ipv4("not_an_ip"));     // garbage
        assert(!PolicyEnforcer::is_valid_ipv4("192.168.1"));     // 3 octets
        assert(!PolicyEnforcer::is_valid_ipv4("192.168.1.1.1")); // 5 octets
        assert(!PolicyEnforcer::is_valid_ipv4("256.1.1.1"));     // octet > 255
    END_TEST();

    // =========================================================================
    TEST("is_loopback detects 127.0.0.0/8") {
        assert(PolicyEnforcer::is_loopback("127.0.0.1"));
        assert(PolicyEnforcer::is_loopback("127.0.0.0"));
        assert(PolicyEnforcer::is_loopback("127.255.255.255"));
        assert(PolicyEnforcer::is_loopback("127.1.2.3"));
        assert(!PolicyEnforcer::is_loopback("10.0.0.1"));
        assert(!PolicyEnforcer::is_loopback("192.168.1.1"));
        assert(!PolicyEnforcer::is_loopback("0.0.0.0"));
    END_TEST();

    // =========================================================================
    TEST("is_valid_ipv6 accepts standard IPv6") {
        assert(PolicyEnforcer::is_valid_ipv6("::1"));
        assert(PolicyEnforcer::is_valid_ipv6("2001:db8::1"));
        assert(PolicyEnforcer::is_valid_ipv6("fe80::1"));
        assert(PolicyEnforcer::is_valid_ipv6("::ffff:192.0.2.1"));
        assert(!PolicyEnforcer::is_valid_ipv6("not_ipv6"));
        assert(!PolicyEnforcer::is_valid_ipv6(""));
    END_TEST();

    // =========================================================================
    TEST("is_valid_ip accepts both IPv4 and IPv6") {
        assert(PolicyEnforcer::is_valid_ip("192.168.1.1"));
        assert(PolicyEnforcer::is_valid_ip("::1"));
        assert(!PolicyEnforcer::is_valid_ip("not_an_ip"));
    END_TEST();

    // =========================================================================
    TEST("add_safe_node and is_safe") {
        PolicyEnforcer enforcer;
        assert(!enforcer.is_safe("ALPHA"));  // not safe by default

        enforcer.add_safe_node("ALPHA");
        assert(enforcer.is_safe("ALPHA"));
        assert(!enforcer.is_safe("BRAVO"));  // different node
    END_TEST();

    // =========================================================================
    TEST("register_peer_ip and resolve_target") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("ALPHA", "192.168.1.10");
        enforcer.register_peer_ip("BRAVO", "10.0.0.5");

        // Resolve by node ID
        assert(enforcer.resolve_target("ALPHA") == "192.168.1.10");
        assert(enforcer.resolve_target("BRAVO") == "10.0.0.5");

        // IP passthrough (if target already looks like an IP)
        assert(enforcer.resolve_target("172.16.0.1") == "172.16.0.1");

        // Unknown node returns empty
        assert(enforcer.resolve_target("UNKNOWN").empty());
    END_TEST();

    // =========================================================================
    TEST("register_peer_ip rejects invalid IPs") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("NODE", "not_an_ip");
        assert(enforcer.resolve_target("NODE").empty());  // not stored
    END_TEST();

    // =========================================================================
    TEST("register_peer_ip rejects empty node_id") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("", "192.168.1.1");
        assert(enforcer.resolve_target("").empty());
    END_TEST();

    // =========================================================================
    std::cout << "\n[ENFORCER] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[ENFORCER] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[ENFORCER] All tests passed. PolicyEnforcer logic is correct." << std::endl;
    return 0;
}
