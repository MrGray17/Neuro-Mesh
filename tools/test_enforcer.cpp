#include "enforcer/PolicyEnforcer.hpp"
#include <iostream>

using namespace neuro_mesh;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        std::cout << "  " << (name) << "... "; \
        try

#define ASSERT(cond) \
        if (!(cond)) { throw std::runtime_error("assertion failed: " #cond); }

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

    TEST("is_valid_ipv4 accepts standard dotted-quad") {
        ASSERT(PolicyEnforcer::is_valid_ipv4("192.168.1.1"));
        ASSERT(PolicyEnforcer::is_valid_ipv4("10.0.0.1"));
        ASSERT(PolicyEnforcer::is_valid_ipv4("127.0.0.1"));
        ASSERT(PolicyEnforcer::is_valid_ipv4("0.0.0.0"));
        ASSERT(PolicyEnforcer::is_valid_ipv4("255.255.255.255"));
    END_TEST();

    TEST("is_valid_ipv4 rejects non-standard formats") {
        ASSERT(!PolicyEnforcer::is_valid_ipv4("1.2.3"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("0x7f000001"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("2130706433"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("1"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4(""));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("not_an_ip"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("192.168.1"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("192.168.1.1.1"));
        ASSERT(!PolicyEnforcer::is_valid_ipv4("256.1.1.1"));
    END_TEST();

    TEST("is_loopback detects 127.0.0.0/8") {
        ASSERT(PolicyEnforcer::is_loopback("127.0.0.1"));
        ASSERT(PolicyEnforcer::is_loopback("127.0.0.0"));
        ASSERT(PolicyEnforcer::is_loopback("127.255.255.255"));
        ASSERT(PolicyEnforcer::is_loopback("127.1.2.3"));
        ASSERT(!PolicyEnforcer::is_loopback("10.0.0.1"));
        ASSERT(!PolicyEnforcer::is_loopback("192.168.1.1"));
        ASSERT(!PolicyEnforcer::is_loopback("0.0.0.0"));
    END_TEST();

    TEST("is_valid_ipv6 accepts standard IPv6") {
        ASSERT(PolicyEnforcer::is_valid_ipv6("::1"));
        ASSERT(PolicyEnforcer::is_valid_ipv6("2001:db8::1"));
        ASSERT(PolicyEnforcer::is_valid_ipv6("fe80::1"));
        ASSERT(PolicyEnforcer::is_valid_ipv6("::ffff:192.0.2.1"));
        ASSERT(!PolicyEnforcer::is_valid_ipv6("not_ipv6"));
        ASSERT(!PolicyEnforcer::is_valid_ipv6(""));
    END_TEST();

    TEST("is_valid_ip accepts both IPv4 and IPv6") {
        ASSERT(PolicyEnforcer::is_valid_ip("192.168.1.1"));
        ASSERT(PolicyEnforcer::is_valid_ip("::1"));
        ASSERT(!PolicyEnforcer::is_valid_ip("not_an_ip"));
    END_TEST();

    TEST("add_safe_node and is_safe") {
        PolicyEnforcer enforcer;
        ASSERT(!enforcer.is_safe("ALPHA"));
        enforcer.add_safe_node("ALPHA");
        ASSERT(enforcer.is_safe("ALPHA"));
        ASSERT(!enforcer.is_safe("BRAVO"));
    END_TEST();

    TEST("register_peer_ip and resolve_target") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("ALPHA", "192.168.1.10");
        enforcer.register_peer_ip("BRAVO", "10.0.0.5");
        ASSERT(enforcer.resolve_target("ALPHA") == "192.168.1.10");
        ASSERT(enforcer.resolve_target("BRAVO") == "10.0.0.5");
        ASSERT(enforcer.resolve_target("172.16.0.1") == "172.16.0.1");
        ASSERT(enforcer.resolve_target("UNKNOWN").empty());
    END_TEST();

    TEST("register_peer_ip rejects invalid IPs") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("NODE", "not_an_ip");
        ASSERT(enforcer.resolve_target("NODE").empty());
    END_TEST();

    TEST("register_peer_ip rejects empty node_id") {
        PolicyEnforcer enforcer;
        enforcer.register_peer_ip("", "192.168.1.1");
        ASSERT(enforcer.resolve_target("").empty());
    END_TEST();

    std::cout << "\n[ENFORCER] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[ENFORCER] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[ENFORCER] All tests passed. PolicyEnforcer logic is correct." << std::endl;
    return 0;
}
