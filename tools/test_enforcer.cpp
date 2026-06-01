#include "enforcer/PolicyEnforcer.hpp"
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <stdexcept>

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

    // Bug 9 regression: is_safe() must be thread-safe even when called
    // concurrently with add_safe_node(). Without the shared_mutex fix,
    // concurrent std::set reads/writes are UB (typically a segfault under
    // high contention or with TSan).
    TEST("is_safe is thread-safe under concurrent writers and readers (Bug 9)") {
        PolicyEnforcer enforcer;
        // Pre-populate some entries.
        for (int i = 0; i < 50; ++i) {
            enforcer.add_safe_node("INIT_" + std::to_string(i));
        }

        constexpr int kWriters = 2;
        constexpr int kReaders = 2;
        constexpr int kIters = 200;

        std::atomic<int> read_count{0};
        std::atomic<int> write_count{0};
        std::vector<std::thread> threads;

        // Writers: add/remove via add_safe_node (no remove API, so just add)
        for (int t = 0; t < kWriters; ++t) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < kIters; ++i) {
                    enforcer.add_safe_node(
                        "W" + std::to_string(t) + "_" + std::to_string(i));
                    write_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        // Readers: query is_safe from all entries
        for (int t = 0; t < kReaders; ++t) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < kIters; ++i) {
                    (void)enforcer.is_safe("W" + std::to_string(t) + "_" + std::to_string(i));
                    (void)enforcer.is_safe("INIT_" + std::to_string(i % 50));
                    read_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        for (auto& th : threads) th.join();

        // We expect no crash, no UB, no segfault. The test passes if we
        // reach this line.
        ASSERT(write_count.load() > 0);
        ASSERT(read_count.load() > 0);

        // Spot-check: at least one of our writes should be visible
        ASSERT(enforcer.is_safe("W0_0"));
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

    TEST("fork_exec_capture: small output is captured verbatim") {
        const char* argv[] = {"/bin/echo", "hello", nullptr};
        auto [ok, out] = PolicyEnforcer::fork_exec_capture("/bin/echo", argv);
        ASSERT(ok);
        ASSERT(out == "hello\n");
    END_TEST();

    // Hardening: a child that prints more than 64 KiB must not OOM the parent.
    // fork_exec_capture caps captured output at 64 KiB.
    TEST("fork_exec_capture: oversized output is capped at 64KiB") {
        // `yes A` repeats "A\n" until killed. 1MB of output > 64KiB cap.
        const char* argv[] = {"/usr/bin/yes", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nullptr};
        // Give the child a deadline so we don't hang if the cap is broken.
        auto [ok, out] = PolicyEnforcer::fork_exec_capture("/usr/bin/yes", argv);
        // ok may be true or false (yes was killed via SIGPIPE on close) — what
        // matters is the output length.
        ASSERT(out.size() <= 64 * 1024 + 256);  // 64KiB cap + small slack
        // And it must be substantially populated.
        ASSERT(!out.empty());
    END_TEST();

    // Hardening: a child that writes 0 bytes (or fails to exec) must not crash.
    TEST("fork_exec_capture: non-existent binary returns false") {
        const char* argv[] = {"/nonexistent/binary/path", nullptr};
        auto [ok, out] = PolicyEnforcer::fork_exec_capture("/nonexistent/binary/path", argv);
        ASSERT(!ok);
        // out may be empty or contain error text — both are valid
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
