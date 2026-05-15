#include "consensus/MeshNode.hpp"
#include "enforcer/PolicyEnforcer.hpp"
#include "enforcer/MitigationEngine.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include <iostream>
#include <cassert>
#include <sstream>

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

// Helper to call private validate_message via friend or by creating minimal MeshNode
// For this test, we'll test the public API surface and split_string directly

int main() {
    std::cout << "[MESGNODE] Running MeshNode unit tests..." << std::endl;

    // =========================================================================
    TEST("split_string basic delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a|b|c", '|');
        assert(tokens.size() == 3);
        assert(tokens[0] == "a");
        assert(tokens[1] == "b");
        assert(tokens[2] == "c");
    END_TEST();

    // =========================================================================
    TEST("split_string empty string") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("", '|');
        assert(tokens.size() == 0);  // empty input = no tokens
    END_TEST();

    // =========================================================================
    TEST("split_string single token") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("single", '|');
        assert(tokens.size() == 1);
        assert(tokens[0] == "single");
    END_TEST();

    // =========================================================================
    TEST("split_string trailing delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a|b|", '|');
        assert(tokens.size() == 2);  // trailing empty dropped
        assert(tokens[0] == "a");
        assert(tokens[1] == "b");
    END_TEST();

    // =========================================================================
    TEST("split_string consecutive delimiters") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a||b", '|');
        assert(tokens.size() == 3);
        assert(tokens[1] == "");
    END_TEST();

    // =========================================================================
    TEST("split_string no delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("nodelimiter", '|');
        assert(tokens.size() == 1);
        assert(tokens[0] == "nodelimiter");
    END_TEST();

    // =========================================================================
    TEST("peer_count starts with self") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        // With no peers, peer_count should be 1 (self)
        assert(node.peer_count() == 1);
    END_TEST();

    // =========================================================================
    TEST("get_active_peer_ids returns empty initially") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        auto ids = node.get_active_peer_ids();
        assert(ids.empty());
    END_TEST();

    // =========================================================================
    TEST("is_targeted_recently false initially") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        // Should be false at start - no recent targeting
        bool targeted = node.is_targeted_recently();
        assert(!targeted);
    END_TEST();

    // =========================================================================
    std::cout << "\n[MESHNODE] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[MESHNODE] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[MESHNODE] All tests passed. MeshNode logic is correct." << std::endl;
    return 0;
}