#include "consensus/MeshNode.hpp"
#include "enforcer/PolicyEnforcer.hpp"
#include "enforcer/MitigationEngine.hpp"
#include "telemetry/TelemetryBridge.hpp"
#include <iostream>
#include <sstream>

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
    std::cout << "[MESGNODE] Running MeshNode unit tests..." << std::endl;

    TEST("split_string basic delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a|b|c", '|');
        ASSERT(tokens.size() == 3);
        ASSERT(tokens[0] == "a");
        ASSERT(tokens[1] == "b");
        ASSERT(tokens[2] == "c");
    END_TEST();

    TEST("split_string empty string") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("", '|');
        ASSERT(tokens.empty());
    END_TEST();

    TEST("split_string single token") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("single", '|');
        ASSERT(tokens.size() == 1);
        ASSERT(tokens[0] == "single");
    END_TEST();

    TEST("split_string trailing delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a|b|", '|');
        ASSERT(tokens.size() == 2);
        ASSERT(tokens[0] == "a");
        ASSERT(tokens[1] == "b");
    END_TEST();

    TEST("split_string consecutive delimiters") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("a||b", '|');
        ASSERT(tokens.size() == 3);
        ASSERT(tokens[1] == "");
    END_TEST();

    TEST("split_string no delimiter") {
        MeshNode node("NODE_1", nullptr, nullptr, nullptr);
        auto tokens = node.split_string("nodelimiter", '|');
        ASSERT(tokens.size() == 1);
        ASSERT(tokens[0] == "nodelimiter");
    END_TEST();

    TEST("peer_count starts with self") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        ASSERT(node.peer_count() == 1);
    END_TEST();

    TEST("get_active_peer_ids returns empty initially") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        auto ids = node.get_active_peer_ids();
        ASSERT(ids.empty());
    END_TEST();

    TEST("is_targeted_recently false initially") {
        PolicyEnforcer enforcer;
        MitigationEngine mitigation(&enforcer);
        TelemetryBridge bridge({});
        MeshNode node("NODE_1", &enforcer, &mitigation, &bridge);
        ASSERT(!node.is_targeted_recently());
    END_TEST();

    std::cout << "\n[MESHNODE] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[MESHNODE] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[MESHNODE] All tests passed. MeshNode logic is correct." << std::endl;
    return 0;
}
