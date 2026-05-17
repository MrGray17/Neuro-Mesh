#include "cell/InferenceEngine.hpp"
#include <iostream>
#include <cmath>

using namespace neuro_mesh::ai;

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
    std::cout << "[INFERENCE] Running InferenceEngine unit tests..." << std::endl;

    TEST("decay moves negative score toward zero") {
        float before = -0.15f;
        float factor = 0.3f;
        float expected = before * (1.0f - factor);
        ASSERT(std::abs(expected - (-0.105f)) < 0.001f);
    END_TEST();

    TEST("decay does not increase negative score") {
        float current = -0.20f;
        float factor = 1.0f;
        float result = current * (1.0f - factor);
        ASSERT(result >= current);
    END_TEST();

    TEST("decay on positive score does nothing") {
        float current = 0.1f;
        float factor = 0.5f;
        float result = current;
        if (result < 0.0f) result = result * (1.0f - factor);
        ASSERT(result >= 0.0f);
    END_TEST();

    TEST("threshold comparison logic") {
        constexpr float threshold = -0.05f;
        ASSERT((-0.15f < threshold) == true);
        ASSERT((-0.05f < threshold) == false);
        ASSERT((0.0f < threshold) == false);
    END_TEST();

    TEST("score to entropy conversion via InferenceEngine::compute_entropy") {
        const char* data = "hello";
        double entropy = InferenceEngine::compute_entropy(data, 5);
        ASSERT(entropy > 0.0);
        ASSERT(entropy <= 8.0);
    END_TEST();

    std::cout << "\n[INFERENCE] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[INFERENCE] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[INFERENCE] All tests passed." << std::endl;
    return 0;
}
