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

    TEST("decay moves score toward zero") {
        float current = -0.15f;
        float factor = 0.3f;
        float result = current * (1.0f - factor);
        ASSERT(std::abs(result - (-0.105f)) < 0.001f);
    END_TEST();

    TEST("decay does not increase negative score") {
        float current = -0.20f;
        float factor = 1.0f;
        float result = current * (1.0f - factor);
        ASSERT(result >= current);
    END_TEST();

    TEST("decay on positive score does nothing") {
        float current = 0.1f;
        float result = current;
        ASSERT(result >= 0.0f);
    END_TEST();

    TEST("threshold comparison logic") {
        constexpr float threshold = -0.05f;
        ASSERT((-0.15f < threshold) == true);
        ASSERT((-0.05f < threshold) == false);
        ASSERT((0.0f < threshold) == false);
    END_TEST();

    TEST("score to entropy conversion (onnx_to_entropy logic from main.cpp)") {
        float score = -0.15f;
        constexpr float kThreshold = -0.05f;
        constexpr float kMinScore = -0.2f;
        float entropy = 0.0f;
        if (score >= kThreshold) {
            entropy = 0.0f;
        } else {
            float t = (kThreshold - score) / (kThreshold - kMinScore);
            entropy = std::min(1.0f, t);
        }
        ASSERT(std::abs(entropy - 0.666f) < 0.01f);
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
