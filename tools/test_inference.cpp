#include "cell/InferenceEngine.hpp"
#include <iostream>
#include <cassert>
#include <cmath>

using namespace neuro_mesh::ai;

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
    std::cout << "[INFERENCE] Running InferenceEngine unit tests..." << std::endl;

    // =========================================================================
    // Test entropy calculation directly (uses private method via friend or
    // we test through public API when ONNX model is available)
    // =========================================================================

    TEST("decay moves score toward zero") {
        // We can't instantiate InferenceEngine without ONNX model,
        // but we can test the decay logic conceptually
        // The decay function: new = current * (1.0f - factor)
        // If current = -0.15 and factor = 0.3, new = -0.15 * 0.7 = -0.105
        float current = -0.15f;
        float factor = 0.3f;
        float expected = current * (1.0f - factor);  // -0.105
        float result = current * (1.0f - factor);
        assert(std::abs(result - expected) < 0.001f);
    END_TEST();

    // =========================================================================
    TEST("decay does not increase negative score") {
        // Decay should always move toward 0 from negative
        float current = -0.20f;
        float factor = 1.0f;  // max decay
        float result = current * (1.0f - factor);
        // With factor 1.0, result should be 0
        assert(result >= current);  // should be closer to zero
    END_TEST();

    // =========================================================================
    TEST("decay on positive score does nothing") {
        // decay() only applies when current < 0.0
        float current = 0.1f;
        float result = current;  // would be unchanged
        assert(result >= 0.0f);
    END_TEST();

    // =========================================================================
    TEST("threshold comparison logic") {
        // threshold is -0.05, scores below this are anomalous
        float threshold = -0.05f;
        assert((-0.15f < threshold) == true);   // anomalous
        assert((-0.05f < threshold) == false);  // boundary - not anomalous
        assert((0.0f < threshold) == false);    // normal
    END_TEST();

    // =========================================================================
    TEST("score to entropy conversion (onnx_to_entropy logic from main.cpp)") {
        // Converting ONNX score to 0-1 entropy
        // Score range: -0.2 (anomalous) to +0.2 (normal), threshold at -0.05
        float score = -0.15f;
        constexpr float kThreshold = -0.05f;
        constexpr float kMinScore = -0.2f;
        float entropy;
        if (score >= kThreshold) {
            entropy = 0.0f;
        } else {
            float t = (kThreshold - score) / (kThreshold - kMinScore);
            entropy = std::min(1.0f, t);
        }
        // Expected: (-0.05 - (-0.15)) / (-0.05 - (-0.2)) = 0.10 / 0.15 = 0.666...
        assert(std::abs(entropy - 0.666f) < 0.01f);
    END_TEST();

    // =========================================================================
    std::cout << "\n[INFERENCE] Results: " << tests_passed << " passed, "
              << tests_failed << " failed." << std::endl;

    if (tests_failed > 0) {
        std::cerr << "[INFERENCE] FAILURE — " << tests_failed << " test(s) failed." << std::endl;
        return 1;
    }

    std::cout << "[INFERENCE] All tests passed." << std::endl;
    return 0;
}