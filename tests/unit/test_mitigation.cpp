// Unit tests for MitigationEngine JSON parsing and execution
#include <gtest/gtest.h>

#include "enforcer/MitigationEngine.hpp"
#include "enforcer/PolicyEnforcer.hpp"

// MitigationEngine's extract_int/extract_string/validate_evidence_schema are private.
// We test through the public execute_response interface.

class MitigationEngineTest : public ::testing::Test {
protected:
    neuro_mesh::PolicyEnforcer enforcer;
    neuro_mesh::MitigationEngine* engine;

    void SetUp() override {
        enforcer.add_safe_node("SAFE_NODE");
        engine = new neuro_mesh::MitigationEngine(&enforcer);
    }

    void TearDown() override {
        delete engine;
    }
};

TEST_F(MitigationEngineTest, ExecuteResponseWithValidEvidence) {
    std::string evidence = R"({
        "pid": 999999,
        "process_name": "test_proc",
        "ip": "10.0.0.1",
        "port": 8080,
        "event_type": "network_anomaly",
        "entropy": 0.95
    })";
    // Should not crash — PID 999999 likely doesn't exist, but parsing should work
    EXPECT_NO_THROW(engine->execute_response(evidence, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithEmptyJson) {
    std::string empty = "";
    EXPECT_NO_THROW(engine->execute_response(empty, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithInvalidJson) {
    std::string invalid = "not json at all";
    EXPECT_NO_THROW(engine->execute_response(invalid, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithPartialFields) {
    std::string partial = R"({"pid":1234})";
    EXPECT_NO_THROW(engine->execute_response(partial, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithMalformedPid) {
    std::string bad_pid = R"({"pid":"not_a_number","process_name":"x","ip":"1.2.3.4","port":80})";
    EXPECT_NO_THROW(engine->execute_response(bad_pid, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithHugePid) {
    std::string huge_pid = R"({"pid":99999999999999999999,"process_name":"x","ip":"1.2.3.4","port":80})";
    // Should not crash — overflow should be handled
    EXPECT_NO_THROW(engine->execute_response(huge_pid, "TARGET"));
}

TEST_F(MitigationEngineTest, ExecuteResponseWithNegativePid) {
    std::string neg_pid = R"({"pid":-1,"process_name":"x","ip":"1.2.3.4","port":80})";
    EXPECT_NO_THROW(engine->execute_response(neg_pid, "TARGET"));
}

TEST_F(MitigationEngineTest, TerminateProcessNonExistentPid) {
    // PID 999999 should not exist
    EXPECT_FALSE(engine->terminate_process(999999));
}

TEST_F(MitigationEngineTest, TerminateProcessOwnPid) {
    // PID 1 (init) should exist but we can't kill it
    // Just verify it doesn't crash
    EXPECT_NO_THROW(engine->terminate_process(1));
}
