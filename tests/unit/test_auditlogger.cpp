// Unit tests for AuditLogger JSON escaping and metric formatting
#include <gtest/gtest.h>

#include "telemetry/AuditLogger.hpp"
#include <cmath>
#include <sstream>
#include <iostream>

// AuditLogger uses static methods and writes to stdout/UDP.
// We test by capturing stdout output.

class AuditLoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Capture stdout
        old_buf = std::cout.rdbuf();
        std::cout.rdbuf(output.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(old_buf);
    }

    std::stringstream output;
    std::streambuf* old_buf;
};

TEST_F(AuditLoggerTest, EmitJsonProducesValidOutput) {
    neuro_mesh::telemetry::AuditLogger::initialize();
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::INFO,
        "test_component",
        "test_action",
        "test_target",
        "test_details"
    );

    std::string out = output.str();
    EXPECT_NE(out.find("\"type\":\"EVENT\""), std::string::npos);
    EXPECT_NE(out.find("\"component\":\"test_component\""), std::string::npos);
    EXPECT_NE(out.find("\"action\":\"test_action\""), std::string::npos);
    EXPECT_NE(out.find("\"target\":\"test_target\""), std::string::npos);
    EXPECT_NE(out.find("\"details\":\"test_details\""), std::string::npos);
}

TEST_F(AuditLoggerTest, JsonEscapesQuotes) {
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::CRITICAL,
        "comp",
        "act",
        "target",
        "details with \"quotes\""
    );

    std::string out = output.str();
    // Should contain escaped quotes, not break JSON
    EXPECT_NE(out.find("\\\"quotes\\\""), std::string::npos);
}

TEST_F(AuditLoggerTest, JsonEscapesBackslash) {
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::WARNING,
        "comp",
        "act",
        "target",
        "path\\to\\file"
    );

    std::string out = output.str();
    EXPECT_NE(out.find("\\\\"), std::string::npos);
}

TEST_F(AuditLoggerTest, JsonEscapesNewlines) {
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::INFO,
        "comp",
        "act",
        "target",
        "line1\nline2"
    );

    std::string out = output.str();
    // Should contain \n escape, not actual newline in JSON string
    EXPECT_NE(out.find("\\n"), std::string::npos);
}

TEST_F(AuditLoggerTest, AllAuditLevels) {
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::CRITICAL, "c", "a", "t", "d");
    EXPECT_NE(output.str().find("\"level\":\"CRITICAL\""), std::string::npos);

    output.str("");
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::DEFENSE_ACTION, "c", "a", "t", "d");
    EXPECT_NE(output.str().find("\"level\":\"DEFENSE_ACTION\""), std::string::npos);

    output.str("");
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::WARNING, "c", "a", "t", "d");
    EXPECT_NE(output.str().find("\"level\":\"WARNING\""), std::string::npos);

    output.str("");
    neuro_mesh::telemetry::AuditLogger::emit_json(
        neuro_mesh::telemetry::AuditLevel::INFO, "c", "a", "t", "d");
    EXPECT_NE(output.str().find("\"level\":\"INFO\""), std::string::npos);
}

TEST_F(AuditLoggerTest, EmitMetricHandlesNaN) {
    neuro_mesh::telemetry::AuditLogger::initialize();
    // Should not crash or produce invalid JSON with NaN
    EXPECT_NO_THROW(
        neuro_mesh::telemetry::AuditLogger::emit_metric(
            std::nan(""), 100.0, 5)
    );
}

TEST_F(AuditLoggerTest, EmitMetricHandlesInf) {
    neuro_mesh::telemetry::AuditLogger::initialize();
    // Should not crash or produce invalid JSON with Inf
    EXPECT_NO_THROW(
        neuro_mesh::telemetry::AuditLogger::emit_metric(
            std::numeric_limits<double>::infinity(), 100.0, 5)
    );
}
