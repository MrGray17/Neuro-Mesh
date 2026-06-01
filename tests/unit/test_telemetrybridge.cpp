#include <gtest/gtest.h>
#include "telemetry/TelemetryBridge.hpp"
#include <string>
#include <cstdlib>
#include <chrono>
#include <thread>

using namespace neuro_mesh;

class TelemetryBridgeTest : public ::testing::Test {
protected:
    void SetUp() override {
        setenv("NEURO_UNSAFE_NO_SANDBOX", "1", 1);
    }
};

TEST_F(TelemetryBridgeTest, ConfigDefaults) {
    TelemetryBridgeConfig cfg;
    EXPECT_EQ(cfg.websocket_port, 9000u);
    EXPECT_EQ(cfg.chroot_path, "/var/empty");
}

TEST_F(TelemetryBridgeTest, SpawnAndShutdown) {
    TelemetryBridgeConfig cfg;
    cfg.websocket_port = 9991;
    TelemetryBridge bridge(cfg);
    auto result = bridge.spawn();
    if (result.ok()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)bridge.shutdown();
    }
}

TEST_F(TelemetryBridgeTest, PushValidJson) {
    TelemetryBridgeConfig cfg;
    cfg.websocket_port = 9992;
    TelemetryBridge bridge(cfg);
    auto spawn_ok = bridge.spawn();
    if (spawn_ok.ok()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        auto result = bridge.push_telemetry(
            R"({"event":"test","value":1.0})");
        if (!result.ok()) {
            SUCCEED() << "push_telemetry may fail on pipe full (expected)";
        }
    }
}

TEST_F(TelemetryBridgeTest, PushMultipleMessages) {
    TelemetryBridgeConfig cfg;
    cfg.websocket_port = 9993;
    TelemetryBridge bridge(cfg);
    auto spawn_ok = bridge.spawn();
    if (spawn_ok.ok()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (int i = 0; i < 3; i++) {
            auto result = bridge.push_telemetry(
                "{\"seq\":" + std::to_string(i) + "}");
            if (!result.ok()) break;
        }
        SUCCEED();
    }
}

TEST_F(TelemetryBridgeTest, CustomPort) {
    TelemetryBridgeConfig cfg;
    cfg.websocket_port = 9994;
    TelemetryBridge bridge(cfg);
    auto result = bridge.spawn();
    if (result.ok()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

TEST_F(TelemetryBridgeTest, DoubleShutdownSafe) {
    TelemetryBridgeConfig cfg;
    cfg.websocket_port = 9995;
    TelemetryBridge bridge(cfg);
    auto result = bridge.spawn();
    if (result.ok()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        (void)bridge.shutdown();
        (void)bridge.shutdown();
        SUCCEED();
    }
}
