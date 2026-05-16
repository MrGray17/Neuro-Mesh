# ============================================================
# NEURO-MESH : PROFESSIONAL BUILD SYSTEM (V10.0)
# ============================================================
# Usage:
#   make                    # Build everything (release)
#   make DEBUG=1            # Build with debug symbols, no optimization
#   make SANITIZE=1         # Build with ASan + UBSan
#   make THREAD=1           # Build with ThreadSanitizer
#   make COVERAGE=1         # Build with coverage instrumentation
#   make -j$(nproc)         # Parallel build
#   make test               # Build and run all unit tests
#   make install PREFIX=/usr/local  # Install to system
#   make clean              # Remove all build artifacts
#   make lint               # Run clang-tidy on all sources
#   ============================================================

# ---- Toolchain ----
CXX := clang++
CC  := clang

# ---- Build mode ----
ifdef DEBUG
  CXXFLAGS_BASE := -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -g -O0 -DDEBUG
  LDFLAGS_OPT :=
else
ifdef SANITIZE
  CXXFLAGS_BASE := -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -g -O1 \
    -fsanitize=address,undefined -fno-omit-frame-pointer -DDEBUG
  LDFLAGS_OPT := -fsanitize=address,undefined
else
ifdef THREAD
  CXXFLAGS_BASE := -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -g -O1 \
    -fsanitize=thread -fno-omit-frame-pointer -DDEBUG
  LDFLAGS_OPT := -fsanitize=thread
else
ifdef COVERAGE
  CXXFLAGS_BASE := -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -g -O0 \
    --coverage -fprofile-instr-generate -fcoverage-mapping -DDEBUG
  LDFLAGS_OPT := --coverage
else
  CXXFLAGS_BASE := -std=c++20 -Wall -Wextra -Wpedantic -Wshadow -Werror -O3 -DNDEBUG
  LDFLAGS_OPT :=
endif
endif
endif
endif

# ---- Include paths ----
INCLUDES := -I. \
            -isystem third_party/uWebSockets/src \
            -isystem third_party/uWebSockets/uSockets/src \
            -I/usr/local/include/onnxruntime

CXXFLAGS := $(CXXFLAGS_BASE) $(INCLUDES)
CXXFLAGS_LINT := $(CXXFLAGS_BASE) $(INCLUDES)

# ---- eBPF toolchain ----
BPF_CC := clang
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m 2>/dev/null || echo x86_64)-linux-gnu

# ---- uSockets C flags ----
USOCK_DIR := third_party/uWebSockets/uSockets/src
USOCK_CFLAGS := -std=c11 -O3 -DLIBUS_NO_SSL -I$(USOCK_DIR)

# ---- Libraries ----
SSL_LIBS  := -lssl -lcrypto -lpthread
BPF_LIBS  := -lbpf -lelf -lz
SECC_LIBS := -lseccomp
ONNX_LIBS := -L/usr/local/lib -lonnxruntime
ALL_LIBS  := $(BPF_LIBS) $(SSL_LIBS) $(SECC_LIBS) $(ONNX_LIBS) $(LDFLAGS_OPT)

# ---- Directories ----
OBJ_DIR := obj
BIN_DIR := bin
PREFIX  ?= /usr/local

# ---- Default target ----
.PHONY: all directories tools test install clean lint check-deps

# ---- Source files and targets (must be before 'all' for variable expansion) ----
AGENT_SRCS := main.cpp \
              cell/NodeAgent.cpp \
              cell/InferenceEngine.cpp \
              consensus/MeshNode.cpp \
              consensus/PeerManager.cpp \
              enforcer/PolicyEnforcer.cpp \
              enforcer/MitigationEngine.cpp \
              crypto/CryptoCore.cpp \
              crypto/KeyManager.cpp \
              net/TransportLayer.cpp \
              attacks/AttackSimulator.cpp \
              telemetry/AuditLogger.cpp \
              telemetry/Observability.cpp \
              telemetry/TelemetryBridge.cpp

AGENT_OBJS := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(AGENT_SRCS))
AGENT_TARGET := $(BIN_DIR)/neuro_agent

all: check-deps directories kernel/sensor.skel.h $(AGENT_TARGET)

# ONNX model generation (optional — agent builds without it)
isolation_forest.onnx:
	@if command -v python3 >/dev/null 2>&1; then \
		python3 -c "from sklearn.ensemble import IsolationForest; from skl2onnx import to_onnx" 2>/dev/null && \
		(python3 tools/train_iforest.py --output $@ --samples 10000 && echo "ONNX model generated") || \
		(if [ -f $@ ]; then echo "WARNING: sklearn not available — using existing model"; else echo "WARNING: sklearn not available — skipping model generation"; fi); \
	else \
		(if [ -f $@ ]; then echo "WARNING: python3 not available — using existing model"; else echo "WARNING: python3 not available — skipping model generation"; fi); \
	fi

# ============================================================
# eBPF skeleton generation
# ============================================================
$(OBJ_DIR)/sensor.bpf.o: kernel/sensor.bpf.c
	@mkdir -p $(dir $@)
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

kernel/sensor.skel.h: $(OBJ_DIR)/sensor.bpf.o
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool gen skeleton $< > $@.tmp 2>/dev/null && mv $@.tmp $@ && echo "eBPF skeleton generated" || \
		(rm -f $@.tmp; \
		 if [ -s $@ ]; then echo "WARNING: bpftool failed — using pre-generated skeleton"; \
		 else echo "ERROR: bpftool failed and no pre-generated skeleton"; exit 1; fi); \
	else \
		if [ -s $@ ]; then echo "WARNING: bpftool not found — using pre-generated skeleton"; \
		else echo "ERROR: bpftool not found and no pre-generated skeleton"; exit 1; fi; \
	fi

# ============================================================
# uSockets C compilation
# ============================================================
USOCK_SRCS := $(USOCK_DIR)/bsd.c \
              $(USOCK_DIR)/context.c \
              $(USOCK_DIR)/loop.c \
              $(USOCK_DIR)/socket.c \
              $(USOCK_DIR)/eventing/epoll_kqueue.c
USOCK_OBJS := $(patsubst $(USOCK_DIR)/%.c,$(OBJ_DIR)/usockets/%.o,$(USOCK_SRCS))

$(OBJ_DIR)/usockets/%.o: $(USOCK_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USOCK_CFLAGS) -c $< -o $@

# ============================================================
# C++ compilation
# ============================================================

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# NodeAgent depends on the generated eBPF skeleton header
$(OBJ_DIR)/cell/NodeAgent.o: kernel/sensor.skel.h

# ============================================================
# Link neuro_agent
# ============================================================
$(AGENT_TARGET): $(USOCK_OBJS) $(AGENT_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(USOCK_OBJS) $(AGENT_OBJS) -o $@ $(ALL_LIBS)
	@echo "Built $(AGENT_TARGET)"

# ============================================================
# Tools
# ============================================================
SIM_TARGET := $(BIN_DIR)/inject_event
CRYPTO_TEST_TARGET := $(BIN_DIR)/test_crypto
PBFT_TEST_TARGET := $(BIN_DIR)/test_pbft
ENFORCER_TEST_TARGET := $(BIN_DIR)/test_enforcer
MESHNODE_TEST_TARGET := $(BIN_DIR)/test_meshnode
INFERENCE_TEST_TARGET := $(BIN_DIR)/test_inference

$(SIM_TARGET): tools/inject_event.cpp
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

$(CRYPTO_TEST_TARGET): tools/test_crypto.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(LDFLAGS_OPT)

$(PBFT_TEST_TARGET): tools/test_pbft.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(LDFLAGS_OPT)

$(ENFORCER_TEST_TARGET): tools/test_enforcer.cpp $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(BPF_LIBS) $(LDFLAGS_OPT)

MESHNODE_TEST_OBJS := $(OBJ_DIR)/consensus/MeshNode.o \
                      $(OBJ_DIR)/consensus/PeerManager.o \
                      $(OBJ_DIR)/enforcer/PolicyEnforcer.o \
                      $(OBJ_DIR)/enforcer/MitigationEngine.o \
                      $(OBJ_DIR)/telemetry/TelemetryBridge.o \
                      $(OBJ_DIR)/telemetry/Observability.o \
                      $(OBJ_DIR)/crypto/CryptoCore.o \
                      $(OBJ_DIR)/crypto/KeyManager.o \
                      $(OBJ_DIR)/net/TransportLayer.o \
                      $(OBJ_DIR)/attacks/AttackSimulator.o

$(MESHNODE_TEST_TARGET): tools/test_meshnode.cpp $(MESHNODE_TEST_OBJS) $(USOCK_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(USOCK_OBJS) $(MESHNODE_TEST_OBJS) -o $@ $(SSL_LIBS) $(BPF_LIBS) $(SECC_LIBS) $(LDFLAGS_OPT)

$(INFERENCE_TEST_TARGET): tools/test_inference.cpp $(OBJ_DIR)/cell/InferenceEngine.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/cell/InferenceEngine.o -o $@ $(ONNX_LIBS) $(LDFLAGS_OPT)

# Google Test-based unit tests
GTEST_FLAGS = -lgtest -lgtest_main -pthread

$(BIN_DIR)/test_common: tests/unit/test_common.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(GTEST_FLAGS) $(LDFLAGS_OPT)

$(BIN_DIR)/test_mitigation: tests/unit/test_mitigation.cpp $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(BPF_LIBS) $(GTEST_FLAGS) $(LDFLAGS_OPT)

$(BIN_DIR)/test_auditlogger: tests/unit/test_auditlogger.cpp $(OBJ_DIR)/telemetry/AuditLogger.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/telemetry/AuditLogger.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(GTEST_FLAGS) $(LDFLAGS_OPT)

# Fuzz targets (require -fsanitize=fuzzer build)
FUZZ_FLAGS := -fsanitize=fuzzer -std=c++20 $(INCLUDES)

$(BIN_DIR)/fuzz_beacon_parser: tests/fuzz/fuzz_beacon_parser.cpp $(OBJ_DIR)/net/TransportLayer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(FUZZ_FLAGS) $< $(OBJ_DIR)/net/TransportLayer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS)

$(BIN_DIR)/fuzz_json_parser: tests/fuzz/fuzz_json_parser.cpp $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(FUZZ_FLAGS) $< $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(BPF_LIBS)

$(BIN_DIR)/fuzz_pbft_message: tests/fuzz/fuzz_pbft_message.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(FUZZ_FLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS)

tools: $(SIM_TARGET) $(CRYPTO_TEST_TARGET) $(PBFT_TEST_TARGET) \
       $(ENFORCER_TEST_TARGET) $(MESHNODE_TEST_TARGET) $(INFERENCE_TEST_TARGET) \
       $(BIN_DIR)/test_common $(BIN_DIR)/test_mitigation $(BIN_DIR)/test_auditlogger

# ============================================================
# Test runner
# ============================================================
test: tools
	@echo "=== Running Unit Tests ==="
	@echo "--- test_crypto ---"
	@$(CRYPTO_TEST_TARGET) && echo "PASS" || echo "FAIL"
	@echo "--- test_pbft ---"
	@$(PBFT_TEST_TARGET) && echo "PASS" || echo "FAIL"
	@echo "--- test_enforcer ---"
	@$(ENFORCER_TEST_TARGET) && echo "PASS" || echo "FAIL"
	@echo "--- test_meshnode ---"
	@$(MESHNODE_TEST_TARGET) && echo "PASS" || echo "FAIL"
	@echo "--- test_inference ---"
	@$(INFERENCE_TEST_TARGET) && echo "PASS" || echo "FAIL"
	@echo "--- test_common (gtest) ---"
	@$(BIN_DIR)/test_common && echo "PASS" || echo "FAIL"
	@echo "--- test_mitigation (gtest) ---"
	@$(BIN_DIR)/test_mitigation && echo "PASS" || echo "FAIL"
	@echo "--- test_auditlogger (gtest) ---"
	@$(BIN_DIR)/test_auditlogger && echo "PASS" || echo "FAIL"
	@echo "=== All Tests Complete ==="

# Fuzz targets — build all and optionally run (make fuzz RUN_FUZZ=1 for execution)
FUZZ_TARGETS := $(BIN_DIR)/fuzz_beacon_parser $(BIN_DIR)/fuzz_json_parser $(BIN_DIR)/fuzz_pbft_message

fuzz: $(FUZZ_TARGETS)
ifdef RUN_FUZZ
	@echo "=== Running Fuzz Tests (10s each) ==="
	@echo "--- fuzz_beacon_parser ---"
	@$(BIN_DIR)/fuzz_beacon_parser -max_total_time=10 || true
	@echo "--- fuzz_json_parser ---"
	@$(BIN_DIR)/fuzz_json_parser -max_total_time=10 || true
	@echo "--- fuzz_pbft_message ---"
	@$(BIN_DIR)/fuzz_pbft_message -max_total_time=10 || true
	@echo "=== Fuzz Tests Complete ==="
else
	@echo "=== Fuzz targets built (run with make fuzz RUN_FUZZ=1) ==="
endif

# ============================================================
# Install
# ============================================================
install: $(AGENT_TARGET) $(SIM_TARGET)
	@echo "Installing to $(PREFIX)..."
	@install -d $(PREFIX)/bin
	@install -d $(PREFIX)/share/neuro-mesh/kernel
	@install -d $(PREFIX)/share/neuro-mesh/models
	@install -d $(PREFIX)/share/neuro-mesh/dashboard
	@install -m 755 $(AGENT_TARGET) $(PREFIX)/bin/neuro_agent
	@install -m 755 $(SIM_TARGET) $(PREFIX)/bin/inject_event
	@install -m 644 kernel/sensor.bpf.c $(PREFIX)/share/neuro-mesh/kernel/
	@if [ -f kernel/sensor.skel.h ]; then install -m 644 kernel/sensor.skel.h $(PREFIX)/share/neuro-mesh/kernel/; fi
	@if [ -f isolation_forest.onnx ]; then install -m 644 isolation_forest.onnx $(PREFIX)/share/neuro-mesh/models/; fi
	@cp -r dashboard/* $(PREFIX)/share/neuro-mesh/dashboard/ 2>/dev/null || true
	@echo "Installation complete"
	@echo "  Binary: $(PREFIX)/bin/neuro_agent"
	@echo "  eBPF:   $(PREFIX)/share/neuro-mesh/kernel/"
	@echo "  Model:  $(PREFIX)/share/neuro-mesh/models/"

# ============================================================
# Lint
# ============================================================
lint:
	@echo "=== Running clang-tidy ==="
	@command -v clang-tidy >/dev/null 2>&1 || { echo "ERROR: clang-tidy not found"; exit 1; }
	@clang-tidy --version
	@FAILED=0; \
	for f in main.cpp $(AGENT_SRCS); do \
		if [ -f "$$f" ]; then \
			echo "--- $$f ---"; \
			clang-tidy "$$f" -- $(CXXFLAGS_LINT) 2>&1 || FAILED=$$((FAILED + 1)); \
		fi; \
	done; \
	if [ $$FAILED -gt 0 ]; then \
		echo "clang-tidy found issues in $$FAILED files"; \
		exit 1; \
	else \
		echo "clang-tidy: no issues found"; \
	fi

# ============================================================
# Clean
# ============================================================
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) kernel/sensor.skel.h
	@echo "Clean complete"
