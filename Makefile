# ============================================================
# NEURO-MESH : PROFESSIONAL BUILD SYSTEM (V9.0)
# ============================================================
CXX = clang++
CC  = clang

CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -I. \
           -Ithird_party/uWebSockets/src \
           -Ithird_party/uWebSockets/uSockets/src \
           -I/usr/local/include/onnxruntime

BPF_CC = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu

# uSockets C flags — minimal, no SSL, Linux epoll backend
USOCK_CFLAGS = -std=c11 -O3 -DLIBUS_NO_SSL -I$(USOCK_DIR)

SSL_LIBS  = -lssl -lcrypto -lpthread
BPF_LIBS  = -lbpf -lelf -lz -lpthread
SECC_LIBS = -lseccomp
ONNX_LIBS = -L/usr/local/lib -lonnxruntime

OBJ_DIR = obj
BIN_DIR = bin

# ---- uSockets C sources (core + epoll backend) ----
USOCK_DIR  = third_party/uWebSockets/uSockets/src
USOCK_SRCS = $(USOCK_DIR)/bsd.c \
             $(USOCK_DIR)/context.c \
             $(USOCK_DIR)/loop.c \
             $(USOCK_DIR)/socket.c \
             $(USOCK_DIR)/eventing/epoll_kqueue.c
USOCK_OBJS = $(patsubst $(USOCK_DIR)/%.c,$(OBJ_DIR)/usockets/%.o,$(USOCK_SRCS))

# ---- C++ agent sources ----
AGENT_SRCS = main.cpp \
             cell/NodeAgent.cpp \
             cell/InferenceEngine.cpp \
             consensus/MeshNode.cpp \
             enforcer/PolicyEnforcer.cpp \
             enforcer/MitigationEngine.cpp \
             crypto/CryptoCore.cpp \
             telemetry/AuditLogger.cpp \
             telemetry/TelemetryBridge.cpp

AGENT_OBJS = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(AGENT_SRCS))
AGENT_TARGET = $(BIN_DIR)/neuro_agent
SIM_TARGET = $(BIN_DIR)/inject_event
CRYPTO_TEST_TARGET = $(BIN_DIR)/test_crypto

all: directories kernel/sensor.skel.h $(AGENT_TARGET) tools

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/cell $(OBJ_DIR)/consensus $(OBJ_DIR)/enforcer
	@mkdir -p $(OBJ_DIR)/crypto $(OBJ_DIR)/telemetry
	@mkdir -p $(OBJ_DIR)/usockets/eventing

# ---- eBPF skeleton generation ----
$(OBJ_DIR)/sensor.bpf.o: kernel/sensor.bpf.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

kernel/sensor.skel.h: $(OBJ_DIR)/sensor.bpf.o
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool gen skeleton $< > $@.tmp 2>/dev/null && mv $@.tmp $@ || \
		( rm -f $@.tmp; \
		  if [ ! -s $@ ]; then \
		    echo "WARNING: bpftool failed — using pre-generated $@"; \
		    touch $@; \
		  fi ); \
	else \
		echo "WARNING: bpftool not found — using pre-generated sensor.skel.h if available"; \
		if [ ! -f $@ ]; then touch $@; fi; \
	fi

# ---- uSockets C compilation ----
$(OBJ_DIR)/usockets/%.o: $(USOCK_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USOCK_CFLAGS) -c $< -o $@

# ---- C++ compilation ----
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# NodeAgent depends on the generated eBPF skeleton header
$(OBJ_DIR)/cell/NodeAgent.o: kernel/sensor.skel.h

# ---- Link neuro_agent ----
$(AGENT_TARGET): $(USOCK_OBJS) $(AGENT_OBJS)
	$(CXX) $(CXXFLAGS) $(USOCK_OBJS) $(AGENT_OBJS) -o $@ $(BPF_LIBS) $(SSL_LIBS) $(SECC_LIBS) $(ONNX_LIBS)

# ---- Tools ----
$(SIM_TARGET): tools/inject_event.cpp
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

$(CRYPTO_TEST_TARGET): tools/test_crypto.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS)

PBFT_TEST_TARGET = $(BIN_DIR)/test_pbft
$(PBFT_TEST_TARGET): tools/test_pbft.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS)

ENFORCER_TEST_TARGET = $(BIN_DIR)/test_enforcer
$(ENFORCER_TEST_TARGET): tools/test_enforcer.cpp $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(BPF_LIBS)

MESHNODE_TEST_TARGET = $(BIN_DIR)/test_meshnode
$(MESHNODE_TEST_TARGET): tools/test_meshnode.cpp $(OBJ_DIR)/consensus/MeshNode.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/telemetry/TelemetryBridge.o $(OBJ_DIR)/crypto/CryptoCore.o $(USOCK_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(USOCK_OBJS) $(OBJ_DIR)/consensus/MeshNode.o $(OBJ_DIR)/enforcer/PolicyEnforcer.o $(OBJ_DIR)/enforcer/MitigationEngine.o $(OBJ_DIR)/telemetry/TelemetryBridge.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS) $(BPF_LIBS) $(SECC_LIBS)

INFERENCE_TEST_TARGET = $(BIN_DIR)/test_inference
$(INFERENCE_TEST_TARGET): tools/test_inference.cpp $(OBJ_DIR)/cell/InferenceEngine.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/cell/InferenceEngine.o -o $@ $(ONNX_LIBS)

tools: $(SIM_TARGET) $(CRYPTO_TEST_TARGET) $(PBFT_TEST_TARGET) $(ENFORCER_TEST_TARGET) $(MESHNODE_TEST_TARGET) $(INFERENCE_TEST_TARGET)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) kernel/sensor.skel.h

.PHONY: all directories tools clean
