# ============================================================
# NEURO-MESH : PROFESSIONAL BUILD SYSTEM (V9.0)
# ============================================================
CXX = clang++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -I.
BPF_CC = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu

SSL_LIBS = -lssl -lcrypto -lpthread
BPF_LIBS = -lbpf -lelf -lz -lpthread

OBJ_DIR = obj
BIN_DIR = bin

AGENT_SRCS = main.cpp \
             cell/SovereignCell.cpp \
             cell/InferenceEngine.cpp \
             consensus/MeshNode.cpp \
             jailer/SystemJailer.cpp \
             crypto/CryptoCore.cpp \
             telemetry/AuditLogger.cpp

AGENT_OBJS = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(AGENT_SRCS))
AGENT_TARGET = $(BIN_DIR)/neuro_agent
SIM_TARGET = $(BIN_DIR)/simulate_threat
CRYPTO_TEST_TARGET = $(BIN_DIR)/test_crypto

all: directories skel $(AGENT_TARGET) tools

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/cell $(OBJ_DIR)/consensus $(OBJ_DIR)/jailer
	@mkdir -p $(OBJ_DIR)/crypto $(OBJ_DIR)/telemetry

# eBPF skeleton generation
$(OBJ_DIR)/sensor.bpf.o: kernel/sensor.bpf.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

skel: $(OBJ_DIR)/sensor.bpf.o
	bpftool gen skeleton $< > kernel/sensor.skel.h

# Compile each .cpp to .o in mirrored obj/ tree
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# SovereignCell depends on the generated eBPF skeleton header
$(OBJ_DIR)/cell/SovereignCell.o: kernel/sensor.skel.h

$(AGENT_TARGET): $(AGENT_OBJS)
	$(CXX) $(CXXFLAGS) $(AGENT_OBJS) -o $@ $(BPF_LIBS) $(SSL_LIBS)

# Tools
$(SIM_TARGET): tools/simulate_threat.cpp $(OBJ_DIR)/consensus/MeshNode.o $(OBJ_DIR)/jailer/SystemJailer.o $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/consensus/MeshNode.o $(OBJ_DIR)/jailer/SystemJailer.o $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(BPF_LIBS) $(SSL_LIBS)

$(CRYPTO_TEST_TARGET): tools/test_crypto.cpp $(OBJ_DIR)/crypto/CryptoCore.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $< $(OBJ_DIR)/crypto/CryptoCore.o -o $@ $(SSL_LIBS)

tools: $(SIM_TARGET) $(CRYPTO_TEST_TARGET)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) kernel/sensor.skel.h

.PHONY: all directories skel tools clean
