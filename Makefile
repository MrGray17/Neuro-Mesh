# ============================================================
# NEURO-MESH : PROFESSIONAL BUILD SYSTEM (V9.0)
# ============================================================
CXX = clang++
CC  = clang

CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -I. \
           -Ithird_party/uWebSockets/src \
           -Ithird_party/uWebSockets/uSockets/src

BPF_CC = clang
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu

# uSockets C flags — minimal, no SSL, Linux epoll backend
USOCK_CFLAGS = -std=c11 -O3 -DLIBUS_NO_SSL -I$(USOCK_DIR)

SSL_LIBS  = -lssl -lcrypto -lpthread
BPF_LIBS  = -lbpf -lelf -lz -lpthread
SECC_LIBS = -lseccomp

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
             cell/SovereignCell.cpp \
             cell/InferenceEngine.cpp \
             consensus/MeshNode.cpp \
             jailer/SystemJailer.cpp \
             crypto/CryptoCore.cpp \
             telemetry/AuditLogger.cpp \
             telemetry/TelemetryBridge.cpp

AGENT_OBJS = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(AGENT_SRCS))
AGENT_TARGET = $(BIN_DIR)/neuro_agent
SIM_TARGET = $(BIN_DIR)/simulate_threat
CRYPTO_TEST_TARGET = $(BIN_DIR)/test_crypto

all: directories skel $(AGENT_TARGET) tools

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/cell $(OBJ_DIR)/consensus $(OBJ_DIR)/jailer
	@mkdir -p $(OBJ_DIR)/crypto $(OBJ_DIR)/telemetry
	@mkdir -p $(OBJ_DIR)/usockets/eventing

# ---- eBPF skeleton generation ----
$(OBJ_DIR)/sensor.bpf.o: kernel/sensor.bpf.c
	$(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

skel: $(OBJ_DIR)/sensor.bpf.o
	bpftool gen skeleton $< > kernel/sensor.skel.h

# ---- uSockets C compilation ----
$(OBJ_DIR)/usockets/%.o: $(USOCK_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(USOCK_CFLAGS) -c $< -o $@

# ---- C++ compilation ----
$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# SovereignCell depends on the generated eBPF skeleton header
$(OBJ_DIR)/cell/SovereignCell.o: kernel/sensor.skel.h

# ---- Link neuro_agent ----
$(AGENT_TARGET): $(USOCK_OBJS) $(AGENT_OBJS)
	$(CXX) $(CXXFLAGS) $(USOCK_OBJS) $(AGENT_OBJS) -o $@ $(BPF_LIBS) $(SSL_LIBS) $(SECC_LIBS)

# ---- Tools ----
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
