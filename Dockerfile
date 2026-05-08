# ============================================================
# Stage 1: Build
# ============================================================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Layer 1: System packages (changes rarely — strong cache)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    make \
    libbpf-dev \
    libelf-dev \
    libssl-dev \
    libseccomp-dev \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    git \
    zlib1g-dev \
    python3 \
    python3-pip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: ONNX Runtime pre-built (changes never — strongest cache)
ARG ONNX_VERSION=1.17.1
RUN wget -q https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && tar xzf onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && cp -r onnxruntime-linux-x64-${ONNX_VERSION}/include/* /usr/local/include/ \
    && cp onnxruntime-linux-x64-${ONNX_VERSION}/lib/libonnxruntime.so* /usr/local/lib/ \
    && ldconfig \
    && rm -rf onnxruntime-linux-x64-${ONNX_VERSION} onnxruntime-linux-x64-${ONNX_VERSION}.tgz

# Layer 3: Python ML deps (changes rarely — strong cache)
RUN pip3 install --break-system-packages numpy scikit-learn skl2onnx

# Layer 4: Train the Isolation Forest model (changes when train_iforest.py changes)
WORKDIR /src
COPY tools/train_iforest.py tools/train_iforest.py
RUN python3 tools/train_iforest.py --output isolation_forest.onnx --samples 10000

# Layer 5: Full source + build (changes frequently — last layer)
COPY . .
RUN rm -rf bin && mkdir -p obj && make obj/sensor.bpf.o && touch kernel/sensor.skel.h && make

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libelf1 \
    libssl3t64 \
    libseccomp2 \
    ca-certificates \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Binaries
COPY --from=builder /src/bin/neuro_agent /app/neuro_agent
COPY --from=builder /src/bin/inject_event /app/inject_event
COPY --from=builder /src/obj/sensor.bpf.o /app/sensor.bpf.o

# ONNX Runtime shared library
COPY --from=builder /usr/local/lib/libonnxruntime.so.1.17.1 /usr/local/lib/
RUN ldconfig

# Attack script
COPY --from=builder /src/tools/traffic_generator.py /app/traffic_generator.py

# Trained model
COPY --from=builder /src/isolation_forest.onnx /app/isolation_forest.onnx

# Create chroot target for TelemetryBridge sandbox
RUN mkdir -p /var/empty && chmod 755 /var/empty

ENTRYPOINT ["/app/neuro_agent"]
CMD ["NODE_1"]
