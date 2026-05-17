# ============================================================
# Stage 1: Build
# ============================================================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    make \
    libbpf-dev \
    libelf-dev \
    libssl-dev \
    libseccomp-dev \
    linux-tools-common \
    git \
    zlib1g-dev \
    python3 \
    python3-pip \
    wget \
    && rm -rf /var/lib/apt/lists/*

ARG ONNX_VERSION=1.20.1
RUN wget -q https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && tar xzf onnxruntime-linux-x64-${ONNX_VERSION}.tgz \
    && cp -r onnxruntime-linux-x64-${ONNX_VERSION}/include/* /usr/local/include/ \
    && cp onnxruntime-linux-x64-${ONNX_VERSION}/lib/libonnxruntime.so* /usr/local/lib/ \
    && ldconfig \
    && rm -rf onnxruntime-linux-x64-${ONNX_VERSION} onnxruntime-linux-x64-${ONNX_VERSION}.tgz

RUN pip3 install --break-system-packages numpy scikit-learn skl2onnx

WORKDIR /src
COPY tools/train_iforest.py tools/train_iforest.py
RUN python3 tools/train_iforest.py --output isolation_forest.onnx --samples 10000

COPY . .
RUN rm -rf bin obj kernel/sensor.skel.h && make -j$(nproc)

# ============================================================
# Stage 2: Runtime (distroless-style minimal image)
# ============================================================
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    libelf1t64 \
    libssl3t64 \
    libseccomp2 \
    ca-certificates \
    python3 \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin neuro \
    && mkdir -p /var/empty \
    && chown neuro:neuro /var/empty \
    && chmod 755 /var/empty

WORKDIR /app

COPY --from=builder /src/bin/neuro_agent /app/neuro_agent
COPY --from=builder /src/bin/inject_event /app/inject_event
COPY --from=builder /src/obj/sensor.bpf.o /app/sensor.bpf.o

COPY --from=builder /usr/local/lib/libonnxruntime.so.* /usr/local/lib/
RUN ldconfig

COPY --from=builder /src/tools/traffic_generator.py /app/traffic_generator.py
COPY --from=builder /src/isolation_forest.onnx /app/isolation_forest.onnx

RUN chown -R neuro:neuro /app

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD pgrep -x neuro_agent > /dev/null || exit 1

USER neuro

ENTRYPOINT ["/usr/bin/tini", "--", "/app/neuro_agent"]
