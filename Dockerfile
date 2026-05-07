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
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    git \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /src/bin/neuro_agent /app/neuro_agent
COPY --from=builder /src/bin/simulate_threat /app/simulate_threat
COPY --from=builder /src/obj/sensor.bpf.o /app/sensor.bpf.o

# Create chroot target for TelemetryBridge sandbox
RUN mkdir -p /var/empty && chmod 755 /var/empty

ENTRYPOINT ["/app/neuro_agent"]
CMD ["NODE_1"]
