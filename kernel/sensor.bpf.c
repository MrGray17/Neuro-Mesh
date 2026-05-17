// ============================================================
// NEURO-MESH : KERNEL eBPF SENSOR & XDP DROPPER (HARDENED)
// ============================================================
// Uses BPF_KPROBE macros from bpf_tracing.h for portable
// syscall argument extraction.  PT_REGS_PARM* macros resolve
// to the correct register for each architecture at compile time.
// ============================================================
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct KernelEvent {
    __u32 pid;
    __u32 event_type;
    char comm[16];
    char payload[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} telemetry_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} xdp_blacklist SEC(".maps");

// XDP: Hardware-level packet dropper
SEC("xdp")
int xdp_neuro_mesh_dropper(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8 *banned = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);
    if (banned && *banned == 1) return XDP_DROP;

    __u32 lockdown_key = 0xFFFFFFFF;
    __u8 *lockdown = bpf_map_lookup_elem(&xdp_blacklist, &lockdown_key);
    if (lockdown && *lockdown == 1) return XDP_DROP;

    return XDP_PASS;
}

// Helper: fill common event fields
static __always_inline void init_event(struct KernelEvent *event, __u32 type) {
    __builtin_memset(event, 0, sizeof(*event));
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = type;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

// Architecture-specific pt_regs definition for kprobe argument extraction.
// PT_REGS_PARM* macros from bpf_tracing.h need the full struct.
#ifdef __TARGET_ARCH_x86
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};
#endif

// KPROBE: sys_execve — uses PT_REGS_PARM1 for arch-portable arg extraction
SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    init_event(event, 1);

    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    if (filename) {
        bpf_probe_read_user_str(&event->payload, sizeof(event->payload), filename);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// KPROBE: sys_sendto — uses PT_REGS_PARM* for portable args
SEC("kprobe/__x64_sys_sendto")
int trace_sendto(struct pt_regs *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    init_event(event, 2);

    const void *buf = (const void *)PT_REGS_PARM2(ctx);
    __u64 len = (__u64)PT_REGS_PARM3(ctx);

    // Bounds: len capped to payload size so bpf_probe_read_user never overflows
    if (len > 0 && buf && len <= sizeof(event->payload)) {
        bpf_probe_read_user(&event->payload, len, buf);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// KPROBE: sys_sendmsg — uses PT_REGS_PARM* for portable args
SEC("kprobe/__x64_sys_sendmsg")
int trace_sendmsg(struct pt_regs *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    init_event(event, 2);

    const void *msg = (const void *)PT_REGS_PARM2(ctx);
    if (msg) {
        struct {
            void *msg_name;
            __u32 msg_namelen;
            void *msg_iov;
            __u64 msg_iovlen;
        } hdr;

        if (bpf_probe_read_user(&hdr, sizeof(hdr), msg) == 0 && hdr.msg_iovlen > 0 && hdr.msg_iov) {
            struct { void *iov_base; __u64 iov_len; } iov;
            if (bpf_probe_read_user(&iov, sizeof(iov), hdr.msg_iov) == 0 && iov.iov_len > 0 && iov.iov_base) {
                __u64 read_len = iov.iov_len < sizeof(event->payload) ? iov.iov_len : sizeof(event->payload);
                bpf_probe_read_user(&event->payload, read_len, iov.iov_base);
            }
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// KPROBE: sys_connect — uses PT_REGS_PARM* for portable args
SEC("kprobe/__x64_sys_connect")
int trace_connect(struct pt_regs *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    init_event(event, 3);

    const void *addr = (const void *)PT_REGS_PARM2(ctx);
    int addr_len = (int)PT_REGS_PARM3(ctx);

    if (addr && addr_len > 0) {
        __u64 read_len = addr_len < sizeof(event->payload) ? addr_len : sizeof(event->payload);
        bpf_probe_read_user(&event->payload, read_len, addr);
    } else {
        __builtin_memcpy(event->payload, "NET_CONNECT", 11);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
