// ============================================================
// NEURO-MESH : KERNEL eBPF SENSOR & XDP DROPPER (HARDENED)
// ============================================================
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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

    // Strict validation of banned IPs
    __u32 src_ip = iph->saddr;
    __u8 *banned = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);
    if (banned && *banned == 1) return XDP_DROP;

    // Global Lockdown Check
    __u32 lockdown_key = 0xFFFFFFFF;
    __u8 *lockdown = bpf_map_lookup_elem(&xdp_blacklist, &lockdown_key);
    if (lockdown && *lockdown == 1) return XDP_DROP;

    return XDP_PASS;
}

// TRACEPOINT: Secure Execution Monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct KernelEvent *event;

    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    // WHY: Cryptographically secure memory sanitization. Prevents uninitialized
    // kernel stack memory from bleeding into user-space via the payload array.
    __builtin_memset(event, 0, sizeof(struct KernelEvent));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 1;

    // WHY: Fail fast if the process is exiting or context is invalid.
    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Safely read the first argument (binary path) into payload
    const char *pathname = NULL;
    bpf_core_read(&pathname, sizeof(pathname), (void *)((char *)ctx + 16));
    if (pathname) {
        bpf_probe_read_user_str(&event->payload, sizeof(event->payload), pathname);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Network sendto tracepoint args layout (x86_64):
//   offset 16: fd (u32)      | offset 24: buff (u64 ptr)
//   offset 32: len (u64)     | offset 40: flags (u32)
//   offset 48: addr (u64 ptr) | offset 56: addr_len (u32)
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(void *ctx) {
    struct KernelEvent *event;

    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(struct KernelEvent));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 2;  // network send

    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Read the data buffer pointer and length
    __u64 len = 0;
    bpf_core_read(&len, sizeof(len), (void *)((char *)ctx + 32));
    if (len > 0 && len <= sizeof(event->payload)) {
        const char *buff = NULL;
        bpf_core_read(&buff, sizeof(buff), (void *)((char *)ctx + 24));
        if (buff) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), buff);
        }
    } else {
        // Truncated read for large buffers — still captures entropy sample
        const char *buff = NULL;
        bpf_core_read(&buff, sizeof(buff), (void *)((char *)ctx + 24));
        if (buff) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), buff);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Network sendmsg tracepoint args layout (x86_64):
//   offset 16: fd (u32)   | offset 24: msg (u64 ptr → struct msghdr)
//   offset 32: flags (u32)
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(void *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(struct KernelEvent));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 2;

    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Read struct msghdr from userspace
    struct msghdr {
        void *msg_name;
        __u32 msg_namelen;
        __u32 _pad;
        void *msg_iov;
        __u64 msg_iovlen;
        void *msg_control;
        __u64 msg_controllen;
        __u32 msg_flags;
    } msg_hdr;

    const struct msghdr *msg_ptr = NULL;
    bpf_core_read(&msg_ptr, sizeof(msg_ptr), (void *)((char *)ctx + 24));
    if (!msg_ptr) { bpf_ringbuf_discard(event, 0); return 0; }
    bpf_probe_read_user(&msg_hdr, sizeof(msg_hdr), msg_ptr);

    if (msg_hdr.msg_iovlen > 0 && msg_hdr.msg_iov) {
        struct iovec {
            void *iov_base;
            __u64 iov_len;
        } iov;
        bpf_probe_read_user(&iov, sizeof(iov), msg_hdr.msg_iov);
        __u64 len = iov.iov_len;
        if (len > 0 && len <= sizeof(event->payload)) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), iov.iov_base);
        } else if (len > sizeof(event->payload) && iov.iov_base) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), iov.iov_base);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Network sendmmsg tracepoint args layout (x86_64):
//   offset 16: fd (u32)   | offset 24: msgvec (u64 ptr → struct mmsghdr)
//   offset 32: vlen (u32) | offset 40: flags (u32)
SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_sendmmsg(void *ctx) {
    struct KernelEvent *event;
    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(struct KernelEvent));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 2;

    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // struct mmsghdr { struct msghdr msg_hdr; unsigned int msg_len; };
    struct mmsghdr {
        void *msg_name;
        __u32 msg_namelen;
        __u32 _pad;
        void *msg_iov;
        __u64 msg_iovlen;
        void *msg_control;
        __u64 msg_controllen;
        __u32 msg_flags;
        __u32 msg_len;
    } mm;

    const struct mmsghdr *mm_ptr = NULL;
    bpf_core_read(&mm_ptr, sizeof(mm_ptr), (void *)((char *)ctx + 24));
    if (!mm_ptr) { bpf_ringbuf_discard(event, 0); return 0; }
    bpf_probe_read_user(&mm, sizeof(mm), mm_ptr);

    if (mm.msg_iovlen > 0 && mm.msg_iov) {
        struct iovec {
            void *iov_base;
            __u64 iov_len;
        } iov;
        bpf_probe_read_user(&iov, sizeof(iov), mm.msg_iov);
        __u64 len = iov.iov_len;
        if (len > 0 && len <= sizeof(event->payload)) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), iov.iov_base);
        } else if (len > sizeof(event->payload) && iov.iov_base) {
            bpf_probe_read_user_str(&event->payload, sizeof(event->payload), iov.iov_base);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Network connect tracepoint args layout (x86_64):
//   offset 16: fd (u32)   | offset 24: addr (u64 ptr)
//   offset 32: addr_len (u32)
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(void *ctx) {
    struct KernelEvent *event;

    event = bpf_ringbuf_reserve(&telemetry_ringbuf, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(struct KernelEvent));

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = 3;  // network connect

    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Read sockaddr pointer and try to capture target info
    __u32 addr_len = 0;
    bpf_core_read(&addr_len, sizeof(addr_len), (void *)((char *)ctx + 32));
    const char *addr_ptr = NULL;
    bpf_core_read(&addr_ptr, sizeof(addr_ptr), (void *)((char *)ctx + 24));
    if (addr_ptr && addr_len > 0 && addr_len <= sizeof(event->payload)) {
        bpf_probe_read_user_str(&event->payload, sizeof(event->payload), addr_ptr);
    } else if (addr_ptr && addr_len > sizeof(event->payload)) {
        bpf_probe_read_user_str(&event->payload, sizeof(event->payload), addr_ptr);
    } else {
        // Fallback: write numeric info so ONNX has something to chew on
        __builtin_memcpy(event->payload, "NET_CONNECT", 11);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
