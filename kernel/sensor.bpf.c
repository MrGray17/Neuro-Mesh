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

char LICENSE[] SEC("license") = "GPL";
