#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

// WHY: eBPF Hash Map pinned to the kernel. 
// User-space (SystemJailer) writes the malicious IP here. Kernel reads it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IP Address
    __type(value, __u8);  // Block Status (1 = Blocked)
} neuro_blocklist SEC(".maps");

SEC("xdp")
int isolate_threat_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // WHY: O(1) kernel lookup. Microsecond packet dropping before OS parsing.
    __u8 *is_blocked = bpf_map_lookup_elem(&neuro_blocklist, &src_ip);
    if (is_blocked && *is_blocked == 1) {
        return XDP_DROP; 
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
