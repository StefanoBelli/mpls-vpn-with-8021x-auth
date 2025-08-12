#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdp_maps_defs.h"

SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
 return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
