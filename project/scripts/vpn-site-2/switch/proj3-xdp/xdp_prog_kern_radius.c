#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "config.h"
#include "maps.h"

SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
 return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
