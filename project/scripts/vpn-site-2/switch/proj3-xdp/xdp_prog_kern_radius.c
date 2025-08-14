#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "config.h"
#include "maps.h"
#include "radius.h"

int get_username_from_avps(struct radiusavphdr *avps, __u16 avpslen, void* data_end, __u8 *out, __u16 *outlen) {
    *outlen = 0;

    for(__u32 i = 0; i < avpslen && ((void*)avps) + sizeof(struct radiusavphdr) <= data_end; i += avps->length) {

        if(avps->type == RADIUS_AVP_TYPE_USER_NAME) {
            __u32 identlen = avps->length - sizeof(struct radiusavphdr);
            __u8 *avp_data = ((void*)avps) + sizeof(struct radiusavphdr);

            if(identlen > CONFIG_MAX_IDENT_NAME_LEN) {
                return XDP_DROP;
            }

            if(((void*)avp_data) + CONFIG_MAX_IDENT_NAME_LEN > data_end) {
                return XDP_DROP;
            }

            for(__u32 j = 0; j < identlen; j++) {
                out[j] = avp_data[j];
            }

            *outlen = identlen;
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

int extract_radiushdr(struct ethhdr *frame, struct radiushdr **out, void *data_end) {
    *out = NULL;

    if(HAS_IP(frame)) {
        struct iphdr *ip = (struct iphdr*) (((void*)frame) + sizeof(struct ethhdr));
        if(((void*)ip) + sizeof(struct iphdr) > data_end) {
            return XDP_DROP;
        }

        if(HAS_UDP(ip)) {
            struct udphdr *udp = (struct udphdr*) (((void*)ip) + sizeof(struct iphdr));
            if(((void*)udp) + sizeof(struct udphdr) > data_end) {
                return XDP_DROP;
            }

            if(HAS_RADIUS(udp)) {
                struct radiushdr *radius = (struct radiushdr*) (((void*)udp) + sizeof(struct udphdr));
                if(((void*)radius) + sizeof(struct radiushdr) > data_end) {
                    return XDP_DROP;
                }

                *out = radius;
            }
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int inspect_radius_frame(struct xdp_md* ctx) {
    void *data_end = (void*)((__u64) ctx->data_end);
    void *data = (void*)((__u64) ctx->data);

    struct ethhdr *eth = data;
    if(((void*)eth) + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    struct radiushdr *radius;
    int rv = extract_radiushdr(eth, &radius, data_end);
    if(radius == NULL) {
        return rv;
    }

    if(radius->code == RADIUS_CODE_ACCESS_ACCEPT) {
        __u8 username[CONFIG_MAX_IDENT_NAME_LEN];
        __u16 usernamelen;
        struct radiusavphdr* avps = (struct radiusavphdr*)((void*)radius) + sizeof(struct radiushdr);
        __u16 avpstotlen = radius->length - sizeof(struct radiushdr);

        __builtin_memset(username, 0, CONFIG_MAX_IDENT_NAME_LEN);
        rv = get_username_from_avps(avps, avpstotlen, data_end, username, &usernamelen);
        if(usernamelen == 0) {
            return rv;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
