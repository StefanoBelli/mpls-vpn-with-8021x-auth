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

static int parse_radius_avps(struct radiusavphdr *avps, __u8* username, __u8* vid, void* data_end) {
    __u8 has_vid = 0;
    __u8 has_username = 0;

    for(int i = 0; i < CONFIG_RADIUS_MAX_AVPS; i++) {
        if(((void*)avps) + sizeof(struct radiusavphdr) > data_end) {
            return XDP_DROP;
        }

        if(avps->length < 2) {
            return XDP_DROP;
        }

        if(((void*)avps) + avps->length > data_end) {
            return XDP_DROP;
        }

        __u8 *data = ((void*)avps) + sizeof(struct radiusavphdr);
        __u16 datalen = avps->length - sizeof(struct radiusavphdr);

        if(avps->type == RADIUS_AVP_TYPE_USER_NAME) {
            if(datalen > CONFIG_MAX_IDENT_NAME_LEN) {
                return XDP_DROP;
            }

            if(bpf_probe_read_kernel(username, datalen, data) < 0) {
                return XDP_DROP;
            }

            has_username = 1;
        } else if(avps->type == RADIUS_AVP_TYPE_TUNNEL_PRIVATE_GROUP_ID) {
            if(datalen > 4) {
                return XDP_DROP;
            }

            if(bpf_probe_read_kernel(username, datalen, data) < 0) {
                return XDP_DROP;
            }

            has_vid = 1;
        }

        if(has_username && has_vid) {
            return XDP_PASS;
        }

        avps = ((void*)avps) + avps->length;
    }

    return XDP_PASS;
}

static int finalize_auth(__u8 *identity, __u8 *vid, __u32 current_iface) {
    struct pending_auth_sta_val *pendauthsta = bpf_map_lookup_elem(&pending_auth_sta, identity);
    if(pendauthsta == NULL) {
        return XDP_DROP;
    }

    struct authd_sta_val authdsta;
    authdsta.last_seen = bpf_ktime_get_boot_ns();
    authdsta.current_iface = current_iface;
    authdsta.origin_iface = pendauthsta->iface;
    __builtin_memcpy(authdsta.vlan_id, vid, 5);
    authdsta.user_known = 0;
    authdsta.supplicant_logoff = 0;

    __u8 macaddr[6];
    __builtin_memcpy(macaddr, pendauthsta->macaddr, 6);

    if(bpf_map_delete_elem(&pending_auth_sta, identity) < 0) {
        return XDP_DROP;
    }

    if(bpf_map_update_elem(&authd_sta, macaddr, &authdsta, BPF_NOEXIST) < 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

static int extract_radiushdr(struct ethhdr *frame, struct radiushdr **out, void *data_end) {
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
        struct radiusavphdr *avps = (struct radiusavphdr*) ((void*)radius) + sizeof(struct radiushdr);

        __u8 username[CONFIG_MAX_IDENT_NAME_LEN];
        __u8 vid[5];

        __builtin_memset(username, 0, CONFIG_MAX_IDENT_NAME_LEN);
        __builtin_memset(vid, 0, 5);

        rv = parse_radius_avps(avps, username, vid, data_end);
        if(username[0] == 0 || vid[0] == 0) {
            return rv;
        }

        return finalize_auth(username, vid, ctx->ingress_ifindex);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
