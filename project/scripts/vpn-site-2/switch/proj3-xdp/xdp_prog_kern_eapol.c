#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#include "config.h"
#include "maps.h"
#include "eapol.h"

static long __check_req_issue_time_cb(void *map, const void *key, const void *value, void *ctx) {
    struct pending_auth_sta *psta = (struct pending_auth_sta*) map;
    struct pending_auth_sta_val *psta_val = (struct pending_auth_sta_val*) value;
    struct pending_auth_sta_key *psta_key = (struct pending_auth_sta_key*) key;

    __u64 now_time = *((__u64*) ctx);

    if(now_time - psta_val->req_issue_time >= PENDING_AUTH_DISCARD_NS) {
        bpf_map_delete_elem(psta, psta_key);
    }

    return 0;
}

static int __do_start_auth(__u8* macaddr, __u32 iface, struct eapdata *data, __u16 typedatalen, void* data_end) {
    if(typedatalen > MAX_IDENT_NAME_LEN) {
        return XDP_DROP;
    }

    if(((void*)data) + sizeof(struct eapdata) > data_end) {
        return XDP_DROP;
    }

    if(data->type != EAP_RESPONSE_TYPE_IDENTITY) {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_boot_ns();
    bpf_for_each_map_elem(&pending_auth_sta, __check_req_issue_time_cb, &now, 0);

    __u8 *identity = (__u8*)(((void*)data) + sizeof(struct eapdata));

    struct pending_auth_sta_key psta_key;
    __builtin_memset(psta_key.identity, 0, MAX_IDENT_NAME_LEN);

    //this is a BPF-verifier-approved "memcpy"
    for(__u32 i = 0; i < MAX_IDENT_NAME_LEN && ((void*) identity) + i + 1 < data_end; i++) {
        psta_key.identity[i] = identity[i];
    }

    struct pending_auth_sta_val *psta_val = bpf_map_lookup_elem(&pending_auth_sta, &psta_key);
    if(psta_val != NULL && psta_val->iface != iface) {
        return XDP_PASS;
    }

    struct pending_auth_sta_val new_psta_val;
    __builtin_memset(&new_psta_val, 0, sizeof(struct pending_auth_sta_val));

    new_psta_val.req_issue_time = now;
    __builtin_memcpy(new_psta_val.macaddr, macaddr, sizeof(__u8) * 6);
    new_psta_val.iface = iface;

    bpf_map_update_elem(&pending_auth_sta, &psta_key, &new_psta_val, BPF_EXIST);

    return XDP_PASS;
}

static int check_if_supplicant_logoff(struct ethhdr* frame, struct authd_sta_val *sta, void *data_end) {
    if(HAS_EAPOL(frame)) {
        struct eapolhdr *eapol = (struct eapolhdr*) (((void*)frame) + sizeof(struct ethhdr));
        if(((void*)eapol) + sizeof(struct eapolhdr) > data_end) {
            return XDP_DROP;
        }

        if(eapol->type == EAPOL_LOGOFF) {
            sta->supplicant_logoff = 1;
        }
    }

    return XDP_PASS;
}

static int attempt_start_auth(__u32 iface, struct ethhdr* frame, void* data_end) {
    if(HAS_EAPOL(frame)) {
        struct eapolhdr *eapol = (struct eapolhdr*) (((void*)frame) + sizeof(struct ethhdr));
        if(((void*)eapol) + sizeof(struct eapolhdr) > data_end) {
            return XDP_DROP;
        }

        if(eapol->type == EAPOL_EAP) {
            struct eaphdr *eap = (struct eaphdr*) (((void*)eapol) + sizeof(struct eapolhdr));
            if(((void*)eap) + sizeof(struct eaphdr) > data_end) {
                return XDP_DROP;
            }

            if(eap->code == EAP_RESPONSE) {
                struct eapdata *eapdata = (struct eapdata*) (((void*)eap) + sizeof(struct eaphdr));
                __u16 tdlen = bpf_ntohs(eap->length) - sizeof(struct eapdata) - sizeof(struct eaphdr);
                return __do_start_auth(frame->h_source, iface, eapdata, tdlen, data_end);
            }
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int inspect_eapol_frame(struct xdp_md* ctx) {
    void *data_end = (void*)((__u64) ctx->data_end);
    void *data = (void*)((__u64) ctx->data);

    struct ethhdr *eth = data;
    if(((void*)eth) + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }

    struct authd_sta_key sta_key;
    __builtin_memcpy(sta_key.macaddr, eth->h_source, 6 * sizeof(__u8));

    struct authd_sta_val *sta = bpf_map_lookup_elem(&authd_sta, &sta_key);
    if(sta != NULL) {
        __u32 sta_cur_iface = sta->current_iface;
        __u32 sta_orig_iface = sta->origin_iface;
        __u8 sta_logoff = sta->supplicant_logoff;

        if(sta_cur_iface != sta_orig_iface || sta_logoff) {
            return XDP_DROP;
        }

        sta->current_iface = ctx->ingress_ifindex;
        sta->last_seen = bpf_ktime_get_boot_ns();

        return check_if_supplicant_logoff(eth, sta, data_end);
    }

    return attempt_start_auth(ctx->ingress_ifindex, eth, data_end);
}

char LICENSE[] SEC("license") = "GPL";
