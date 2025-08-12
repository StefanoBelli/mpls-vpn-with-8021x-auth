#ifndef XDP_MAPS_DEFS_H
#define XDP_MAPS_DEFS_H

#define MAX_CONN_STAS 4
#define MAX_IDENT_NAME_LEN 256
#define MAX_IDENTS 2

struct pending_auth_sta_key {
    __u8 identity[MAX_IDENT_NAME_LEN];
};

struct pending_auth_sta_val {
    __u64 req_issue_time;
    __u32 iface;
    __u8 macaddr[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IDENTS);
    __type(key, struct pending_auth_sta_key);
    __type(value, struct pending_auth_sta_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pending_auth_sta SEC(".maps");

struct authd_sta_key {
    __u8 macaddr[6];
};

struct authd_sta_val {
    __u64 last_seen;
    __u32 current_iface;
    __u32 origin_iface;
    __u16 vlan_id;
    __u8 user_known;
    __u8 supplicant_logoff;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONN_STAS);
    __type(key, struct authd_sta_key);
    __type(value, struct authd_sta_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} authd_sta SEC(".maps");

#endif
