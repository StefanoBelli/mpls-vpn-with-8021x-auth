#ifndef MAPS_H
#define MAPS_H

#ifndef CONFIG_H
#error You must include config.h before maps.h
#endif

struct pending_auth_sta_val {
    __u64 req_issue_time;
    __u32 iface;
    __u8 macaddr[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CONFIG_MAX_IDENTS);
    __type(key, __u8[CONFIG_MAX_IDENT_NAME_LEN]);
    __type(value, struct pending_auth_sta_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pending_auth_sta SEC(".maps");

#include "shmapsdefs.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CONFIG_MAX_CONN_STAS);
    __type(key, __u8[6]);
    __type(value, struct authd_sta_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} authd_sta SEC(".maps");

#endif
