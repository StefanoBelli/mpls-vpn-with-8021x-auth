#ifndef SHMAPSDEFS_H
#define SHMAPSDEFS_H

struct authd_sta_val {
    __u64 last_seen;
    __u32 current_iface;
    __u32 origin_iface;
    __u8 vlan_id[5];
    __u8 user_known;
    __u8 supplicant_logoff;
};

#endif
