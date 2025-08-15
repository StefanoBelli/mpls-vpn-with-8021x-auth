#ifndef RADIUS_H
#define RADIUS_H

#ifndef CONFIG_H
#error You must include config.h before radius.h
#endif

// note : length includes # of bytes for the whole RADIUS payload within UDP
//        that is - code + id + length + authenticator + avps

struct radiushdr {
    __u8 code;
    __u8 id;
    __u16 length;
    __u8 authenticator[16];
} __attribute__((packed));

#define RADIUS_CODE_ACCESS_ACCEPT 2

// note : length includes # of bytes for the whole AVP payload within RADIUS
//        that is - avp.type + avp.length + avp.type_specific_data

struct radiusavphdr {
    __u8 type;
    __u8 length;
} __attribute__((packed));

#define RADIUS_AVP_TYPE_USER_NAME 1
#define RADIUS_AVP_TYPE_TUNNEL_TYPE 64
#define RADIUS_AVP_TYPE_TUNNEL_MEDIUM_TYPE 65
#define RADIUS_AVP_TYPE_TUNNEL_PRIVATE_GROUP_ID 81

#define HAS_IP(_eth) ((_eth)->h_proto == bpf_htons(ETH_P_IP))
#define HAS_UDP(_ip) ((_ip)->protocol == IPPROTO_UDP)
#define HAS_RADIUS(_udp) ((_udp)->source == bpf_htons(CONFIG_RADIUS_SPORT))

#endif
