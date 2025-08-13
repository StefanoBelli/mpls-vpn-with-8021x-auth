#ifndef EAPOL_H
#define EAPOL_H

struct eapolhdr {
    __u8 version;
    __u8 type;
    __u16 length;
} __attribute__((packed));

struct eaphdr {
    __u8 code;
    __u8 id;
    __u16 length;
} __attribute__((packed));

struct eapdata {
    __u8 type;
} __attribute__((packed));

#define EAP_RESPONSE 2
#define EAP_RESPONSE_TYPE_IDENTITY 1
#define EAPOL_EAP 0
#define EAPOL_LOGOFF 2
#define HAS_EAPOL(frame) ((frame)->h_proto == bpf_htons(ETH_P_PAE))

#endif
