#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <linux/limits.h>
#include <bpf/bpf.h>
#include <net/if.h>

#include "die.h"
#include "shmapsdefs.h"

#ifndef DISCONNECT_AFTER_INACTIVITY_THR_NS
#define DISCONNECT_AFTER_INACTIVITY_THR_NS 600000000000LL
#endif

#ifndef DEFAULT_BPFFS_PATH
#define DEFAULT_BPFFS_PATH "/sys/fs/bpf/xdp/globals"
#endif

static char bpffs[PATH_MAX];

static int open_bpf_map_by_name(const char* name) {
    char full_map_path[PATH_MAX];
    memset(full_map_path, 0, sizeof(full_map_path));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(full_map_path, PATH_MAX, "%s/%s", bpffs, name);
#pragma GCC diagnostic pop

    int fd = bpf_obj_get(full_map_path);
    if(fd < 0) {
        __die1(bpf_obj_get, full_map_path);
    }

    return fd;
}

static void load_defaults() {
    memset(bpffs, 0, sizeof(bpffs));
    strncpy(bpffs, DEFAULT_BPFFS_PATH, sizeof(bpffs) - 1);
}

static void print_program_settings() {
    printf(" * BPF fs path: %s\n", bpffs);
}

static void event_polling(int);

int main() {
    if(getuid() != 0) {
        fputs("this program must be run as root\n", stderr);
        return EXIT_FAILURE;
    }

    load_defaults();
    print_program_settings();

    int map_fd = open_bpf_map_by_name("authd_sta");
    event_polling(map_fd);

    //unreachable code
    close(map_fd);
    return EXIT_SUCCESS;
}

/* Event polling and policy enforcement */

#define NANO_PER_SEC 1000000000LL

#define timespec_to_ns(ts) (((__u64)(ts).tv_sec) * NANO_PER_SEC + (ts).tv_nsec)

#define NEED_TO_DENY_ACCESS(x) \
    ((subtract_times(timespec_to_ns(now), (x).last_seen) > DISCONNECT_AFTER_INACTIVITY_THR_NS) || \
    ((x).current_iface != (x).origin_iface) || \
    ((x).supplicant_logoff))

#define s_always_inline static inline __attribute__((always_inline))

s_always_inline __u64 subtract_times(__u64 ns_x, __u64 ns_y) {
    if(ns_y >= ns_x) {
        return 0;
    }

    return ns_x - ns_y;
}

#define DEFINE_IFNAME_FROM_IFINDEX(_ifnamevar, ifindex) \
    char _ifnamevar[IF_NAMESIZE]; \
    if(if_indextoname(ifindex, _ifnamevar) == NULL) { \
        __die0(if_indextoname); \
    }

#define CMDLINE_MAX 256

static void run_command(const char* cmd) {
    FILE *fp = popen(cmd, "r");
    if(fp == NULL) {
        __die0(popen);
    }

    int wstatus = pclose(fp);
    if(wstatus == -1) {
        __die0(pclose);
    }

    if(WIFEXITED(wstatus)) {
        if(WEXITSTATUS(wstatus) != 0) {
            fprintf(stderr, "command \"%s\" exited with exit code %d\n", cmd, WEXITSTATUS(wstatus));
            exit(EXIT_FAILURE);
        }
    } else {
        fprintf(stderr, "command \"%s\" did *not* exit()\n", cmd);
        exit(EXIT_FAILURE);
    }
}

static void allow_access(const __u8 *macaddr, const struct authd_sta_val *val) {
    char cmdbuf[CMDLINE_MAX];
    DEFINE_IFNAME_FROM_IFINDEX(ifname, val->origin_iface);

    memset(cmdbuf, 0, CMDLINE_MAX);
    snprintf(cmdbuf, CMDLINE_MAX, "bridge vlan add dev %s vid %s pvid untagged", ifname, val->vlan_id);
    run_command(cmdbuf);

    memset(cmdbuf, 0, CMDLINE_MAX);
    snprintf(cmdbuf, CMDLINE_MAX, "ebtables -A FORWARD -s %02X:%02X:%02X:%02X:%02X:%02X -j ACCEPT",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    run_command(cmdbuf);
}

static void deny_access(const __u8 *macaddr, const struct authd_sta_val *val) {
    char cmdbuf[CMDLINE_MAX];
    DEFINE_IFNAME_FROM_IFINDEX(ifname, val->origin_iface);

    memset(cmdbuf, 0, CMDLINE_MAX);
    snprintf(cmdbuf, CMDLINE_MAX, "bridge vlan del dev %s vid %s pvid untagged", ifname, val->vlan_id);
    run_command(cmdbuf);

    memset(cmdbuf, 0, CMDLINE_MAX);
    snprintf(cmdbuf, CMDLINE_MAX, "bridge vlan add dev %s vid 1 pvid untagged", ifname);
    run_command(cmdbuf);

    memset(cmdbuf, 0, CMDLINE_MAX);
    snprintf(cmdbuf, CMDLINE_MAX, "ebtables -D FORWARD -s %02X:%02X:%02X:%02X:%02X:%02X -j ACCEPT",
        macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    run_command(cmdbuf);
}

static void __fmttime(char buf[100]) {
    memset(buf, 0, 100);

    time_t raw;
    time(&raw);

    struct tm *timeinfo = localtime(&raw);
    strftime(buf, 100, "%F %r", timeinfo);
}

#define DEFINE_STRFTIME(_varn) \
    char _varn[100]; \
    __fmttime(_varn)

static void __base_log(const char* evt, const __u8 *macaddr, const struct authd_sta_val *val) {
    DEFINE_STRFTIME(nowtime);
    DEFINE_IFNAME_FROM_IFINDEX(curiface, val->current_iface);
    DEFINE_IFNAME_FROM_IFINDEX(origiface, val->origin_iface);

    printf(
            "[%s] %s access for %02X:%02X:%02X:%02X:%02X:%02X with vid %s,"
            " origin iface: %s, current iface: %s,"
            " logoff: %s\n",
        nowtime, evt,
        macaddr[0], macaddr[1], macaddr[2], macaddr[3],
        macaddr[4], macaddr[5], val->vlan_id,
        origiface, curiface,
        val->supplicant_logoff ? "yes" : "no");
}

static void log_access_allowed(const __u8 *macaddr, const struct authd_sta_val *val) {
    __base_log("allowed", macaddr, val);
}

static void log_access_denied(const __u8 *macaddr, const struct authd_sta_val *val) {
    __base_log("denied", macaddr, val);
}

static void event_polling(int map) {
    printf("starting event polling...\n");

    while(1) {
        struct timespec now;

        if(clock_gettime(CLOCK_BOOTTIME, &now) < 0) {
            __die0(clock_getttime);
        }

        __u8 prev_key[6];
        __u8 cur_key[6];
        void *prev_key_ptr = NULL;

        int rv;
        while((rv = bpf_map_get_next_key(map, prev_key_ptr, cur_key)) == 0) {
            struct authd_sta_val cur_val;

            int rv = bpf_map_lookup_elem(map, cur_key, &cur_val);
            if(rv != 0) {
                __die0(bpf_map_lookup_elem);
            }

            if(NEED_TO_DENY_ACCESS(cur_val)) {
                deny_access(cur_key, &cur_val);
                if(bpf_map_delete_elem(map, cur_key) < 0) {
                    __die0(bpf_map_delete_elem);
                }

                log_access_denied(cur_key, &cur_val);
                continue;
            }

            if(!cur_val.user_known) {
                allow_access(cur_key, &cur_val);
                cur_val.user_known = 1;
                if(bpf_map_update_elem(map, cur_key, &cur_val, 0) < 0) {
                    __die0(bpf_map_update_elem);
                }

                log_access_allowed(cur_key, &cur_val);
            }

            memcpy(prev_key, cur_key, sizeof(__u8) * 6);
            if(prev_key_ptr == NULL) {
                prev_key_ptr = prev_key;
            }
        }

        if(rv != -ENOENT) {
            __die0(bpf_map_get_next_key);
        }

        sleep(5);
    }
}
