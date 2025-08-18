# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_PROG_KERN_EAPOL = xdp_prog_kern_eapol
XDP_PROG_KERN_RADIUS = xdp_prog_kern_radius
XDP_PROG_USER = xdp_prog_user

XDP_TARGETS  := $(XDP_PROG_KERN_EAPOL) $(XDP_PROG_KERN_RADIUS)
USER_TARGETS := $(XDP_PROG_USER)

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common

EXTRA_DEPS := $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk

# ---------------------------------
# ---- ste's install commands -----
# ---------------------------------

SHELL=/bin/bash

TARGET_IFACES_RADIUS ?= eth2

install-xdp-radius: $(XDP_PROG_KERN_RADIUS).o
        @for iface in $(TARGET_IFACES_RADIUS); do \
                ip link set dev $${iface} xdp obj $(XDP_PROG_KERN_RADIUS).o sec xdp && \
                        echo "[ OK ] RADIUS xdp program installed for $${iface}" || \
                        echo "[ FAIL ] RADIUS xdp program **NOT** installed for $${iface}"; \
        done

TARGET_IFACES_EAPOL ?= eth0 eth1

install-xdp-eapol: $(XDP_PROG_KERN_EAPOL).o
        @for iface in $(TARGET_IFACES_EAPOL); do \
                ip link set dev $${iface} xdp obj $(XDP_PROG_KERN_EAPOL).o sec xdp && \
                        echo "[ OK ] EAPOL xdp program installed for $${iface}" || \
                        echo "[ FAIL ] EAPOL xdp program **NOT** installed for $${iface}"; \
        done

install-xdp: install-xdp-eapol install-xdp-radius

RM_TARGET_IFACES ?= $(TARGET_IFACES_RADIUS) $(TARGET_IFACES_EAPOL)

remove-xdp-only:
        @for iface in $(RM_TARGET_IFACES); do \
                ip link set $${iface} xdp off && \
                        echo "[ OK ] xdp program removed for $${iface}" || \
                        echo "[ FAIL ] xdp program **NOT** removed for $${iface}"; \
        done

PINNED_MAPS_PATH ?= /sys/fs/bpf/xdp/globals
RM_TARGET_MAPS ?= authd_sta pending_auth_sta

remove-pinned-maps:
        @for map in $(RM_TARGET_MAPS); do \
                rm $(PINNED_MAPS_PATH)/$${map} && \
                        echo "[ OK ] map $(PINNED_MAPS_PATH)/$${map} removed" || \
                        echo "[ FAIL ] map $(PINNED_MAPS_PATH)/$${map} **NOT** removed"; \
        done

remove-xdp: remove-xdp-only remove-pinned-maps

reinstall:
        @make remove-xdp
        @make install-xdp

deep-reinstall:
        @make clean
        @make reinstall
