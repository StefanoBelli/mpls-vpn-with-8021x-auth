#!/bin/bash

ip addr add 192.168.2.2/24 dev eth2
ip route add default via 192.168.2.1 dev eth2

ip link add bridge0 type bridge
ip link set eth0 master bridge0
ip link set eth1 master bridge0
ip link set bridge0 up

echo 8 > /sys/class/net/bridge0/bridge/group_fwd_mask

ebtables -P FORWARD DROP
ebtables -P INPUT ACCEPT
ebtables -P OUTPUT ACCEPT

INSTALLDIR=/etc/hostapd
install -D -m600 hostapd.conf $INSTALLDIR/hostapd.conf
