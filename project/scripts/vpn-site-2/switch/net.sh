#!/bin/bash

ip link add bridge0 type bridge
ip link set bridge0 type bridge vlan_filtering 1
ip link set eth0 master bridge0
ip link set eth1 master bridge0
ip link set eth2 master bridge0
ip link set bridge0 up

bridge vlan del vid 1 dev eth0 pvid untagged
bridge vlan del vid 1 dev eth1 pvid untagged
bridge vlan del vid 1 dev eth2 pvid untagged

bridge vlan add vid 95 dev eth2
bridge vlan add vid 32 dev eth2
bridge vlan add vid 10 dev eth2 pvid untagged

bridge vlan add dev bridge0 vid 10 self
ip link add auth.bridge0.10 link bridge0 type vlan id 10
ip addr add 192.168.2.2/24 dev auth.bridge0.10

ip link set auth.bridge0.10 up

ip route add default via 192.168.2.1 dev auth.bridge0.10

echo 8 > /sys/class/net/bridge0/bridge/group_fwd_mask

ebtables -P FORWARD DROP
ebtables -P INPUT ACCEPT
ebtables -P OUTPUT ACCEPT
ebtables -A FORWARD -i eth2 -j ACCEPT

INSTALLDIR=/etc/hostapd
install -D -m600 hostapd.conf $INSTALLDIR/hostapd.conf
