#!/bin/bash

vtysh -f frrconf

sysctl -w net.ipv4.ip_forward=1

ip link add link eth1 name eth1.95 type vlan id 95
ip link add link eth1 name eth1.32 type vlan id 32
ip link set eth1.95 up
ip link set eth1.32 up

VLAN_95_IPADDR=192.168.2.5/30
VLAN_32_IPADDR=192.168.2.9/30

#VLAN_95_IPADDR=192.168.3.1/24
#VLAN_32_IPADDR=192.168.4.1/24

ip addr add $VLAN_95_IPADDR dev eth1.95
ip addr add $VLAN_32_IPADDR dev eth1.32
