#!/bin/bash

ip link add vpnA type vrf table 10
ip link set vpnA up
ip link set eth0 master vpnA

sysctl -w net.mpls.conf.lo.input=1
sysctl -w net.mpls.conf.eth1.input=1
sysctl -w net.mpls.conf.vpnA.input=1
sysctl -w net.mpls.platform_labels=100000

vtysh -f frrconf

# no static routes
#ip route add 192.168.0.0/24 via 10.0.0.1 vrf vpnA