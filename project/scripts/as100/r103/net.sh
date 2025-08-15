#!/bin/bash

ip link add vpnA type vrf table 10
ip link set vpnA up
ip link set eth1 master vpnA

sysctl -w net.mpls.conf.lo.input=1
sysctl -w net.mpls.conf.eth0.input=1
sysctl -w net.mpls.conf.vpnA.input=1
sysctl -w net.mpls.platform_labels=100000

vtysh -f frrconf
