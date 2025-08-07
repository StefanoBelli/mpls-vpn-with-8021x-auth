#!/bin/bash

ip addr add 10.0.0.5/24 dev eth0
ip route add 192.168.0.0/24 via 10.0.0.6 dev eth0
ip route add 192.168.2.0/24 via 10.0.0.6 dev eth0

ip addr add 192.168.1.1/24 dev eth1

vtysh -f frrconf
