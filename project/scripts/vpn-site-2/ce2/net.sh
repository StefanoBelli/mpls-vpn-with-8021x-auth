#!/bin/bash

ip addr add 10.0.0.9/30 dev eth0
ip route add 192.168.0.0/24 via 10.0.0.10 dev eth0
ip route add 192.168.1.0/24 via 10.0.0.10 dev eth0

ip addr add 192.168.2.1/24 dev eth1

vtysh -f frrconf