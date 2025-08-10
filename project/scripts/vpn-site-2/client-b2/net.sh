#!/bin/bash

IPADDR=192.168.2.10/30
GATEWAY=192.168.2.9

#IPADDR=192.168.4.2/24
#GATEWAY=192.168.4.1

ip addr add $IPADDR dev eth0
ip route add default via $GATEWAY dev eth0

INSTALLDIR=/etc
install -D -m400 wpa_supplicant.conf $INSTALLDIR/wpa_supplicant.conf
