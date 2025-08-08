#!/bin/bash

ip addr add 192.168.1.2/24 dev eth0
ip route add default via 192.168.1.1 dev eth0

INSTALLDIR=/etc/freeradius/3.0
install -D -m444 clients.conf $INSTALLDIR/clients.conf

# apparently on newer freeradius versions
# the "users" file is actually located at
# /etc/freeradius/3.0/mods-config/files/authorize

# comment one of the following lines if one config file
# keeps disturbing freeradius, but should ensure compat
# across freeradius versions / configs

install -D -m444 authorize $INSTALLDIR/mods-config/files/authorize
install -m444 authorize $INSTALLDIR/users