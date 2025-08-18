# Progetto #3 del corso di Network and System Defense
Stefano Belli, matricola 0350116
Anno accademico 2024/2025

## Indice
1. [Introduzione](#introduzione)
2. [Configurazione della backbone (AS100)](#configurazione-della-backbone-as100)
3. [Configurazione della VPN site 1](#configurazione-della-vpn-site-1)
4. [Configurazione della VPN site 2](#configurazione-della-vpn-site-2)
5. [Configurazione della VPN site 3](#configurazione-della-vpn-site-3)
4. [Conclusioni](#conclusioni)


## Introduzione

Il progetto prevede l'implementazione di una VPN MPLS/BGP hub-and-spoke con possibilità di comunicazione spoke-to-spoke e
advertisement delle rotte CE-PE eseguita automaticamente. In aggiunta, nella VPN site 1 c'è un dispositivo sensitive,
quindi bisogna impiegare un mandatory access control, nella VPN site 2 ci sono due client che possono accedere alla LAN
solo dopo autenticazione (802.1x), e quindi ricevere un VLAN id automaticamente. Nella VPN site 3 c'è il server RADIUS
che è l'authentication server.

![topology](./img/topology.PNG)

## Configurazione della backbone (AS100)

 * **R101**

 * **R102**

 * **R103**

 * **R104**

## Configurazione della VPN site 1

 * **CE1**

 frrconf

 ```bash
interface eth0
 ip address 10.0.0.1/30

interface eth1
 ip address 192.168.0.1/24

ip route 0.0.0.0/0 10.0.0.2

router bgp 65000
 network 192.168.0.0/24
 neighbor 10.0.0.2 remote-as 100
 ```

 net.sh

 ```bash
#!/bin/bash

vtysh -f frrconf
 ```

 * **client-A1**

## Configurazione della VPN site 2

 * **CE2**

 frrconf

 ```bash
interface eth0
 ip address 10.0.0.9/30

interface eth1
 ip address 192.168.2.1/24

ip route 0.0.0.0/0 10.0.0.10

router bgp 65002
 network 192.168.2.0/24
 neighbor 10.0.0.10 remote-as 100
 ```

 net.sh

 ```bash
#!/bin/bash

vtysh -f frrconf

sysctl -w net.ipv4.ip_forward=1

ip link add link eth1 name eth1.95 type vlan id 95
ip link add link eth1 name eth1.32 type vlan id 32
ip link set eth1.95 up
ip link set eth1.32 up

VLAN_95_IPADDR=192.168.2.9/30
VLAN_32_IPADDR=192.168.2.5/30

#VLAN_95_IPADDR=192.168.4.1/24
#VLAN_32_IPADDR=192.168.3.1/24

ip addr add $VLAN_95_IPADDR dev eth1.95
ip addr add $VLAN_32_IPADDR dev eth1.32
 ```

 * **RADIUS**

 net.sh

 ```bash
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
 ```

 radius.sh

 ```bash
#!/bin/bash

freeradius $@
 ```

 clients.conf

 ```bash
client vs2switch {
 ipaddr = 192.168.2.2
 secret = "mysecretpasswd"
 shortname = authnserv
}
 ```

 authorize

 ```bash
clientb1 Cleartext-Password := "clientb1passwd"
        Service-Type = Framed-User,
        Tunnel-Type = 13,
        Tunnel-Medium-Type = 6,
        Tunnel-Private-Group-ID = 32

clientb2 Cleartext-Password := "clientb2passwd"
        Service-Type = Framed-User,
        Tunnel-Type = 13,
        Tunnel-Medium-Type = 6,
        Tunnel-Private-Group-ID = 95
 ```

## Configurazione della VPN site 3

 * **CE3**

 frrconf

 ```bash
interface eth0
 ip address 10.0.0.5/30

interface eth1
 ip address 192.168.1.1/24

ip route 0.0.0.0/0 10.0.0.6

router bgp 65001
 network 192.168.1.0/24
 neighbor 10.0.0.6 remote-as 100
 ```

 net.sh

 ```bash
#!/bin/bash

vtysh -f frrconf
 ```

 * **switch**

 * **client-B1**

 * **client-B2**

## Conclusioni
