#!/bin/bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o ens0 -j MASQUERADE
iptables -A FORWARD -o ens0 -i tmfifo_net0 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -i ens0 -j ACCEPT
#iptables -A FORWARD -j drop
