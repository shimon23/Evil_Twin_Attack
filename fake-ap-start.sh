#!/usr/bin/bash

service network-manager stop #stop the OS network service
airmon-ng check kill #kill all procesess that interfere with monitor mode wifi card
ifconfig wlp2s0 10.0.0.1 netmask 255.255.255.0 #intilize the ip and subnet
route add default gw 10.0.0.1

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT

dnsmasq -C dnsmasq.conf
hostapd hostapd.conf -B 
echo "Starting apache server"
sudo sudo systemctl restart apache2




