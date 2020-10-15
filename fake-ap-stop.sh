#!/bin/bash

systemctl stop hostapd 
systemctl stop httpd 
systemctl stop dnsmasq 
systemctl stop rpcbind 
killall dnsmasq
killall hostapd

systemctl start NetworkManager
