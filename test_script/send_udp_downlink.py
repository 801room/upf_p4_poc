#!/usr/bin/python

# Send downlink packets to UE.

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send
from scapy.layers.l2 import Ether

gNB_ADDR = '193.168.1.2'
N3_ADDR = '193.168.1.3'
UE_ADDR = '10.10.10.2'
DN_ADDR = '10.10.10.3'

RATE = 5  # packets per second
PAYLOAD = ' '.join(['P4 is great!'] * 50)
print "Sending %d UDP packets per second to %s..." % (RATE, UE_ADDR)
pkt = IP(src=DN_ADDR,dst=UE_ADDR) /UDP(sport=10053,dport=10053)/PAYLOAD
send(pkt, iface='h1b-eth0',inter=1.0 / RATE, loop=True, verbose=True)