#!/usr/bin/python

# Send uplink packets to DN.

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send
from scapy.contrib.gtp import GTPHeader as GTPHeader
from scapy.layers.l2 import Ether

gNB_ADDR = '193.168.1.2'
N3_ADDR = '193.168.1.3'
UE_ADDR = '10.10.10.2'
DN_ADDR = '10.10.10.3'

RATE = 5  # packets per second
PAYLOAD = ' '.join(['P4 is great!'] * 50)
GTP = GTPHeader(version=1, teid=1111,length=677,gtp_type=0xff)
print "Sending %d UDP packets per second to %s..." % (RATE, UE_ADDR)
pkt = IP(src=gNB_ADDR,dst=N3_ADDR) / UDP(sport=2152, dport=2152) /GTP/IP(src=UE_ADDR,dst=DN_ADDR)/UDP(sport=10053,dport=10053)/PAYLOAD
send(pkt, iface='h1a-eth0',inter=1.0 / RATE, loop=True, verbose=True)
