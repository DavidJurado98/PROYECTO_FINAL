#!/usr/bin/python
# La ruta para ipv6 no es necesaria para  este programa 
# entonces ponemos esto para que no salte el WARNING
from scapy.all import *
def print_pkt(pkt):
  pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
