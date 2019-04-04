#!/usr/bin/python
# La direccion para ipv6 no es necesaria para  este programa 
# entonces ponemos esto para que no salte el WARNING
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


from scapy.all import *
def print_pkt(pkt):
  pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
