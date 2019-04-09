#!/usr/bin/python
# LINEA 4 y 5 SOLO SI SALTA EL ERROR DEL IPV6
# La direccion para ipv6 no es necesaria para  este programa 
# entonces añadimos la linea 4 y 5 que elimina las advertencias para que no salte el WARNING
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


from scapy.all import *
def print_pkt(pkt):
  pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)
