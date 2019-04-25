#!/usr/bin/python
# -*- coding: UTF-8 -*-

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#EJERCICIO A (Filtrar por paquetes ICMP)
pkt = sniff(filter='icmp', prn=print_pkt)

#EJERCICIO B (Filtrar por paquetes TCP y puerto 23)
#pkt = sniff(filter='tcp port 23', prn=print_pkt)

#EJERCICIO C (Filtrar por subred)
#pkt = sniff(filter='net 8.8.8.0/24', prn=print_pkt)
