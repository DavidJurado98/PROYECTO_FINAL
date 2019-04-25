#!/usr/bin/python
# -*- coding: UTF-8 -*-

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

#Elimine el simbolo "#" de la linea del ejercicio que quiera realizar
	
#EJERCICIO A (Filtrar por paquetes ICMP)
pkt = sniff(filter='icmp', prn=print_pkt)

#EJERCICIO B (Filtrar por paquetes TCP y puerto 23)
#pkt = sniff(filter='tcp port 23', prn=print_pkt)

#EJERCICIO C (Filtrar por subred)
#pkt = sniff(filter='net 128.230.0.0/16', prn=print_pkt)
