#!/usr/bin/python

from scapy.all import *
def print_pkt(pkt):
	pkt.show()
pkt = sniff(prn=lambda x: xsprintf("ip broadcast 255.255.255.0"))
