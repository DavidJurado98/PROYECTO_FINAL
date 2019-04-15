#!/usr/bin/python

from scapy.all import *
def print_pkt(pkt):
	pkt.show()
pkt = sniff(iface="enp0s3",filter="tcp and host 192.168.1.120 and port 80",\
prn = lambda x: x.summary("%IP.src% %IP.dst% %IP.proto%"))
