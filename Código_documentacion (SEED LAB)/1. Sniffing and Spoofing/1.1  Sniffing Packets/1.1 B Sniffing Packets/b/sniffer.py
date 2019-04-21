#!/usr/bin/python
# -*- coding: UTF-8 -*-
from scapy.all import *
def pkt_callback(pkt):
    pkt.show() # debug statement
sniff(iface="enp0s3", prn=pkt_callback, filter="tcp and host 192.168.1.120 and port 23", store=0)

