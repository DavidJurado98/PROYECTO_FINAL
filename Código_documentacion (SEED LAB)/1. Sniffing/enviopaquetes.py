#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
a = IP()
a.dst = '192.168.50.50'
b = ICMP()
p = a/b
send(p)
