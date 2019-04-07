#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
a = IP()
a.dst = '192.168.1.20'
a.ttl = 2
b = ICMP()
send(a/b)
print "::::Paquete TTL=2 ENVIADO::::"
