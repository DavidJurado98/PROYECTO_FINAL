#!/usr/bin/python
from scapy.all import *

print "===============[TRACEROUTER]==============="
#Introducimos la direccion:
direccion = "www.INTRODUCEWEBAQUI.com"
for ttl in range(1, 28):
    pkt = IP(dst=direccion, ttl=ttl) / UDP(dport=33434)
    # Envia los paquetes y obtiene un reply
    reply = sr1(pkt, verbose=0)
    if reply is None:
        # Si no recibe el reply se para
        break
    elif reply.type == 3:
        # Llega con exito
        print "=========================================================="
        print "Ruta trazada con exito a la direccion:", reply.src
        print "=========================================================="
        break
    else:
        # Esta en proceso de llegar a su destino
        print "Router %i con exito:"% ttl , reply.src