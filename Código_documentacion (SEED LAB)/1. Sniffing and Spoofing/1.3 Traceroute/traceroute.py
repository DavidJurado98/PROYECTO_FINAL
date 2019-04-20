#!/usr/bin/python
# -*- coding: UTF-8 -*-
from scapy.all import *

print "=======================[TRACEROUTE]======================="
#Introducimos la direccion:
direccion = "www.iana.org"
for ttl in range(1, 28):
    pkt = IP(dst=direccion, ttl=ttl) / UDP(dport=33434)
    #El puerto 33434 es el traceroute para la localizacion de rutas.
    # Envia los paquetes y obtiene un reply (sr1() es una funcion que envia un paquete y escucha la respuesta, en este caso si no se recibe respuesta salta el "break")
    reply = sr1(pkt, verbose=0)
    if reply is None:
        # Si no recibe el reply se para
        break
    elif reply.type == 3:
        # Llega con exito a su destino
	print "=========================================================="
        print "Ruta trazada con exito a la direccion:", reply.src
	print "=========================================================="
	break
    else:
        # Esta en proceso de llegar a su destino
        print "Router %i con exito:"% ttl,reply.src
