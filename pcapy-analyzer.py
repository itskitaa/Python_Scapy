#!/usr/bin/python
import os
import sys
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


# function to view list of IP Addresses in conversations
def IPAddresses(pkts) : 

	print "\t[*]IP Addresses in conversations"
	for pkt in pkts:
		if pkt.haslayer(IP):
			src = pkt[IP].src
			if src and (src not in ipAddresses):
				ipAddresses.add(src)
				print len(ipAddresses), src

# function to view dns traffic in PCAP file
def DNSTraffic(pkts) :

	print "\t[*] DNS Traffic in PCAP File"
	for pkt in pkts:
		ipLayer = pkt.getlayer(IP)
		if (pkt.haslayer(DNS)) and (pkt.payload.dport == 53):
			dns = pkt.payload.qd.qname
			print ("Source IP: " + ipLayer.src + " Destination IP: " + ipLayer.dst + " Queried Domain Name: " + dns)

# function to view list of visited urls in PCAP File
def HTTPTraffic(pkts) : 

	# Courtesy of:
	# https://gist.githubusercontent.com/ismailakkila/a5e182fffb7d7c1300fdd13b4b5a147b/raw/88509a58fa67d59fe5ccd642bc97157b20f7826d/scapy_parser.py
	print "\t[*]Visited URLs by Source and Destination"
	sessions = pkts.sessions()
	for session in sessions:
		for packet in sessions[session]:
			try:
				ipLayer = packet.getlayer(IP)
				if packet[TCP].dport == 80:
					payload = bytes(packet[TCP].payload)
					url_path = payload[payload.index(b"GET ")+4:payload.index(b" HTTP/1.1")].decode("utf8")
					http_header_raw = payload[:payload.index(b"\r\n\r\n")+2]
					http_header_parsed = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
					url = http_header_parsed["Host"] + url_path
					print ipLayer.src + " requested the url " + url.encode() + "  at " + ipLayer.dst
			except:
				pass

# function to view ARP traffic in PCAP File
def ARPTraffic(pkts) : 

	print"\t[*] ARP Traffic in PCAP Files"
	for pkt in pkts:
		if pkt.haslayer(ARP) and (pkt[ARP].op == 1):
			print pkt[ARP].hwsrc + " at " + pkt[ARP].psrc + " looked up " + pkt[ARP].pdst # + pkt[ARP].hwdst + " at "

		elif pkt.haslayer(ARP) and (pkt[ARP].op == 2):
				print pkt[ARP].hwsrc + " at " + pkt[ARP].psrc + " replied to " + pkt[ARP].hwdst + " at " + pkt[ARP].pdst

# function to view ICMP traffic in PCAP File
def ICMPTraffic(pkts) : 

	print "\t[*] ICMP Traffic in PCAP File"
	for pkt in pkts:
		eLayer = pkt.getlayer(Ether)
		ipLayer = pkt.getlayer(IP)
		if pkt.haslayer(ICMP) and (pkt[ICMP].type == 8):
			print eLayer.src + " at " + ipLayer.src + " echo-requested " + eLayer.dst + " at " +ipLayer.dst
		elif pkt.haslayer(ICMP) and (pkt[ICMP].type == 0):
			print eLayer.src + " at " + ipLayer.src + " echo-replied " + eLayer.dst + " at " + ipLayer.dst

def SMTPTraffic(pkts) :

def DHCPTraffic(pkts) : 

def SSHTraffic(pkts) : 

def SSLTraffic(pkts) : 

	if (pkt.payload.dport == 443 ) or (pkt.payload.sport == 443 ):
		
		print pkt.summary()

def FTPTraffic(pkts) : 

	if (pkt.payload.dport == 21 ) or (pkt.payload.sport == 21):
		
		print pkt.summary()


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument("pcap_file", help="/path/to/pcap/file")
	# parser.add_argument("")
	# parser.add_argument("")
	# parser.add_argument("")
	# parser.add_argument("")

	args = parser.parse_args()

	print ""
	print "Kitaa's pcapy-analyzer - A PCAP Files analyzer based on Scapy, the interactive packet manipulation tool"
	print ""
	print "PCAP File to analyze is: ", args.pcap_file
	print ""

	pkts = rdpcap(args.pcap_file)