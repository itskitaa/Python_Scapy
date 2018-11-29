#!/usr/bin/python
import os
import sys
import argparse
import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict

# function to view statistics of protocol by frequency
def protoStats(pkts):
	# courtesy of https://github.com/envelope000/anycon-2017/tree/master/esp8266
	print "\t[*]Protocol by Frequency\n"
	i = 0
	layers = []
	counts = {}
	for pkt in pkts:
		i=0
		while True:
			layer = pkt.getlayer(i)
			if (layer != None):
				if (layer.name not in counts):
					counts[layer.name]=0
				counts[layer.name] += 1
			else:
				break
			i += 1

	sortedcounts = OrderedDict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
	for prot in sortedcounts:
		if (prot != None):
			print prot, sortedcounts[prot]
	print ""

# function to view list of IP Addresses in conversations
def IPAddresses(pkts) : 
	print "\t[*]IP Addresses in conversations\n"
	ipAddresses = set()
	for pkt in pkts:
		if pkt.haslayer(IP):
			src = pkt[IP].src
			if src and (src not in ipAddresses):
				ipAddresses.add(src)
				print len(ipAddresses), src
	print ""

# function to view dns traffic in PCAP file
def DNSTraffic(pkts) :
	print "\t[*] DNS Traffic in PCAP File\n"
	for pkt in pkts:
		ipLayer = pkt.getlayer(IP)
		if (pkt.haslayer(DNS)) and (pkt.payload.dport == 53):
			dns = pkt.payload.qd.qname
			results = "Source IP: " + ipLayer.src + " Destination IP: " + ipLayer.dst + " Queried Domain Name: " + dns
			print results

# function to view list of visited urls in PCAP File
def HTTPTraffic(pkts) : 
	# Courtesy of:
	# https://gist.githubusercontent.com/ismailakkila/a5e182fffb7d7c1300fdd13b4b5a147b/raw/88509a58fa67d59fe5ccd642bc97157b20f7826d/scapy_parser.py
	print "\t[*]Visited URLs by Source and Destination\n"
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
	print"\t[*] ARP Traffic in PCAP Files\n"
	for pkt in pkts:
		if pkt.haslayer(ARP) and (pkt[ARP].op == 1):
			print pkt[ARP].hwsrc + " at " + pkt[ARP].psrc + " looked up " + pkt[ARP].pdst # + pkt[ARP].hwdst + " at "

		elif pkt.haslayer(ARP) and (pkt[ARP].op == 2):
				print pkt[ARP].hwsrc + " at " + pkt[ARP].psrc + " replied to " + pkt[ARP].hwdst + " at " + pkt[ARP].pdst

# function to view ICMP traffic in PCAP File
def ICMPTraffic(pkts) : 
	print "\t[*] ICMP Traffic in PCAP File\n"
	for pkt in pkts:
		eLayer = pkt.getlayer(Ether)
		ipLayer = pkt.getlayer(IP)
		if pkt.haslayer(ICMP) and (pkt[ICMP].type == 8):
			print eLayer.src + " at " + ipLayer.src + " echo-requested " + eLayer.dst + " at " +ipLayer.dst
		elif pkt.haslayer(ICMP) and (pkt[ICMP].type == 0):
			print eLayer.src + " at " + ipLayer.src + " echo-replied " + eLayer.dst + " at " + ipLayer.dst

# function to view DHCP traffic in PCAP File
def DHCPTraffic(pkts) : 
	print "\t[*] DHCP Traffic in PCAP File\n"
	for pkt in pkts:
		eLayer = pkt.getlayer(Ether)
		ipLayer = pkt.getlayer(IP)
		if (pkt.haslayer(UDP) and pkt.getlayer(UDP).sport == 68):
			option = pkt.getlayer(DHCP).options[0][1]
			if option == 1:
				print eLayer.src + " sent a DHCP Discover to " + eLayer.dst + " at " + ipLayer.dst
			elif option == 3:
				print eLayer.src + " made a DHCP Request to " + str(pkt.getlayer(DHCP).options[3][1])
		elif (pkt.haslayer(UDP) and pkt.getlayer(UDP).dport == 68):
			option = pkt.getlayer(DHCP).options[0][1]
			if option == 2:
				print eLayer.src + " at " + ipLayer.src + " made the Following DHCP Offer to " + eLayer.dst + "\n\t" \
				 + " IP Address: " + str(pkt.getlayer(BOOTP).yiaddr)\
				  + "\n\t" + " Subnet: " + str(pkt.getlayer(DHCP).options[1][1]) \
				 + "\n\t" + " Lease time: " + str((pkt.getlayer(DHCP).options[4][1])/3600) + " hour" \
				 + "\n\t" + " Renewal time: " + str((pkt.getlayer(DHCP).options[2][1])/60) + " minutes"
			elif option == 5:
				print eLayer.src + " at " + ipLayer.src + " ACKED the assignment of " + ipLayer.dst + " to "  + eLayer.dst 

# function to view FTP Traffic in PCAP File
def FTPTraffic(pkts) : 

	for pkt in pkts:
		if (pkt.getlayer(TCP).dport == 21 ) or (pkt.getlayer(TCP).sport == 21):
			# print pkt.getlayer(Raw)
			if pkt.getlayer(Raw) != None:
				print pkt.getlayer(Raw).load
			else:
				pass

# function to view SMTP Traffic in PCAP File
def SMTPTraffic(pkts) :
	
	for pkt in pkts:
		if (pkt.getlayer(TCP).dport == 25 ) or (pkt.getlayer(TCP).sport == 25):
			if pkt.getlayer(Raw) != None:
				print pkt.getlayer(Raw).load
			else:
				pass
	# print "\t[*] MAIL Traffic in PCAP File"
	# for pkt in pkts:
	# 	eLayer = pkt.getlayer(Ether)
	# 	ipLayer = pkt.getlayer(IP)
	# 	if pkt.haslayer(SMTP) or pkt.haslayer(POP) or pkt.haslayer(IMAP):
	
def SSHTraffic(pkts) : 
	if (pkt.payload.dport == 443 ) or (pkt.payload.sport == 443 ):
		
		print pkt.summary()
	
def SSLTraffic(pkts) : 

	if (pkt.payload.dport == 443 ) or (pkt.payload.sport == 443 ):
		
		print pkt.summary()

def Threader(func, pkts):
	threadHandler = threading.Thread(target=func,args=(pkts,))
	threadHandler.start()

if __name__ == "__main__":

	parser = argparse.ArgumentParser(description="Kitaa's pcapy-analyzer - A PCAP Files analyzer based on Scapy, the interactive packet manipulation tool")
	parser.add_argument("-f","--file", dest='pcap', metavar="PCAP", help="PCAP File to analyze", required=True)
	parser.add_argument("-t","--traffic", dest="traffic", type=str, help="Type of traffic to analyze")
	parser.add_argument("-i","--ip-addressess",dest="ips",action="store_true",help="View IP Addresses in PCAP")
	parser.add_argument("-s","--statistics",dest="stats",action="store_true",help="View statistics of protocols by frequency")
	# parser.add_argument("--statistics, help="View stats of protocols by frequency")
	# parser.add_argument("-o", "--output-file, help="file to output results", type=argparse.FileType('a'))
	# parser.add_argument("")

	if len(sys.argv[1:])==0:
		parser.print_help()
		# parser.print_usage() # for just the usage line
		parser.exit()

	args = parser.parse_args()

	print "\t\nPCAP File to analyze is: ", args.pcap + "\n"
	try:
		pkts = rdpcap(args.pcap)
		traffic=str(args.traffic)

		if args.ips:
			IPAddresses(pkts)

		if args.stats:
			protoStats(pkts)

		if traffic.lower() == "dns":
			Threader(DNSTraffic,pkts)
		elif traffic.lower() == "icmp":
			Threader(ICMPTraffic,pkts)
		elif traffic.lower() == "arp":
			Threader(ARPTraffic,pkts)
		elif traffic.lower() == "http":
			Threader(HTTPTraffic,pkts)
		elif traffic.lower() == "dhcp":
			Threader(DHCPTraffic,pkts)
		elif traffic.lower() == "ftp":
			Threader(FTPTraffic,pkts)
		elif traffic.lower() == "smtp":
			Threader(SMTPTraffic,pkts)

	except Exception as e:
		raise e
	

	