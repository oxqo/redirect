from scapy.all import *
import os
import sys

MY_IP="192.168.101.147"
def fwd_block(packet):
	if(packet[IP].src)== MY_IP):
		packet[TCP].flags = 'F'
		del packet[Raw].load
		del packet[IP].chksum
		del packet[TCP].chksum
		del packet.chksum
		sendp(packet)

def bwd_block(packet):
	if(packet[IP].src == MY_IP):
		packet[TCP].seq += len(packet[Raw].load)
		packet[TCP].flags = 'FA'
		packet[IP].src, packet[IP].dst = packet[IP].dst, packet[IP].src
		packet[Ether].src, packet[Ether].dst = packet[Ether].dst, packet[Ether].src
		packet[TCP].sport, packet[TCP].dport = packet[TCP].dport, packet[TCP].sport
		packet[TCP].seq , packet[TCP].ack = packet[TCP].ack, packet[TCP].seq
		del packet[Raw].load
		del packet[IP].chksum
		del packet[TCP].chksum
		del packet.chksum
		
		sendp(packet)

def print_packet(packet):
	if(packet.haslayer(Raw)):
		if(str(packet[Raw].load).find("GET")>=0):
			#fwd_block(packet)
			bwd_block(packet)

sniff(filter="tcp port 80 and host 192.168.101.147", prn=print_packet, iface="eth0", store=0)
