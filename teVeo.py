from scapy.all import *

ap_list = []

def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 4:
			if pkt.addr2 == "f8:a9:d0:4f:52:30":
				print "--detectado Nico signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "48:a2:2d:76:28:93":
				print "--detectado Dad signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "5c:95:ae:e0:8c:da":
				print "--detectado Jou signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "34:4d:f7:38:59:a8":
				print "--detectado Pat signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))

sniff(iface="wlan0",prn = PacketHandler)
