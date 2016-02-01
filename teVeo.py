from scapy.all import *

ap_list = []

banner = '''
--==TeVeO==-- 
a stalkers best friend...

Version: %s
Programador: %s
''' % ('0.1','Nicotrial')

def PacketHandler(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 4:
			if pkt.addr2 == "ff:af:df:4f:5f:3f":
				print "--detectado Persona1 signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "4f:af:2f:7f:2f:9f":
				print "--detectado Persona2 signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "5f:9f:af:ef:8f:df":
				print "--detectado Persona3 signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))
			if pkt.addr2 == "3f:4f:ff:3f:5f:af":
				print "--detectado Persona4 signal = %d" %(-(256-ord(pkt.notdecoded[-4:-3])))

def PacketHandler2(pkt):
	if pkt.haslayer(Dot11):
		if pkt.type == 0 and pkt.subtype == 4:
			print "Probe Detected: %s" %(pkt.addr2)


def main():
	help = '''
--------------------------------------
	Remember: Start wifi in monitor mode before using 
		  or you will not capture anything	
	Usage:./teVeo.py -s
	
	Options:
		-s: Begin Scan
		-a: Scan all Probes
	
	Ejemplo: ./teVeo.py -s
	ctrl-c to end..
--------------------------------------
	'''
	if sys.argv[1] == '-s':
		sniff(iface="wlan0",prn = PacketHandler)
	if sys.argv[1] == '-a':
		sniff(iface="wlan0",prn = PacketHandler2)
	else:
		print(help)

if __name__ == '__main__':
	print(banner)
	main()
