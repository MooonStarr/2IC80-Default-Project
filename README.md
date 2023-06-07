# 2IC80-Default-Project

to create port redirection:
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

to delete port redirection:
sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

to see the active ip tables:
sudo iptables -t nat -L PREROUTING

Currently required steps:
1. sudo python arp_spoofing_for_ssl.py (ARP spoofing)
2. sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080 (IP port redirection)
3. sudo python project_ssl.py (SSL stripping)

Note: Check scripts for setting proper ips. The victims browser needs to have clear cookies and history (check privacy settings).
