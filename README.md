# 2IC80-Default-Project

This is a simple command-line tool to run ARP poisoning, DNS spoofing, and SSL stripping attacks for victims in the same network as the attacker, written in Python.

## Prerequisites
1. Linux Operating system
2. Python (preferable version 3.6.5)
3. Helping libraries installed

## Steps to run
```
sudo python attacker.py
```

### Other commands

Create port redirection
```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

Delete port redirection
```
sudo iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

See the active ip tables
```
sudo iptables -t nat -L PREROUTING
```

Note: Check scripts for setting proper ips. The victims browser needs to have clear cookies and history (check privacy settings).
