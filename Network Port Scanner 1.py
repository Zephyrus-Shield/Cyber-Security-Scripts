"""
This code is a simple port scanner using Scapy, a powerful Python library for network packet manipulation. It performs two types of scans:

SYN Scan – Checks if specific TCP ports are open on the target.

DNS Scan – Checks if the target is a DNS server.
"""

#IMPORT REQUIRED LIBRARY
from scapy.all import *

#DEFINE THE PORTS TO SCAN
ports = [25,80,53,443,445,8080,8443]

#SYN SCAN FUNCTION
def SynScan(host):
    """
This function scans TCP ports using a SYN (Stealth) Scan on a given host.

This function contains codes for;

1. Building and sending SYN packets.

2. Processing the responses.

3. Loops through each answered request (s) and its response (r).

4. Ensures both the sent and received packets contain a TCP layer.

5. Compares the destination port of the request (s[TCP].dport) with the source port of the response (r[TCP].sport).

6. If they match, it means the port is open and responds.

"""
    
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),timeout=2,verbose=0)
    
    print("Open ports at %s:" % host)
    
    for (s,r,) in ans:
        if s.haslayer(TCP) and r.haslayer(TCP):
            if s[TCP].dport == r[TCP].sport:
                print(s[TCP].dport)

#DNS SCAN FUNCTION
def DNSScan(host):
    
    """
    This function checks if the host is a DNS server by sending a DNS query.
    
    This function contains codes for;
    
    1. Building and Sending DNS query.
    
    2. Processing the responses.     
    
    """
    
    ans,unans = sr(IP(dst=host)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
    if ans:
        print("DNS Server at %s"%host)

#PERFROMING THE SCANS    
host = "8.8.8.8"

SynScan(host)
DNSScan(host)
