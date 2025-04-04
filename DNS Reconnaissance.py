"""
This script performs DNS reconnaissance by:

1. Performing Reverse DNS lookups (finding domain names associated with an IP).

2. Resolving DNS records for a given domain (finding its IP address).

4. Searching for subdomains using a dictionary list of words.

5. The script is designed to find subdomains of a given domain
(e.g., google.com) by appending common words from a file (subdomains.txt)
and checking if they resolve to an IP address.

"""

#IMPORT REQUIRED LIBRARIES
import dns
import dns.resolver
import socket

#REVERSE DNS LOOK-UP FUNCTION
def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]]+result[1]
    except socket.herror:
        return None

#DNS REQUEST FUNCTION
def DNSRequest(domain):
    ips = []
    try:
        result = dns.resolver.resolve(domain)
        if result:
            print(domain)
            for answer in result:
                print(answer)
                print("Domain Names: %s" % ReverseDNS(answer.to_text()))
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []
    return ips

#SUBDOMAIN ENUMERATION
def SubdomainSearch(domain, dictionary,nums):
    successes = []
    for word in dictionary:
        subdomain = word+"."+domain
        DNSRequest(subdomain)
        if nums:
            for i in range(0,10):
                s = word+str(i)+"."+domain
                DNSRequest(s)

#READING THE DICTIONARY FILE
domain = "google.com"
d = "subdomains.txt"
dictionary = []
with open(d,"r") as f:
    dictionary = f.read().splitlines()
SubdomainSearch(domain,dictionary,True)
