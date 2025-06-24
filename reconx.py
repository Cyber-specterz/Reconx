#!/usr/bin/env python3
import socket
import requests
import json
import whois
from termcolor import colored

def banner():
    print(colored(r"""
██████  ███████  ██████  ██████  ███    ██ ██   ██ 
██   ██ ██      ██      ██   ██ ████   ██  ██ ██  
██   ██ █████   ██      ██   ██ ██ ██  ██   ███   
██   ██ ██      ██      ██   ██ ██  ██ ██  ██ ██  
██████  ███████  ██████ ██████  ██   ████ ██   ██ 
        v1.0 by @cyber_specterz | Tool: reconx
""", "red"))

def dns_lookup(domain):
    print(colored("\n[+] DNS Lookup", "cyan"))
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
    except socket.gaierror:
        print("❌ DNS lookup failed.")

def whois_lookup(domain):
    print(colored("\n[+] WHOIS Lookup", "cyan"))
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print("❌ WHOIS lookup failed:", str(e))

def geo_ip_lookup(domain):
    print(colored("\n[+] IP Geolocation", "cyan"))
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        for k, v in r.items():
            print(f"{k}: {v}")
    except Exception as e:
        print("❌ Geolocation lookup failed:", str(e))

def crt_subdomains(domain):
    print(colored("\n[+] Subdomain Enumeration (crt.sh)", "cyan"))
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        data = r.json()
        found = set()
        for entry in data:
            name = entry['name_value']
            for sub in name.split('\n'):
                found.add(sub.strip())
        for sub in sorted(found):
            print(sub)
    except Exception as e:
        print("❌ Subdomain enumeration failed:", str(e))

def main():
    banner()
    domain = input(colored("\nEnter domain (e.g., example.com): ", "yellow")).strip()
    dns_lookup(domain)
    whois_lookup(domain)
    geo_ip_lookup(domain)
    crt_subdomains(domain)

if __name__ == "__main__":
    main()
