#!/usr/bin/env python3

import os
import sys
import time
import socket
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup
from scapy.all import ARP, Ether, srp
import re
import hashlib

# Function to print colored text
def print_colored(text, color):
    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'end': '\033[0m'
    }
    print(f"{colors[color]}{text}{colors['end']}")

# Function to clear the screen
def clear_screen():
    os.system('clear')

# Function to display the main menu
def display_menu():
    clear_screen()
    print_colored("""
    ______   ______   ______   ______   ______   ______   ______   ______   ______   ______
   /      \ /      \ /      \ /      \ /      \ /      \ /      \ /      \ /      \ /      \
  /$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |$$$$$$  |
  $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
  $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
  $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
  $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
  $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
  $$ \__/$$ |$$ |  $$ |$$ |__$$ |$$ |__$$ |$$ |__$$ |$$ |__$$ |$$ |__$$ |$$ |__$$ |$$ |__$$ |
   \______/  \______/  \______/  \______/  \______/  \______/  \______/  \______/  \______/
    """, 'red')
    print_colored("ATI Tooljai - Hacking Toolkit", 'yellow')
    print_colored("1. Port Scanner", 'red')
    print_colored("2. IP Geolocation", 'red')
    print_colored("3. Subdomain Enumeration", 'red')
    print_colored("4. DNS Lookup", 'red')
    print_colored("5. Whois Lookup", 'red')
    print_colored("6. HTTP Header Grabber", 'red')
    print_colored("7. SSL Certificate Checker", 'red')
    print_colored("8. Banner Grabber", 'red')
    print_colored("9. Directory Brute Force", 'red')
    print_colored("10. SQL Injection Scanner", 'red')
    print_colored("11. XSS Scanner", 'red')
    print_colored("12. Robots.txt Checker", 'red')
    print_colored("13. Sitemap Checker", 'red')
    print_colored("14. Email Harvester", 'red')
    print_colored("15. Password Cracker", 'red')
    print_colored("16. Hash Cracker", 'red')
    print_colored("17. Network Scanner", 'red')
    print_colored("18. Vulnerability Scanner", 'red')
    print_colored("19. Exploit Database Search", 'red')
    print_colored("20. Metasploit Integration", 'red')
    print_colored("21. Exit", 'red')
    print()

# Function to perform a port scan
def port_scan(target):
    print_colored(f"Scanning ports on {target}...", 'blue')
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    if open_ports:
        print_colored(f"Open ports: {', '.join(map(str, open_ports))}", 'green')
    else:
        print_colored("No open ports found.", 'red')
    print_colored("Port scan completed.", 'blue')

# Function to perform IP geolocation
def ip_geolocation(ip):
    print_colored(f"Performing IP geolocation on {ip}...", 'blue')
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        print_colored(f"Country: {data['country']}", 'green')
        print_colored(f"Region: {data['regionName']}", 'green')
        print_colored(f"City: {data['city']}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("IP geolocation completed.", 'blue')

# Function to enumerate subdomains
def subdomain_enumeration(domain):
    print_colored(f"Enumerating subdomains for {domain}...", 'blue')
    subdomains = ["mail", "www", "ftp", "ns1", "ns2"]
    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            print_colored(f"Found subdomain: {full_domain} -> {ip}", 'green')
        except socket.error:
            pass
    print_colored("Subdomain enumeration completed.", 'blue')

# Function to perform a DNS lookup
def dns_lookup(domain):
    print_colored(f"Performing DNS lookup for {domain}...", 'blue')
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print_colored(f"A Record: {rdata}", 'green')
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print_colored(f"MX Record: {rdata.exchange}", 'green')
    except dns.resolver.NoAnswer:
        print_colored("No DNS records found.", 'red')
    except dns.resolver.NXDOMAIN:
        print_colored("Domain does not exist.", 'red')
    print_colored("DNS lookup completed.", 'blue')

# Function to perform a Whois lookup
def whois_lookup(domain):
    print_colored(f"Performing Whois lookup for {domain}...", 'blue')
    try:
        w = whois.whois(domain)
        print_colored(f"Registrar: {w.registrar}", 'green')
        print_colored(f"Registration Date: {w.creation_date}", 'green')
        print_colored(f"Expiration Date: {w.expiration_date}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Whois lookup completed.", 'blue')

# Function to grab HTTP headers
def http_header_grabber(url):
    print_colored(f"Grabbing HTTP headers for {url}...", 'blue')
    try:
        response = requests.head(url)
        for header, value in response.headers.items():
            print_colored(f"{header}: {value}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("HTTP header grab completed.", 'blue')

# Function to check SSL certificates
def ssl_certificate_checker(domain):
    print_colored(f"Checking SSL certificate for {domain}...", 'blue')
    try:
        response = requests.get(f"https://{domain}", verify=True)
        cert = response.connection.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        print_colored(f"Issuer: {issuer['commonName']}", 'green')
        print_colored(f"Expiration Date: {cert['notAfter']}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("SSL certificate check completed.", 'blue')

# Function to grab banners
def banner_grabber(target):
    print_colored(f"Grabbing banners from {target}...", 'blue')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, 22))
        banner = sock.recv(1024).decode()
        print_colored(f"Banner: {banner}", 'green')
        sock.close()
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Banner grab completed.", 'blue')

# Function to perform directory brute force
def directory_brute_force(target):
    print_colored(f"Performing directory brute force on {target}...", 'blue')
    directories = ["admin", "login", "panel", "dashboard", "backup"]
    for directory in directories:
        url = f"http://{target}/{directory}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print_colored(f"Found directory: {directory}", 'green')
        except Exception as e:
            print_colored(f"Error: {e}", 'red')
    print_colored("Directory brute force completed.", 'blue')

# Function to scan for SQL injection
def sql_injection_scanner(target):
    print_colored(f"Scanning for SQL injection on {target}...", 'blue')
    payloads = ["' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1' #"]
    for payload in payloads:
        url = f"{target}?id={payload}"
        try:
            response = requests.get(url)
            if "SQL syntax" in response.text or "MySQL" in response.text:
                print_colored(f"Vulnerable parameter found: id with payload {payload}", 'green')
        except Exception as e:
            print_colored(f"Error: {e}", 'red')
    print_colored("SQL injection scan completed.", 'blue')

# Function to scan for XSS
def xss_scanner(target):
    print_colored(f"Scanning for XSS on {target}...", 'blue')
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    for payload in payloads:
        url = f"{target}?search={payload}"
        try:
            response = requests.get(url)
            if payload in response.text:
                print_colored(f"Vulnerable parameter found: search with payload {payload}", 'green')
        except Exception as e:
            print_colored(f"Error: {e}", 'red')
    print_colored("XSS scan completed.", 'blue')

# Function to check robots.txt
def robots_txt_checker(target):
    print_colored(f"Checking robots.txt for {target}...", 'blue')
    url = f"http://{target}/robots.txt"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print_colored(f"Robots.txt content:\n{response.text}", 'green')
        else:
            print_colored("Robots.txt not found.", 'red')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Robots.txt check completed.", 'blue')

# Function to check sitemap
def sitemap_checker(target):
    print_colored(f"Checking sitemap for {target}...", 'blue')
    url = f"http://{target}/sitemap.xml"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print_colored(f"Sitemap URL: {url}", 'green')
        else:
            print_colored("Sitemap not found.", 'red')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Sitemap check completed.", 'blue')

# Function to harvest emails
def email_harvester(target):
    print_colored(f"Harvesting emails from {target}...", 'blue')
    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = soup.find_all(text=re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'))
        for email in emails:
            print_colored(f"Found email: {email}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Email harvest completed.", 'blue')

# Function to crack passwords
def password_cracker(target):
    print_colored(f"Cracking passwords for {target}...", 'blue')
    password_list = ["password", "123456", "qwerty", "letmein", "admin"]
    with open(target, 'r') as file:
        hashes = file.readlines()
    for hash in hashes:
        hash = hash.strip()
        for password in password_list:
            if hash == hashlib.md5(password.encode()).hexdigest():
                print_colored(f"Cracked password: {password} for hash {hash}", 'green')
                break
    print_colored("Password crack completed.", 'blue')

# Function to crack hashes
def hash_cracker(target):
    print_colored(f"Cracking hashes for {target}...", 'blue')
    hash_list = ["5f4dcc3b5aa765d61d8327deb882cf99", "202cb962ac59075b964b07152d234b70"]
    password_list = ["password", "123456", "qwerty", "letmein", "admin"]
    with open(target, 'r') as file:
        hashes = file.readlines()
    for hash in hashes:
        hash = hash.strip()
        for password in password_list:
            if hash == hashlib.md5(password.encode()).hexdigest():
                print_colored(f"Cracked hash: {hash} with password {password}", 'green')
                break
    print_colored("Hash crack completed.", 'blue')

# Function to scan the network
def network_scanner(target):
    print_colored(f"Scanning network for {target}...", 'blue')
    arp_request = ARP(pdst=target)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for sent, received in answered_list:
        print_colored(f"Found device: {received.psrc} -> {received.hwsrc}", 'green')
    print_colored("Network scan completed.", 'blue')

# Function to scan for vulnerabilities
def vulnerability_scanner(target):
    print_colored(f"Scanning for vulnerabilities on {target}...", 'blue')
    try:
        response = requests.get(f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={target}")
        soup = BeautifulSoup(response.text, 'html.parser')
        vulnerabilities = soup.find_all('a', href=True)
        for vulnerability in vulnerabilities:
            print_colored(f"Vulnerability found: {vulnerability.text}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Vulnerability scan completed.", 'blue')

# Function to search the exploit database
def exploit_database_search(target):
    print_colored(f"Searching exploit database for {target}...", 'blue')
    try:
        response = requests.get(f"https://www.exploit-db.com/search/?q={target}")
        soup = BeautifulSoup(response.text, 'html.parser')
        exploits = soup.find_all('a', href=True)
        for exploit in exploits:
            print_colored(f"Exploit found: {exploit.text}", 'green')
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Exploit database search completed.", 'blue')

# Function to integrate with Metasploit
def metasploit_integration(target):
    print_colored(f"Integrating with Metasploit for {target}...", 'blue')
    try:
        os.system(f"msfconsole -x 'use auxiliary/scanner/portscan/syn; set RHOSTS {target}; run'")
    except Exception as e:
        print_colored(f"Error: {e}", 'red')
    print_colored("Metasploit integration completed.", 'blue')

# Main function to handle user input and tool selection
def main():
    while True:
        display_menu()
        choice = input("Select a tool (1-21): ")
        if choice == '1':
            target = input("Enter target IP/Host: ")
            port_scan(target)
        elif choice == '2':
            ip = input("Enter IP address: ")
            ip_geolocation(ip)
        elif choice == '3':
            domain = input("Enter domain: ")
            subdomain_enumeration(domain)
        elif choice == '4':
            domain = input("Enter domain: ")
            dns_lookup(domain)
        elif choice == '5':
            domain = input("Enter domain: ")
            whois_lookup(domain)
        elif choice == '6':
            url = input("Enter URL: ")
            http_header_grabber(url)
        elif choice == '7':
            domain = input("Enter domain: ")
            ssl_certificate_checker(domain)
        elif choice == '8':
            target = input("Enter target IP/Host: ")
            banner_grabber(target)
        elif choice == '9':
            target = input("Enter target domain: ")
            directory_brute_force(target)
        elif choice == '10':
            target = input("Enter target URL: ")
            sql_injection_scanner(target)
        elif choice == '11':
            target = input("Enter target URL: ")
            xss_scanner(target)
        elif choice == '12':
            target = input("Enter target domain: ")
            robots_txt_checker(target)
        elif choice == '13':
            target = input("Enter target domain: ")
            sitemap_checker(target)
        elif choice == '14':
            target = input("Enter target URL: ")
            email_harvester(target)
        elif choice == '15':
            target = input("Enter file path with hashes: ")
            password_cracker(target)
        elif choice == '16':
            target = input("Enter file path with hashes: ")
            hash_cracker(target)
        elif choice == '17':
            target = input("Enter target network (e.g., 192.168.1.0/24): ")
            network_scanner(target)
        elif choice == '18':
            target = input("Enter target to scan for vulnerabilities: ")
            vulnerability_scanner(target)
        elif choice == '19':
            target = input("Enter search term for exploit database: ")
            exploit_database_search(target)
        elif choice == '20':
            target = input("Enter target IP/Host: ")
            metasploit_integration(target)
        elif choice == '21':
            print_colored("Exiting ATI Tooljai - Hacking Toolkit.", 'yellow')
            break
        else:
            print_colored("Invalid choice. Please select a valid option.", 'red')

if __name__ == "__main__":
    main()
