import os
import sys
import subprocess
import datetime
import re
import socket


def print_banner():
    banner = '''
\033[1;31m  _   _  ___   ___  ____  ____  _____ ____ ___  _   _ \033[0m
\033[1;32m | \ | |/ _ \ / _ \| __ )|  _ \| ____/ ___/ _ \| \ | |\033[0m
\033[1;33m |  \| | | | | | | |  _ \| |_) |  _|| |  | | | |  \| |\033[0m
\033[1;34m | |\  | |_| | |_| | |_) |  _ <| |__| |__| |_| | |\  |\033[0m
\033[1;35m |_| \_|\___/ \___/|____/|_| \_\_____\____\___/|_| \_|\033[0m
\033[1;36m                                                      \033[0m
\033[1;37m DEVELOPER: ADHITHYA | VERSION: V.1.0 \033[0m
'''
    print(banner)


def run_nmap_scan(target, recon_file):
    print("Running Nmap scan...")
    result = subprocess.run(["nmap", "-sV", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())


def run_traceroute(target, recon_file):
    print("Running Traceroute...")
    result = subprocess.run(["traceroute", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())


def run_dns_queries(target, recon_file):
    print("Running DNS queries...")
    result = subprocess.run(["host", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())
    
    result = subprocess.run(["host", "-t", "mx", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())
    
    result = subprocess.run(["host", "-t", "ns", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())
    
    result = subprocess.run(["host", "-t", "txt", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())


def check_zone_transfer(target, recon_file):
    print("Checking Zone Transfer...")
    result = subprocess.run(["dig", "AXFR", target], capture_output=True)
    if "Transfer failed" in result.stdout.decode():
        print("Zone transfer not possible")
        recon_file.write("Zone transfer not possible\n")
    else:
        print("Zone transfer possible")
        recon_file.write("Zone transfer possible\n")


def run_whois_lookup(target, recon_file):
    print("Running Whois lookup...")
    result = subprocess.run(["whois", target], capture_output=True, text=True)
    if result.returncode == 0:
        output = result.stdout.strip()
        print(output)
        recon_file.write(output)
    else:
        print("Error occurred during Whois lookup.")
        print(result.stderr)



def run_dirb_scan(target, recon_file):
    print("Running Dirb scan...")
    url = f"http://{target}"
    result = subprocess.run(["dirb", url], capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
        recon_file.write(result.stdout)
    if result.stderr:
        print(result.stderr)
        recon_file.write(result.stderr)




def run_wafw00f(target, recon_file):
    print("Running WAFW00F...")
    result = subprocess.run(["wafw00f", target], capture_output=True)
    print(result.stdout.decode())
    recon_file.write(result.stdout.decode())



def run_subfinder(target, recon_file):
    print("Running Subfinder...")
    result = subprocess.run(["subfinder", "-d", target], capture_output=True, text=True)
    if result.returncode == 0:
        subdomains = result.stdout.strip()
        if subdomains:
            print(subdomains)
            print(f"Found {len(subdomains.splitlines())} subdomains")
            recon_file.write(subdomains)
            recon_file.write(f"\nFound {len(subdomains.splitlines())} subdomains\n")
        else:
            print("No subdomains found.")
    else:
        print("Error occurred during Subfinder execution.")
        print(result.stderr.decode())



def is_valid_domain_or_ip(address):
    try:
        if socket.gethostbyname(address):
            return True
    except socket.error:
        pass

    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        pass

    return False



def main():
    print_banner()
    if len(sys.argv) != 2:
        print("Usage: python3 noobrecon.py [target]")
        return

    target = sys.argv[1]

    # Validate if the target is in the correct format
    if not is_valid_domain_or_ip(target):
        print("Enter a valid domain name or IP address")
        return

    recon_filename = f"{target}_recon.txt"

    with open(recon_filename, "w") as recon_file:
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "NMAP SCAN" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_nmap_scan(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "TRACEROUTE" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_traceroute(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "DNS RECON" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_dns_queries(target, recon_file)
        check_zone_transfer(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "WHOIS LOOKUP" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_whois_lookup(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "CHECKING FOR WEB APPLICATION FIREWALL" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_wafw00f(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "FINDING SUBDOMAINS" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_subfinder(target, recon_file)
        print("\033[34m" + "-" * 70 + "\033[0m")
        print("\033[34m" + "SEARCHING FOR HIDDEN FILES AND DIRECTORIES" + "\033[0m")
        print("\033[34m" + "-" * 70 + "\033[0m")
        run_dirb_scan(target, recon_file)
    print(f"Recon results saved to {recon_filename}")


if __name__ == "__main__":
    main()
