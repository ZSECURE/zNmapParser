#!/usr/bin/python3
import re
import argparse
from termcolor import colored

def parse_nmap_output(nmap_output):
    # Initialize dictionaries to hold the categorized open ports for each host
    domain_controllers = {}
    printers = {}
    web_servers = {}
    windows_hosts = {}
    linux_hosts = {}
    database_servers = {}
    vpn_servers = {}
    remote_access_tools = {}
    exploitable_services = {}
    dns_servers = {}
    ftp_servers = {}
    email_servers = {}
    voip_servers = {}
    file_sharing_services = {}
    remote_administration_tools = {}
    
    # Parse the Nmap output to extract information about each host and its open ports
    ip_address = None
    for line in nmap_output.splitlines():
        # Extract the IP address of the host
        ip_match = re.search(r'Nmap scan report for ([\d\.]+)', line)
        if ip_match:
            ip_address = ip_match.group(1)
            continue
        
        # Extract the port number and service name for each open port
        port_match = re.search(r'(\d+)/(\w+)\s+open', line)
        if port_match:
            port_number = int(port_match.group(1))
            service_name = port_match.group(2)
            
            # Categorize the open ports based on their common use cases
            if port_number in [389, 636, 3268, 3269]:
                if ip_address:
                    domain_controllers[ip_address] = domain_controllers.get(ip_address, []) + [port_number]
            elif port_number in [515, 9100, 631]:
                if ip_address:
                    printers[ip_address] = printers.get(ip_address, []) + [port_number]
            elif port_number in [80, 443, 8080]:
                if ip_address:
                    web_servers[ip_address] = web_servers.get(ip_address, []) + [port_number]
            elif port_number in [135, 139, 445, 3389]:
                if ip_address:
                    windows_hosts[ip_address] = windows_hosts.get(ip_address, []) + [port_number]
            elif port_number in [22, 111, 2049]:
                if ip_address:
                    linux_hosts[ip_address] = linux_hosts.get(ip_address, []) + [port_number]
            elif port_number in [3306, 5432, 1433]:
                if ip_address:
                    database_servers[ip_address] = database_servers.get(ip_address, []) + [port_number]
            elif port_number in [1194, 1723]:
                if ip_address:
                    vpn_servers[ip_address] = vpn_servers.get(ip_address, []) + [port_number]
            elif port_number in [3389, 5900, 23]:
                if ip_address:
                    remote_access_tools[ip_address] = remote_access_tools.get(ip_address, []) + [port_number]
            elif port_number in [21, 22, 80]:
                if ip_address:
                    exploitable_services[ip_address] = exploitable_services.get(ip_address, []) + [port_number]
            elif port_number in [53]:
                if ip_address:
                    dns_servers[ip_address] = dns_servers.get(ip_address, []) + [port_number]
            elif port_number in [20, 21]:
                if ip_address:
                    ftp_servers[ip_address] = ftp_servers.get(ip_address, []) + [port_number]
            elif port_number in [25, 143, 110]:
                if ip_address:
                    email_servers[ip_address] = email_servers.get(ip_address, []) + [port_number]
            elif port_number in [5060, 1720]:
                if ip_address:
                    voip_servers[ip_address] = voip_servers.get(ip_address, []) + [port_number]
            elif port_number in [445, 2049]:
                if ip_address:
                    file_sharing_services[ip_address] = file_sharing_services.get(ip_address, []) + [port_number]
            elif port_number in [5985, 22]:
                if ip_address:
                    remote_administration_tools[ip_address] = remote_administration_tools.get(ip_address, []) + [port_number]
        
    # Return the categorized open ports for each host
    return {
        colored("Exploitable Services", "red"): exploitable_services,
        colored("Domain Controllers", "white"): domain_controllers,
        "Printers": printers,
        "Windows Hosts": windows_hosts,
        "Web Servers": web_servers,
        "Linux Hosts": linux_hosts,
        "Database Servers": database_servers,
        "VPN Servers": vpn_servers,
        "Remote Access Tools": remote_access_tools,
        "DNS Servers": dns_servers,
        colored("FTP Servers", "yellow"): ftp_servers,
        colored("Email Servers", "yellow"): email_servers,
        colored("VoIP Servers", "blue"): voip_servers,
        "File Sharing Services": file_sharing_services,
        "Remote Administration Tools": remote_administration_tools
    }

BANNER = '''
     _   _                         ____                          
 ___| \\ | |_ __ ___   __ _ _ __   |  _ \\ __ _ _ __ ___  ___ _ __ 
|_  /  \\| | '_ ` _ \\ / _` | '_ \\  | |_) / _` | '__/ __|/ _ \\ '__|
 / /| |\\  | | | | | | (_| | |_) | |  __/ (_| | |  \\__ \\  __/ |   
/___|_| \\_|_| |_| |_|\\__,_| .__/  |_|   \\__,_|_|  |___/\\___|_|   
                          |_| 

                        Created by @ZakHax
                            Version 1.0                              
'''

if __name__ == '__main__':
    print(BANNER)
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Parse nmap output and categorize open ports by common use cases.')
    parser.add_argument('nmap_file', help='Path to the nmap output file')
    parser.add_argument('-o', '--output', help='Output file name')
    args = parser.parse_args()

    # Read the nmap output file
    with open(args.nmap_file, 'r') as f:
        nmap_output = f.read()

    # Parse the nmap output and categorize the open ports
    results = parse_nmap_output(nmap_output)


    # Write the results to the output file
    if args.output:
        with open(args.output, 'w') as f:
            for category, hosts in results.items():
                f.write(f"{category}:\n")
                if not hosts:
                    f.write("\tNo hosts found.")
                else:
                    for host, ports in hosts.items():
                        f.write(f"\t{host}: {', '.join(str(port) for port in ports)}\n")
                f.write("\n")

    # Print the results to the console
    for category, hosts in results.items():
        if category == colored("Exploitable Services", "red"):
            print(colored(f"{category}:", "red"))
        elif category in (colored("Email Servers", "yellow"), colored("VoIP Servers", "blue"), colored("FTP Servers", "yellow")):
            print(colored(f"{category}:", "yellow"))
        elif category in colored("Domain Controllers", "white"):
            print(colored(f"{category}:", "white"))
        else:
            print(f"{category}:")
        if not hosts:
            print("\tNo hosts found.")
        else:
            for host, ports in hosts.items():
                print(f"\t{host}: {', '.join(str(port) for port in ports)}")
        print("")
