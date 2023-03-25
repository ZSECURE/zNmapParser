#!/usr/bin/python3
import sys
import xml.etree.ElementTree as ET
import csv

def main(input_file, output_file):
    tree = ET.parse(input_file)
    root = tree.getroot()

    header = [
        "IP",
        "Hostname",
        "Port",
        "Protocol",
        "Service",
        "Service Version",
        "OS",
        "OS Version",
    ]
    rows = []

    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        hostname = host.find("hostnames/hostname").get("name") if host.find("hostnames/hostname") is not None else ""
        os = host.find("os/osmatch").get("name") if host.find("os/osmatch") is not None else ""
        os_version = host.find("os/osmatch").get("accuracy") if host.find("os/osmatch") is not None else ""

        for port in host.findall("ports/port"):
            protocol = port.get("protocol")
            port_number = port.get("portid")
            service = port.find("service").get("name") if port.find("service") is not None else ""
            service_version = port.find("service").get("product") if port.find("service") is not None else ""

            row = [
                ip,
                hostname,
                port_number,
                protocol,
                service,
                service_version,
                os,
                os_version,
            ]
            rows.append(row)

    with open(output_file, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(header)
        csvwriter.writerows(rows)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 Nmap2csv.py <input_file.xml> <output_file.csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    main(input_file, output_file)
