#!/usr/bin/env python3

"""
NetScanPro v1.0

Author: Devansh Solanki

Features:
- ARP Network Discovery
- MAC Vendor Identification
- Auto Network Detection
- CSV / JSON / HTML Reporting
- Vendor Cache
- Fast / Detailed Scan Modes
"""

# ==================================================
# Imports
# ==================================================

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as scapy
import socket
import csv
import json
import time
import netifaces

import os

CACHE_FILE = "vendor_cache.json"

if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as file:
        vendor_cache = json.load(file)
else:
    vendor_cache = {}

from colorama import Fore, init
from mac_vendor_lookup import MacLookup

init(autoreset=True)
mac_lookup = MacLookup()

# ==================================================
# Utility Function
# ==================================================

def get_network(interface):
    iface = netifaces.ifaddresses(interface)

    ip = iface[netifaces.AF_INET][0]["addr"]

    octets = ip.split(".")

    network = (
        f"{octets[0]}."
        f"{octets[1]}."
        f"{octets[2]}."
        f"0/24"
    )

    return network

def select_interface():
    interfaces = scapy.get_if_list()

    print(Fore.CYAN + "\nAvailable Interfaces:")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i}. {iface}")

    while True:
        try:
            choice = int(input("\nSelect Interface: "))
            return interfaces[choice - 1]
        except:
            print(Fore.RED + "Invalid Selection.")

# ==================================================
# Vendor Cache
# ==================================================

def get_vendor(mac):
    prefix = mac[:8].lower()

    if prefix in vendor_cache:
        return vendor_cache[prefix]

    try:
        vendor = mac_lookup.lookup(mac)


    except Exception:
        vendor = "Unknown"

    vendor_cache[prefix] = vendor

    return vendor

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


# ==================================================
# Scanning Function
# ==================================================

def scan(ip, interface, detailed_mode=False):
    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    arp_request_broadcast = (
            broadcast / arp_request
    )

    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=1,
        iface=interface,
        verbose=False
    )[0]

    clients_list = []

    for element in answered_list:

        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc

        hostname = "Disabled"

        if detailed_mode:
            hostname = get_hostname(ip_addr)

        vendor = get_vendor(mac_addr)

        client_dict = {
            "ip": ip_addr,
            "mac": mac_addr,
            "vendor": vendor,
            "hostname": hostname
        }

        clients_list.append(client_dict)

    print("[DEBUG] Scan Finished")

    return clients_list


def print_result(results_list):
    print(
        Fore.GREEN +
        "\n{:<5} {:<18} {:<20} {:<25} {:<25}".format(
            "No.",
            "IP Address",
            "MAC Address",
            "Vendor",
            "Hostname"
        )
    )

    print("-" * 100)

    for index, client in enumerate(
            results_list,
            start=1):
        print(
            "{:<5} {:<18} {:<20} {:<25} {:<25}".format(
                index,
                client["ip"],
                client["mac"],
                client["vendor"][:24],
                client["hostname"]
            )
        )

# ==================================================
# Export Functions
# ==================================================

def save_csv(results):
    filename = input(
        "\nEnter CSV filename (without .csv): "
    )

    with open(
            filename + ".csv",
            "w",
            newline=""
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "ip",
                "mac",
                "vendor",
                "hostname"
            ]
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    print(
        Fore.GREEN +
        f"[+] Saved to {filename}.csv"
    )


def save_json(results):
    filename = input(
        "\nEnter JSON filename (without .json): "
    )

    with open(
            filename + ".json",
            "w"
    ) as jsonfile:
        json.dump(
            results,
            jsonfile,
            indent=4
        )

    print(
        Fore.GREEN +
        f"[+] Saved to {filename}.json"
    )


def save_html(results):
    filename = input(
        "\nEnter HTML filename (without .html): "
    )

    html_content = f"""
    <html>
    <head>
        <title>NetScan Report</title>

        <style>

        body {{
            font-family: Arial;
            margin: 30px;
        }}

        h1 {{
            color: #333;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
        }}

        th, td {{
            border: 1px solid black;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background-color: #f2f2f2;
        }}

        </style>

    </head>

    <body>

    <h1>NetScan Report</h1>

    <table>

    <tr>
        <th>IP Address</th>
        <th>MAC Address</th>
        <th>Vendor</th>
        <th>Hostname</th>
    </tr>
    """

    for host in results:
        html_content += f"""
        <tr>
            <td>{host['ip']}</td>
            <td>{host['mac']}</td>
            <td>{host['vendor']}</td>
            <td>{host['hostname']}</td>
        </tr>
        """

    html_content += """
    </table>

    </body>
    </html>
    """

    with open(
            filename + ".html",
            "w"
    ) as html_file:
        html_file.write(html_content)

    print(
        Fore.GREEN +
        f"[+] Saved to {filename}.html"
    )

# ==================================================
# Main Program
# ==================================================

def main():
    target = input(
        "Enter Target IP / IP Range (Leave Blank For Auto Detection): "
    )

    interface = select_interface()

    if target == "":
        target = get_network(interface)

        print(
            f"\n[+] Auto Detected Network: {target}"
        )

    detailed_mode = input(
        "\nEnable Detailed Mode (Hostname Lookup)? (y/n): "
    ).lower() == "y"

    start_time = time.time()

    print(f"\nDEBUG Target: {target}")
    print(f"DEBUG Interface: {interface}")

    scan_result = scan(
        target,
        interface,
        detailed_mode
    )

    end_time = time.time()

    print_result(scan_result)

    print(
        Fore.CYAN +
        "\n" +
        "-" * 100
    )

    print(
        Fore.YELLOW +
        f"Hosts Found : {len(scan_result)}"
    )

    print(
        Fore.YELLOW +
        f"Scan Time   : "
        f"{round(end_time - start_time, 2)} sec"
    )

    print(
        Fore.YELLOW +
        f"Interface   : {interface}"
    )

    print(
        "\nExport Results?"
        "\n1. CSV"
        "\n2. JSON"
        "\n3. HTML"
        "\n4. CSV + JSON"
        "\n5. All"
        "\n6. Skip"
    )

    choice = input(
        "\nChoice: "
    )

    if choice == "1":

        save_csv(scan_result)

    elif choice == "2":

        save_json(scan_result)

    elif choice == "3":

        save_html(scan_result)

    elif choice == "4":

        save_csv(scan_result)
        save_json(scan_result)

    elif choice == "5":

        save_csv(scan_result)
        save_json(scan_result)
        save_html(scan_result)

    print(
        Fore.GREEN +
        "\n[+] Scan Completed"
    )


if __name__ == "__main__":
    main()