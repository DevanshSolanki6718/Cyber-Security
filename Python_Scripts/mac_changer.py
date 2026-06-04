#!/usr/bin/env python3

import subprocess
import re

def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(
            ["ifconfig", interface]
        ).decode()

        mac_addr_search_result = re.search(
            r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",
            ifconfig_result
        )

        if mac_addr_search_result:
            return mac_addr_search_result.group(0)
        else:
            print("[-] Could not read MAC address")
            return None

    except subprocess.CalledProcessError:
        print("[-] Invalid interface")
        return None

    except Exception as e:
        print("[-] Error:", e)
        return None

print("\n========== MAC CHANGER ==========")
print("1. Check Current MAC")
print("2. Change MAC Address")
print("3. Exit")

choice = input("\nEnter your choice: ")

if choice == "1":

    interface = input("Enter interface name: ")

    current_mac = get_current_mac(interface)

    if current_mac:
        print("[+] Current MAC Address =", current_mac)

elif choice == "2":
    interface = input("Enter interface: ")
    new_mac = input("Enter new MAC Address: ")

    current_mac = get_current_mac(interface)

    if current_mac:
        print("[+] Current MAC =", current_mac)

        change_mac(interface, new_mac)

        current_mac = get_current_mac(interface)

        if current_mac == new_mac:
            print(
                "[+] MAC address was successfully changed to "
                + current_mac
            )
        else:
            print(
                "[-] Sorry! MAC address did not get changed."
            )

elif choice == "3":
    print("[+] Exiting program...")
else:
    print("[-] Invalid option. Please choose 1, 2, or 3.")