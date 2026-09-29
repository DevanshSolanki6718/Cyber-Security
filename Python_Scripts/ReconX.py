import sys, os
import whois
import subprocess
import argparse
import dns.resolver
import requests
import time
import socket
import json, re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import io
from contextlib import redirect_stdout

argparse = argparse.ArgumentParser(
    description="Basic Info Gathering Tool.",
    usage="python3 ReconX.py -d DOMAIN [-s IP]"
)

argparse.add_argument(
    "-d", "--domain",
    help="Enter the domain for footprinting.",
    required=True
)

args = argparse.parse_args()
domain = args.domain

class Tee:
    def __init__(self):
        self.terminal = sys.stdout
        self.file = io.StringIO()

    def write(self, text):
        self.terminal.write(text)

        if "[+] Getting" not in text:
            self.file.write(text)

    def flush(self):
        self.terminal.flush()

def recon():

    # ============================================================
    # WHOIS MODULE
    # ============================================================

    print("[+] Getting whois info...")
    time.sleep(2)
    print("[+] Getting dns info...")
    time.sleep(2)
    print("[+] Getting ip geo-location info...")
    time.sleep(2)

    try:

        # .IN domains
        if domain.endswith(".in"):

            result = subprocess.check_output(
                ["whois", "-h", "whois.nixiregistry.in", domain],
                text=True,
                timeout=10
            )

            # print(result)
            print("\n╔══════════════════════════════════════════════════════════════╗")
            print("║                         WHOIS DATA                           ║")
            print("╚══════════════════════════════════════════════════════════════╝\n")

            name_server = []
            for line in result.splitlines():

                if "domain name:" in line.lower():
                    print(f"{'Domain':<19}: {line.split(':', 1)[1].strip()}")

                elif "registrar:" in line.lower():
                    print(f"{'Registrar':<19}: {line.split(':', 1)[1].strip()}")

                elif "registrant name:" in line.lower():
                    print(f"{'Registrant':<19}: {line.split(':', 1)[1].strip()}")

                elif "registrant organization:" in line.lower():
                    print(f"{'Registrant Org':<19}: {line.split(':', 1)[1].strip()}")

                elif "registrant country:" in line.lower():
                    print(f"{'Registrant Country':<19}: {line.split(':', 1)[1].strip()}")

                elif "creation date:" in line.lower():
                    print(f"{'Creation Date':<19}: {line.split(':', 1)[1].strip()}")

                elif "updated date:" in line.lower():
                    print(f"{'Updated Date':<19}: {line.split(':', 1)[1].strip()}")

                elif "registry expiry date:" in line.lower():
                    print(f"{'Expiration Date':<19}: {line.split(':', 1)[1].strip()}")

                elif "name server:" in line.lower():
                    name_server.append(line.split(":", 1)[1].strip())

                elif "domain status:" in line.lower():
                    print(f"{'Status':<19}: {line.split(':', 1)[1].strip()}")

                elif "dnssec:" in line.lower():
                    print(f"{'DNSSEC':<19}: {line.split(':', 1)[1].strip()}")

            print(f"{'Name Server':<19}: {', '.join(name_server)}")

        # Other domains
        else:

            py = whois.query(domain)

            print("\n╔══════════════════════════════════════════════════════════════╗")
            print("║                         WHOIS DATA                           ║")
            print("╚══════════════════════════════════════════════════════════════╝\n")

            print(f"{'Domain':<19}: {domain}")
            print(f"{'Registrar':<19}: {py.registrar}")
            print(f"{'Registrant':<19}: {py.registrant}")
            print(f"{'Registrant Country':<19}: {py.registrant_country}")
            print(f"{'Status':<19}: {py.status}")

            print(f"{'Name Server':<19}: {py.name_servers}")

            print(f"{'DNSSEC':<19}: {py.dnssec}")
            print()

            print(f"{'Creation Date':<19}: {py.creation_date}")
            print(f"{'Updated Date':<19}: {py.last_updated}")
            print(f"{'Expiration Date':<19}: {py.expiration_date}")

    except subprocess.TimeoutExpired:
        print("[!] WHOIS request timed out.")

    except Exception as e:
        print("[!] WHOIS lookup failed:", e)

    # ============================================================
    # DNS MODULE
    # ============================================================

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                          DNS DATA                            ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    def get_dns(record):

        try:
            values = []

            for r in dns.resolver.resolve(domain, record):
                values.append(r.to_text())

            if record == "TXT":
                print(f"{'TXT Record':<19}: {values[0]}")

                for value in values[1:]:
                    print(f"{'':<19}  {value}")

            else:
                print(f"{record + ' Record':<19}: {', '.join(values)}")

        except Exception:
            print(f"{record + ' Record':<19}: Not Found")
    get_dns("A")
    get_dns("AAAA")
    get_dns("NS")
    get_dns("MX")
    get_dns("CNAME")
    get_dns("TXT")

    try:
        soa = dns.resolver.resolve(domain, "SOA")[0]

        print(f"{'SOA Record':<19}: Primary NS: {soa.mname}")
        print(f"{'':<19}  Responsible: {soa.rname}")
        print(f"{'':<19}  Serial: {soa.serial}")
        print(f"{'':<19}  Refresh: {soa.refresh}")
        print(f"{'':<19}  Retry: {soa.retry}")
        print(f"{'':<19}  Expire: {soa.expire}")
        print(f"{'':<19}  Minimum TTL: {soa.minimum}")

    except Exception:
        print(f"{'SOA Record':<19}: Not Found")

    get_dns("CAA")
    get_dns("SRV")

    # ============================================================
    # IP GEOLOCATION MODULE
    # ============================================================

    try:
        ip = socket.gethostbyname(domain)

        response = requests.get(
            "https://geolocation-db.com/json/" + ip
        ).json()

        print("\n╔══════════════════════════════════════════════════════════════╗")
        print("║                      IP GEOLOCATION                          ║")
        print("╚══════════════════════════════════════════════════════════════╝\n")

        print(f"{'IP Address':<19}: {ip}")
        print(f"{'Country':<19}: {response['country_name']}")
        print(f"{'State':<19}: {response['state']}")
        print(f"{'City':<19}: {response['city']}")
        print(f"{'Latitude':<19}: {response['latitude']}")
        print(f"{'Longitude':<19}: {response['longitude']}")

    except Exception:
        print(f"{'IP Geolocation':<19}: Not Found")

# ============================================================
# SAVE OUTPUT
# ============================================================

tee = Tee()

with redirect_stdout(tee):
    recon()

result = tee.file.getvalue()

save = input("\n[?] Do you want to save the results? (y/n): ")

if save.lower() == "y":

    path = input("[?] Enter save path: ")
    filename = input("[?] Enter file name: ")

    filepath = os.path.join(path, filename)

    with open(filepath, "w") as file:
        file.write(result)

    print(f"[+] Results saved to {filepath}")