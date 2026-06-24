# Import Modules
from dotenv import load_dotenv
import ipaddress
import re
import os
import sys
import vt 
import requests

# Establish API connection
load_dotenv()
api_key = os.getenv("API_KEY")
client = vt.Client(api_key)

# Declare variables
ips = []
hashes = []
ip_results = []
hash_results = []
hash_types = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
session = requests.Session()
session.headers.update({"accept": "application/json", "x-apikey": api_key})

# Determines if input is an IP or a Hash
def data_classify(v):
    try:
        ipaddress.ip_address(v)
        return "IP"
    except ValueError:
        pass

    for hash_type, pattern in hash_types.items():
        if pattern.match(v):
            return hash_type
        

def parse_vt_json(resp):
    data = resp.json()
    attrs = data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})

    detections = [
        vendor
        for vendor, result in attrs.get("last_analysis_results", {}).items()
        if result.get("category") == "malicious"
    ]

    return {
        "id": data["data"]["id"],
        "country": attrs.get("country"),
        "asn": attrs.get("asn"),
        "owner": attrs.get("as_owner"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "detections": detections
    }

# Get filename
if len(sys.argv) < 2:
    print("Error: Please provide a file path.")
    sys.exit(1)

file_path = sys.argv[1]

# Read File
try:
    with open(file_path, 'r') as file:
        for line in file:
            row = line.strip()
            result = data_classify(row)
            if result == "IP":
                ips.append(row)
            elif result in {"MD5", "SHA1", "SHA256"}:
                hashes.append(row)
except FileNotFoundError:
    print(f"Error: The file '{file_path}' was not found.")

# Write out results to CSV file

if ips:
    for ip in ips:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = session.get(url)
        
        if response.status_code == 200:
            ip_results.append(parse_vt_json(response))
        else:
            print(f"Failed lookup for {ip}")

    for r in ip_results:
        print(
            f"IP: {r['id']} | "
            f"Country: {r['country']} | "
            f"Malicious Count: {r['malicious']} | "
            f"Suspicious Count: {r['suspicious']} | "
        )

if hashes:
    for h in hashes:
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        response = session.get(url)

        if response.status_code == 200:
            hash_results.append(parse_vt_json(response))
        else:
            print(f"Failed lookup for {h}")

    for r in hash_results:
        print(
            f"Hash: {r['id']} | "
            f"Malicious Count: {r['malicious']} | "
            f"Suspicious Count: {r['suspicious']} | "
        )

# TODO: 
# Output resutls into new file

# TODO Future:
# Run locally, drag and drop file in browser.
# Output returned in same browser.