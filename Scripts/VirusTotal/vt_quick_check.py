# Import Modules
from dotenv import load_dotenv
import ipaddress
import re
import os
import sys
import vt 
import requests

# Declare variables
file_path = "C:/Projects/Scripts/VirusTotal/test.txt.txt"
ips = []
hashes = []
hash_types = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

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

# Establish API connection
load_dotenv()
api_key = os.getenv("API_KEY")
client = vt.Client(api_key)

# if len(sys.argv) < 2:
#     print("Error: Please provide a file path.")
#     sys.exit(1)

# Get filename
# file_path = sys.argv[1]

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
    print(ips)
    print("Run Ips against VT")

if hashes:
    print(hashes)
    print("Run Hashes against VT")



# TODO: 
# Loop through list and run against VT
# Output resutls into new file

# TODO Future:
# Run locally, drag and drop file in browser.
# Output returned in same browser.