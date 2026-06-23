# Initialize Variables
from dotenv import load_dotenv
import os
import sys
import vt 

load_dotenv()
api_key = os.getenv("API_KEY")
client = vt.Client(api_key)

# Input IPs/Hashes

if len(sys.argv) < 2:
    print("Error: Please provide a file path.")
    sys.exit(1)

# Get filename
file_path = sys.argv[1]
values = []

# Read File
try:
    with open(file_path, 'r') as file:
        for line in file:
            row = line.strip().split(",")
            values.append(row)
except FileNotFoundError:
    print(f"Error: The file '{file_path}' was not found.")

# Write out results to CSV file

print(values)