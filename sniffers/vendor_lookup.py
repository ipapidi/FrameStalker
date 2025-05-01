import os
import csv

OUI_DB = {}

def load_oui_database(file_path="data/oui.csv"):
    """
    Loads the new IEEE OUI CSV database into a dictionary.
    The CSV format has 'Assignment', 'Organization Name', etc.
    """
    if not os.path.exists(file_path):
        print(f"[!] OUI CSV file not found: {file_path}")
        return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prefix = row["Assignment"].upper().replace("-", "")
            vendor = row["Organization Name"].strip()
            if len(prefix) == 6:
                OUI_DB[prefix] = vendor

    print(f"[i] Loaded {len(OUI_DB)} MAC vendors from {file_path}")

def get_vendor(mac: str) -> str:
    """
    Returns the vendor name from a MAC address.
    """
    mac_clean = mac.upper().replace(":", "").replace("-", "")
    prefix = mac_clean[:6]
    return OUI_DB.get(prefix, "Unknown Vendor")

# Load at startup
load_oui_database()

