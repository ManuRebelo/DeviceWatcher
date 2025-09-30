import requests
import csv

KNOWN_DEVICES = 'MAC_Address_Device_List.csv'

def load_KnownDevices_csv_to_dict(csv_file_path=KNOWN_DEVICES):
    """
    Load the CSV file into a list of dictionaries.

    Args:
        csv_file_path (str): Path to the CSV file to parse.

    Returns:
        list: A list of dictionaries, each representing a row in the CSV file.
    """
    data = []
    with open(csv_file_path, mode='r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            data.append({
                "MAC_Prefix": row['MAC_Prefix'],
                "Brand": row['Brand'],
                "DeviceType": row['DeviceType'],
                "SpecificModels": row['SpecificModels']
            })
    return data

def find_mac_in_data(mac_address, data):
    """
    Check if the MAC address exists in the provided data list.

    Args:
        mac_address (str): The MAC address to check.
        data (list): The list of dictionaries containing the CSV data.

    Returns:
        dict: The dictionary with the matching prefix details, or None if not found.
    """
    # Extract the MAC prefix (first 3 octets of the MAC address)
    mac_prefix = ":".join(mac_address.split(":")[:3]).upper()

    # Search for the matching MAC prefix
    for row in data:
        if row['MAC_Prefix'].upper() == mac_prefix:
            return row

    return None

def lookup_vendor(vendors: list, mac: str) -> str:
        """
        Lookup vendor for a MAC address using multiple vendor APIs.
        
        Args:
            vendors (dict): Cache of looked-up MAC vendors.
            mac (str): MAC address to look up.

        Returns:
            str: The vendor name or "Unknown"
        """
        mac = mac.upper().strip()
        if mac in vendors:
            return vendors[mac]

        sources = [
            f"https://api.macvendors.com/{mac}",
            f"https://www.macvendorlookup.com/api/v2/{mac}",       # Requires parsing JSON"
        ]

        headers = {}
        for url in sources:
            try:
                response = requests.get(url, timeout=5, headers=headers)
                if response.status_code == 200:
                    if "https://www.macvendorlookup.com/api/v2/" in url:
                        data = response.json()
                        if data and isinstance(data, list) and 'company' in data[0]:
                            vendor = data[0]['company']
                        else:
                            vendor = "Unknown"
                    else:  # macvendors.com returns plain text
                        vendor = response.text.strip()
                    if vendor and vendor != "Unknown":
                        vendors[mac] = vendor
                        return vendor
            except Exception:
                continue  # Try the next source on error

        vendors[mac] = "Unknown"
        return "Unknown"

