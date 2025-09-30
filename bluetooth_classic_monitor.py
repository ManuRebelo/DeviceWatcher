import bluetooth
import logging
import time
from datetime import datetime
from utils import lookup_vendor, find_mac_in_data, load_KnownDevices_csv_to_dict

class BluetoothClassicMonitor:
    def __init__(self, interface, db_manager):
        self.vendors = {} 
        self.db_manager = db_manager
        self.knownDevices = load_KnownDevices_csv_to_dict()
        self.scanning = False
        self.interface = interface
        self.logger = logging.getLogger("BluetoothClassicMonitor")
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def start_scan(self, duration=30):
        """Scans for Bluetooth Classic devices for a given duration."""
        self.scanning = True
        self.logger.info("Starting Bluetooth Classic scan...")   
        try:
            while self.scanning:
                devices = bluetooth.discover_devices(device_id=self.interface, duration=duration, lookup_names=True)
                for addr, name in devices:
                    signal_strength=-50
                    self.handle_device(addr, name, signal_strength)
                time.sleep(duration)
        except Exception as e:
            self.logger.error(f"Error during Bluetooth Classic scan: {e}")
        
    def stop_scan(self):
        """Stops scanning for Bluetooth Classic devices."""
        self.scanning = False
        self.logger.info("Stopping Bluetooth Classic scan.")

    def handle_device(self, mac_address, name, signal_strength):
        """Handles discovered Bluetooth Classic devices."""
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen
        vendor =  lookup_vendor(self.vendors, mac_address)
        deviceInfo = find_mac_in_data(mac_address, self.knownDevices)
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type = deviceInfo['DeviceType']
            specific_models = deviceInfo['SpecificModels']  
        else:
            brand ="Unknown"
            device_type = "Unknown"
            specific_models ="Unknown"
        self.db_manager.insert_or_update_bt_classic(mac_address, name, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen)
        self.logger.info(f"Discovered Bluetooth Classic device: {name} ({mac_address}) Vendor:{vendor} Brand:{brand}, Device Type:{device_type}, Specific Models:{specific_models}, RSSI:{signal_strength}")