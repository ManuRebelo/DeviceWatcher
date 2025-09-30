import logging
import time
from datetime import datetime
from bluepy import btle
from utils import lookup_vendor, find_mac_in_data, load_KnownDevices_csv_to_dict

class BLEMonitor: 
    def __init__(self, interface, db_manager):
        self.vendors = {} 
        self.db_manager = db_manager
        self.knownDevices = load_KnownDevices_csv_to_dict()
        self.interface = interface
        self.scanning = False
        self.logger = logging.getLogger("BLEMonitor")
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def start_scan(self, duration=30):
        """Scans for BLE devices."""
        self.scanning = True        
        try:
            self.logger.info("Starting BLE scan...")
            self.scanner = btle.Scanner(self.interface)
            while self.scanning:
                devices = self.scanner.scan(timeout=duration,passive=True)
                for dev in devices:
                    self.handle_device(dev)
                time.sleep(duration)
        except Exception as e:
            self.logger.error(f"Error during BLE scan: {e}")

    def stop_scan(self):
        """Stops BLE scanning."""
        self.scanning = False
        self.logger.info("Stopping BLE scan.")

    def handle_device(self, dev):
        """Handles discovered BLE devices."""
        mac_address = dev.addr
        vendor =  lookup_vendor(self.vendors, mac_address)
        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"    

        signal_strength = dev.rssi
        iface = dev.iface
        addrType = dev.addrType
        connectable = dev.connectable
        rawData = dev.rawData
        scanData = dev.scanData
        updateCount = dev.updateCount
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen
        self.db_manager.insert_or_update_ble(mac_address, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen)   