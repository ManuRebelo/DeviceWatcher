from scapy.all import *
import requests
import logging
import subprocess
import threading
import time
import json
from datetime import datetime
from utils import find_mac_in_data, load_KnownDevices_csv_to_dict
from database_manager import DatabaseManager

class WiFiMonitor:
    def __init__(self, db_manager):
        self.vendors = {}  # Cache for MAC address vendor lookup
        self.channel_hopper_thread = None
        self.stop_channel_hopping = threading.Event()
        self.db_manager = db_manager
        self.current_channel = 1
        self.knownDevices = load_KnownDevices_csv_to_dict()
        # Define Wi-Fi channels for 2.4GHz and 5GHz
        self.channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] + [
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140
        ]

        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger("WiFiMonitor")

    def start_sniffing(self, interface):
        """Start sniffing packets on the given interface with channel hopping."""
        try:
            self.logger.info(f"Starting packet sniffing on interface: {interface}")
            self.channel_hopper_thread = threading.Thread(target=self.channel_hopper, args=(interface,))
            self.channel_hopper_thread.start()
            sniff(iface=interface, prn=self.packet_handler, store=0)
        except Exception as e:
            self.logger.error(f"Error starting sniffing: {e}")
        finally:
            self.stop_channel_hopping.set()
            if self.channel_hopper_thread:
                self.channel_hopper_thread.join()

    def channel_hopper(self, interface):
        """Hops through Wi-Fi channels to sniff packets on all frequencies using nl80211."""
        self.logger.info("Starting channel hopping...")
        while not self.stop_channel_hopping.is_set():
            for channel in self.channels:
                try:
                    # Using `iw dev` to change channels via nl80211
                    subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.logger.debug(f"Switched to channel: {channel} using nl80211")
                    self.current_channel = channel
                    time.sleep(0.4)  # Delay to allow packet capture on the channel
                except Exception as e:
                    self.logger.warning(f"Failed to switch channel using nl80211: {e}")
                if self.stop_channel_hopping.is_set():
                    break

    def is_ap(self, packet):
        """Check if the packet is from an Access Point (AP)."""
        if not packet.haslayer(Dot11):
            return False
        # Beacon, Probe Response, Association Response
        if packet.type == 0 and packet.subtype in [8, 5, 1]:
            return True
        # Data frame: FromDS=0, ToDS=1 (AP to client), or FromDS=1, ToDS=0 (client to AP)
        if packet.type == 2:
            fc = packet[Dot11].FCfield
            to_ds = fc & 0x1
            from_ds = (fc & 0x2) >> 1
            # AP-to-AP (WDS): ToDS=1, FromDS=1
            if to_ds == 1 and from_ds == 1:
                return True
            # AP-to-client: FromDS=1, ToDS=0 (source is AP)
            if from_ds == 1 and to_ds == 0:
                return True
        return False

    def is_client(self, packet):
        """Check if the packet is from a client device."""
        if not packet.haslayer(Dot11):
            return False
        # Probe Request, Authentication, Association Request
        if packet.type == 0 and packet.subtype in [4, 11, 0]:
            return True
        # Data frame: FromDS=0, ToDS=1 (client to AP)
        if packet.type == 2:
            fc = packet[Dot11].FCfield
            to_ds = fc & 0x1
            from_ds = (fc & 0x2) >> 1
            # Client-to-AP: ToDS=1, FromDS=0 (source is client)
            if to_ds == 1 and from_ds == 0:
                return True
        return False

    def is_ap_to_ap(self, packet):
        """Detect AP-to-AP (WDS/extender) communication."""
        if not packet.haslayer(Dot11):
            return False
        if packet.type == 2:
            fc = packet[Dot11].FCfield
            to_ds = fc & 0x1
            from_ds = (fc & 0x2) >> 1
            # WDS: ToDS=1, FromDS=1
            if to_ds == 1 and from_ds == 1:
                return True
        return False

    def handle_reassociation_request(self, packet, mac_address, bssid):
        """Handle Reassociation Request frames (type 0, subtype 2)."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Reassociation request from client: {mac_address}, AP: {bssid}")
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        self.db_manager.insert_or_update_client(
            mac_address=mac_address, associated_ap=bssid, vendor=self.lookup_vendor(mac_address),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_reassociation_response(self, packet, mac_address, bssid):
        """Handle Reassociation Response frames (type 0, subtype 3)."""
        if not self.is_valid_mac(bssid):
            return
        self.logger.info(f"Reassociation response from AP: {mac_address}, Client: {bssid}")
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(bssid, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        self.db_manager.insert_or_update_client(
            mac_address=bssid, associated_ap=mac_address, vendor=self.lookup_vendor(bssid),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_disassociation(self, packet, mac_address, bssid):
        """Handle Disassociation frames (type 0, subtype 10)."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Disassociation: {mac_address} <-> {bssid}")
        # Mark client as disassociated in the database (could set associated_ap to None)
        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db_manager.update_client_disassociation(mac_address, bssid, last_seen)

    def handle_deauthentication(self, packet, mac_address, bssid):
        """Handle Deauthentication frames (type 0, subtype 12)."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Deauthentication: {mac_address} <-> {bssid}")
        # Mark client as deauthenticated in the database (could set associated_ap to None)
        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db_manager.update_client_deauthentication(mac_address, bssid, last_seen)

    def handle_action(self, packet, mac_address, bssid):
        """Handle Action frames (type 0, subtype 13)."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Action frame: {mac_address} <-> {bssid}")
        # Optionally update last seen for both AP and client
        last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db_manager.update_client_last_seen(mac_address, last_seen)
        if bssid:
            self.db_manager.update_ap_last_seen(bssid, last_seen)

    def handle_authentication_response(self, packet, mac_address, bssid):
        """Handle Authentication Response frames (type 0, subtype 11)."""
        if not self.is_valid_mac(bssid):
            return
        self.logger.info(f"Authentication response: {mac_address} <-> {bssid}")
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(bssid, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        self.db_manager.insert_or_update_client(
            mac_address=bssid, associated_ap=mac_address, vendor=self.lookup_vendor(bssid),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_association_response(self, packet, mac_address, bssid):
        """Handle Association Response frames (type 0, subtype 1)."""
        if not self.is_valid_mac(bssid):
            return
        self.logger.info(f"Association response: {mac_address} <-> {bssid}")
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(bssid, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        self.db_manager.insert_or_update_client(
            mac_address=bssid, associated_ap=mac_address, vendor=self.lookup_vendor(bssid),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_probe_response(self, packet, mac_address, bssid):
        """Handle Probe Response frames (type 0, subtype 5)."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Probe response: {mac_address} <-> {bssid}")
        ssid = packet.info.decode(errors="ignore").strip() if hasattr(packet, 'info') and packet.info else "Hidden SSID"
        channel = self.extract_channel(packet)
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        frequency = self.get_frequency(channel)
        security = self.parse_security(packet)
        ap_id = f"{mac_address}_{frequency}"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"

        self.db_manager.insert_or_update_ap(
            mac_address=ap_id, ssid=ssid, vendor=self.lookup_vendor(mac_address), 
            brand = brand, device_type = device_type, specific_models = specific_models,
            channel=channel, frequency=frequency, signal_strength=signal_strength, 
            security=security, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_ps_poll(self, packet, mac_address, bssid):
        """Handle PS-Poll frames (type 1, subtype 5)."""
        if not self.is_valid_mac(mac_address) or not self.is_valid_mac(bssid):
            return
        self.logger.info(f"PS-Poll frame: Client {mac_address} polling AP {bssid}")
        # Optionally update last seen for the client and AP
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        deviceInfo = find_mac_in_data(bssid, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        self.db_manager.insert_or_update_client(
            mac_address=bssid, associated_ap=mac_address, vendor=self.lookup_vendor(bssid),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

        # Only proceed if bssid is valid
        if self.is_valid_mac(bssid):
            ssid = packet.info.decode(errors="ignore").strip() if hasattr(packet, 'info') and packet.info else "Hidden SSID"
            channel = self.extract_channel(packet)
            frequency = self.get_frequency(channel)
            security = self.parse_security(packet)
            ap_id = f"{bssid}_{frequency}"
            self.db_manager.insert_or_update_ap(
                mac_address=ap_id, ssid=ssid, vendor=self.lookup_vendor(bssid), 
                brand = brand, device_type = device_type, specific_models = specific_models,
                channel=channel, frequency=frequency, signal_strength=signal_strength, 
                security=security, count=1, first_seen=first_seen, last_seen=last_seen
            )

    def handle_block_ack(self, packet, mac_address, bssid):
        """Handle Block Ack Request (BAR) and Block Ack (BA) frames."""
        if not self.is_valid_mac(mac_address) or not self.is_valid_mac(bssid):
            return

        frame_subtype = packet.subtype
        frame_type = "Block Ack Request" if frame_subtype == 8 or frame_subtype == 9 else "Block Ack"

        self.logger.info(f"{frame_type}: {mac_address} <-> {bssid}")

        # Optionally, extract relevant info from the Block Ack frame
        tid = packet.TID if hasattr(packet, 'TID') else "Unknown"  # Traffic Identifier
        start_seq = packet.start_seq if hasattr(packet, 'start_seq') else "Unknown"

        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"

        # Store or update info in your DB if needed
        self.db_manager.insert_or_update_client(
            mac_address=mac_address,
            associated_ap=bssid,
            vendor=self.lookup_vendor(mac_address),
            brand="Unknown",
            device_type="Unknown",
            specific_models="Unknown",
            signal_strength=signal_strength,
            count=1,
            first_seen=first_seen,
            last_seen=last_seen
        )

    def packet_handler(self, packet):
        """Process each packet to extract APs, Clients, and AP-to-AP links."""
        try:
            if not packet.haslayer(Dot11):
                return

            mac_address = packet[Dot11].addr2  # Source MAC
            bssid = packet[Dot11].addr3 if hasattr(packet[Dot11], 'addr3') else None  # BSSID

            # Validate MAC address
            if not self.is_valid_mac(mac_address):
                return

            # AP-to-AP (WDS/extender) detection
            if self.is_ap_to_ap(packet):
                src_ap = mac_address
                dst_ap = packet[Dot11].addr1  # Destination MAC
                self.logger.info(f"AP-to-AP (WDS) frame: {src_ap} <-> {dst_ap}")
                return

            # AP detection
            if self.is_ap(packet):
                self.handle_beacon(packet, mac_address)
                return

            # Client detection
            if self.is_client(packet):
                if packet.type == 0 and packet.subtype == 4:
                    self.handle_probe_request(packet, mac_address, bssid)
                elif packet.type == 0 and packet.subtype == 0:
                    self.handle_association(packet, mac_address, bssid)
                elif packet.type == 0 and packet.subtype == 11:
                    self.handle_authentication(packet, mac_address, bssid)
                elif packet.type == 2:
                    self.handle_client(packet, mac_address, bssid)
                return

            # Additional management frames (type 0 and 1)
            if packet.type == 0:
                if packet.subtype == 1:
                    self.handle_association_response(packet, mac_address, bssid)
                    return
                elif packet.subtype == 5:
                    self.handle_probe_response(packet, mac_address, bssid)
                    return
                elif packet.subtype == 2:
                    self.handle_reassociation_request(packet, mac_address, bssid)
                    return
                elif packet.subtype == 3:
                    self.handle_reassociation_response(packet, mac_address, bssid)
                    return
                elif packet.subtype == 10:
                    self.handle_disassociation(packet, mac_address, bssid)
                    return
                elif packet.subtype == 12:
                    self.handle_deauthentication(packet, mac_address, bssid)
                    return
                elif packet.subtype == 13:
                    self.handle_action(packet, mac_address, bssid)
                    return

            if packet.type == 1:
                if packet.subtype == 5:
                    self.handle_ps_poll(packet, mac_address, bssid)
                    return
                elif packet.subtype == 9:
                    self.handle_block_ack(packet, mac_address, bssid)
                    return
                elif packet.subtype == 11:
                    self.handle_authentication_response(packet, mac_address, bssid)
                    return

            # Unhandled frame types
            self.logger.warning(f"Unhandled frame type/subtype: {packet.type}/{packet.subtype}, MAC:{mac_address}, BSSID:{bssid}")

        except Exception as e:
            self.logger.warning(f"Error processing packet: {e}")

    def is_valid_mac(self, mac):
        """Validate the format of a MAC address and filter broadcast MAC."""
        if mac is None or not isinstance(mac, str):
            return False
        mac = mac.lower()
        if not mac or mac == "ff:ff:ff:ff:ff:ff":
            return False
        parts = mac.split(":")
        if len(parts) != 6:
            return False
        try:
            return all(0 <= int(byte, 16) <= 255 for byte in parts)
        except ValueError:
            return False
    
    def parse_security(self, packet):
        """Parse security protocols from the RSN or WEP fields in beacon frames."""
        security = []
        if packet.haslayer(Dot11Elt):
            raw_info = packet.getlayer(Dot11Elt)
            while raw_info:
                if raw_info.ID == 48:  # RSN Information Element
                    security.append("WPA2")
                elif raw_info.ID == 221 and raw_info.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA
                    security.append("WPA")
                elif raw_info.ID == 0:  # WEP
                    security.append("WEP")
                raw_info = raw_info.payload.getlayer(Dot11Elt)
        return ", ".join(security) if security else "Open/Unknown"
    
    def extract_channel(self, packet):
        channel = None  # Default to "Unknown" if we can't find it
        try:
            channel = ord(packet[Dot11Elt:3].info) if packet.haslayer(Dot11Elt) and packet[Dot11Elt:3].ID == 3 and len(packet[Dot11Elt:3].info) == 1 else self.current_channel
        except Exception as e:
            channel = self.current_channel
        return channel
    
    def handle_beacon(self, packet, mac_address):
        """Process beacon frames to extract AP information."""
        if not self.is_valid_mac(mac_address):
            return
        ssid = packet.info.decode(errors="ignore").strip() if hasattr(packet, 'info') and packet.info else "Hidden SSID"
        channel = self.extract_channel(packet)
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        frequency = self.get_frequency(channel)
        security = self.parse_security(packet)  # Extract security details

        # Unique AP ID (MAC + frequency)
        ap_id = f"{mac_address}_{frequency}"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen       
        
        #Check in device list
        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"

        # Log Beacon Frame Details
        self.logger.info(f"Beacon Frame Detected: AP {ssid} (BSSID: {mac_address}) with signal strength {signal_strength} dBm")

        # Insert or update the AP in the database
        self.db_manager.insert_or_update_ap(
            mac_address=ap_id, ssid=ssid, vendor=self.lookup_vendor(mac_address), 
            brand = brand, device_type = device_type, specific_models = specific_models,
            channel=channel, frequency=frequency, signal_strength=signal_strength, 
            security=security, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_probe_request(self, packet, mac_address, bssid):
        """Process probe request frames to extract client information."""
        if not self.is_valid_mac(mac_address):
            return
        if mac_address:
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            last_seen = first_seen

            #Check in device list
            deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
            if deviceInfo is not None:          
                brand = deviceInfo['Brand']
                device_type= deviceInfo['DeviceType']
                specific_models= deviceInfo['SpecificModels']  
            else:
                brand="Unknown"
                device_type="Unknown"
                specific_models="Unknown"

            # Log Probe Request Details
            self.logger.info(f"Probe Request from client: {mac_address} to AP: {bssid} (Signal: {signal_strength} dBm)")

            # Insert or update the client in the database
            self.db_manager.insert_or_update_client(
                mac_address=mac_address, associated_ap=bssid, vendor=self.lookup_vendor(mac_address),
                brand = brand, device_type = device_type, specific_models = specific_models,
                signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
            )

    def handle_client(self, packet, mac_address, bssid):
        """Process client frames to extract client information."""
        if not self.is_valid_mac(mac_address):
            return
        if mac_address:
            signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
            first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            last_seen = first_seen

            #Check in device list
            deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
            if deviceInfo is not None:          
                brand = deviceInfo['Brand']
                device_type= deviceInfo['DeviceType']
                specific_models= deviceInfo['SpecificModels']  
            else:
                brand="Unknown"
                device_type="Unknown"
                specific_models="Unknown"

            # Log Client Frame Details
            self.logger.info(f"Client Frame Detected: Client {mac_address} associated with AP {bssid} (Signal: {signal_strength} dBm)")

            # Check if the AP exists in the database (using MAC_freq as the unique ID)
            frequency = self.get_frequency(self.current_channel)
            ap_id = f"{bssid}_{frequency}"

            if not self.db_manager.ap_exists(ap_id):
                self.add_minimal_ap(bssid, frequency)

            # Insert or update the client in the database
            self.db_manager.insert_or_update_client(
                mac_address=mac_address, associated_ap=ap_id, vendor=self.lookup_vendor(mac_address),
                brand = brand, device_type = device_type, specific_models = specific_models,
                signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
            )

    def handle_association(self, packet, mac_address, bssid):
        """Handle Association Request frames."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Association request from client: {mac_address}, AP: {bssid}")

        # Insert or update client in the database
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        #Check in device list
        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"      

        # Insert client info
        self.db_manager.insert_or_update_client(
            mac_address=mac_address, associated_ap=bssid, vendor=self.lookup_vendor(mac_address),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def handle_authentication(self, packet, mac_address, bssid):
        """Handle Authentication frames."""
        if not self.is_valid_mac(mac_address):
            return
        self.logger.info(f"Authentication request from client: {mac_address}, AP: {bssid}")

        # Insert or update client in the database
        signal_strength = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        #Check in device list
        deviceInfo = find_mac_in_data(mac_address, self.knownDevices) 
        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type= deviceInfo['DeviceType']
            specific_models= deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"

        # Insert client info
        self.db_manager.insert_or_update_client(
            mac_address=mac_address, associated_ap=bssid, vendor=self.lookup_vendor(mac_address),
            brand = brand, device_type = device_type, specific_models = specific_models,
            signal_strength=signal_strength, count=1, first_seen=first_seen, last_seen=last_seen
        )

    def add_minimal_ap(self, bssid, frequency):
        """Add a minimal record for an AP detected through client association."""
        if not self.is_valid_mac(bssid):
            return
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        last_seen = first_seen

        ap_id = f"{bssid}_{frequency}"

        #Check in device list
        deviceInfo = find_mac_in_data(bssid, self.knownDevices)

        if deviceInfo is not None:          
            brand = deviceInfo['Brand']
            device_type = deviceInfo['DeviceType']
            specific_models = deviceInfo['SpecificModels']  
        else:
            brand="Unknown"
            device_type="Unknown"
            specific_models="Unknown"

        self.db_manager.insert_or_update_ap(
            mac_address=ap_id,
            ssid="Hidden or Undetected",
            vendor=self.lookup_vendor(bssid),
            brand = brand, 
            device_type = device_type, 
            specific_models = specific_models,
            channel=self.current_channel,
            frequency=frequency,
            signal_strength="Unknown",
            security="Unknown",
            count=0,
            first_seen=first_seen,
            last_seen=last_seen
        )

    def lookup_vendor(self, mac: str) -> str:
        """
        Lookup vendor for a MAC address using multiple vendor APIs.
        
        Args:
            vendors (dict): Cache of looked-up MAC vendors.
            mac (str): MAC address to look up.

        Returns:
            str: The vendor name or "Unknown"
        """
        mac = mac.upper().strip()
        if mac in self.vendors:
            return self.vendors[mac]

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
                        self.vendors[mac] = vendor
                        return vendor
            except Exception:
                continue  # Try the next source on error

        self.vendors[mac] = "Unknown"
        return "Unknown"

    def get_frequency(self, channel):
        """Get the frequency (in MHz) for a given channel."""
        frequency_2_4GHz = {
            1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437, 7: 2442,
            8: 2447, 9: 2452, 10: 2457, 11: 2462, 12: 2467, 13: 2472
        }
        frequency_5GHz = {
            36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280, 60: 5300,
            64: 5320, 100: 5500, 104: 5520, 108: 5540, 112: 5560, 116: 5580,
            120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680, 140: 5700
        }
        if channel in frequency_2_4GHz:
            return frequency_2_4GHz[channel]
        elif channel in frequency_5GHz:
            return frequency_5GHz[channel]
        else:
            if self.current_channel in frequency_2_4GHz:
                return frequency_2_4GHz[self.current_channel]
            elif channel in frequency_5GHz:
                return frequency_5GHz[self.current_channel]
            #self.logger.warning(f"Failed to get frequency for: {channel}")

