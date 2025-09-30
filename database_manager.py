import sqlite3
from datetime import datetime
import logging

class DatabaseManager:
    def __init__(self, db_file='device_watcher_data.db'):
        self.db_file = db_file
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.create_tables()
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger("DatabaseManager")

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS aps (
            mac_address TEXT PRIMARY KEY,
            ssid TEXT,
            vendor TEXT,
            brand TEXT,
            device_type TEXT,
            specific_models TEXT,
            channel TEXT,
            frequency TEXT,
            signal_strength TEXT,
            security TEXT,
            count INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
            mac_address TEXT PRIMARY KEY,
            associated_ap TEXT,
            vendor TEXT,
            brand TEXT,
            device_type TEXT,
            specific_models TEXT,
            signal_strength TEXT,
            count INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS bt_classic (
            mac_address TEXT PRIMARY KEY,
            name TEXT,
            vendor TEXT,
            brand TEXT,
            device_type TEXT,
            specific_models TEXT,           
            signal_strength INTEGER,
            first_seen TEXT,
            last_seen TEXT
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS ble_devices (
            mac_address TEXT PRIMARY KEY,
            vendor TEXT,
            brand TEXT,
            device_type TEXT,
            specific_models TEXT,
            signal_strength INTEGER,
            first_seen TEXT,
            last_seen TEXT
        )''')
        self.conn.commit()

    def _sanitize_ssid(self, ssid: str) -> str:
        """Sanitize SSID to prevent SQL injection and malformed data."""
        if ssid is None:
            return "Unknown"
        sanitized = ''.join(ch for ch in ssid if 32 <= ord(ch) <= 126)
        return sanitized[:32]

    def insert_or_update_ap(self, mac_address, ssid, vendor, brand, device_type, specific_models, channel, frequency, signal_strength, security, count, first_seen, last_seen):
        cursor = self.conn.cursor()
        ssid = self._sanitize_ssid(ssid)
        cursor.execute('''INSERT INTO aps (mac_address, ssid, vendor, brand, device_type, specific_models, channel, frequency, signal_strength, security, count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET
                    ssid=CASE
                            WHEN aps.ssid IN ('Hidden', 'Undetected') AND excluded.ssid != aps.ssid THEN excluded.ssid
                            ELSE aps.ssid
                         END,
                    channel=excluded.channel,
                    frequency=excluded.frequency,
                    signal_strength=excluded.signal_strength,
                    security=excluded.security,
                    count=aps.count + excluded.count,
                    last_seen=excluded.last_seen''',
                    (mac_address, ssid, vendor, brand, device_type, specific_models, channel, frequency, signal_strength, security, count, first_seen, last_seen))
        self.conn.commit()

    def insert_or_update_client(self, mac_address, associated_ap, vendor, brand, device_type, specific_models, signal_strength, count, first_seen, last_seen):
                
        if self.ap_exists(mac_address) and self.ap_exists(associated_ap):
            self.delete_client(mac_address)
            return       
        cursor = self.conn.cursor()
        cursor.execute('''INSERT INTO clients (mac_address, associated_ap, vendor, brand, device_type, specific_models, signal_strength, count, first_seen, last_seen)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(mac_address) DO UPDATE SET
                          associated_ap=CASE
                                      WHEN excluded.associated_ap != 'ff:ff:ff:ff:ff:ff' AND excluded.associated_ap != clients.associated_ap THEN excluded.associated_ap
                                      ELSE clients.associated_ap
                                    END,
                          vendor=excluded.vendor,
                          signal_strength=excluded.signal_strength,
                          count=clients.count + excluded.count,
                          last_seen=excluded.last_seen''',
                       (mac_address, associated_ap, vendor, brand, device_type, specific_models, signal_strength, count, first_seen, last_seen))
        self.conn.commit()

    def insert_or_update_bt_classic(self, mac_address, name, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen):
        cursor = self.conn.cursor()
        cursor.execute('''INSERT INTO bt_classic (mac_address, name, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(mac_address) DO UPDATE SET
                          name=excluded.name,
                          signal_strength=excluded.signal_strength,
                          last_seen=excluded.last_seen''',
                       (mac_address, name, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen))
        self.conn.commit()

    def insert_or_update_ble(self, mac_address, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen):
        cursor = self.conn.cursor()
        cursor.execute('''INSERT INTO ble_devices (mac_address, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(mac_address) DO UPDATE SET
                          signal_strength=excluded.signal_strength,
                          last_seen=excluded.last_seen''',
                       (mac_address, vendor, brand, device_type, specific_models, signal_strength, first_seen, last_seen))
        self.conn.commit()

    def fetch_all_bt_classic(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM bt_classic')
        return cursor.fetchall()

    def fetch_all_ble_devices(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM ble_devices')
        return cursor.fetchall()

    def fetch_bt_classic_by_mac(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM bt_classic WHERE mac_address = ?', (mac_address,))
        return cursor.fetchone()

    def fetch_ble_device_by_mac(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM ble_devices WHERE mac_address = ?', (mac_address,))
        return cursor.fetchone()

    def delete_bt_classic(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM bt_classic WHERE mac_address = ?', (mac_address,))
        self.conn.commit()

    def delete_ble_device(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM ble_devices WHERE mac_address = ?', (mac_address,))
        self.conn.commit()

    def fetch_all_aps(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM aps')
        return cursor.fetchall()

    def fetch_all_clients(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM clients')
        return cursor.fetchall()

    def fetch_ap_by_id(self, ap_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM aps WHERE mac_address = ?', (ap_id,))
        return cursor.fetchone()

    def fetch_client_by_mac(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE mac_address = ?', (mac_address,))
        return cursor.fetchone()

    def delete_ap(self, ap_id):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM aps WHERE mac_address = ?', (ap_id,))
        self.conn.commit()

    def delete_client(self, mac_address):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM clients WHERE mac_address = ?', (mac_address,))
        self.conn.commit()

    def ap_exists(self, ap_id):
        """Check if an AP with a MAC address starting with the given prefix exists in the database."""
        cursor = self.conn.cursor()
        mac_address = ap_id.split('_')[0]
        cursor.execute('SELECT COUNT(1) FROM aps WHERE mac_address LIKE ?', (mac_address + '%',))
        result = cursor.fetchone()
        return result[0] > 0 if result else False

    
    def update_last_seen(self, table_name, identifier, timestamp):
        """Update the last_seen column for a given record."""
        cursor = self.conn.cursor()
        if table_name == 'aps':
            cursor.execute('UPDATE aps SET last_seen = ? WHERE mac_address = ?', (timestamp, identifier))
        elif table_name == 'clients':
            cursor.execute('UPDATE clients SET last_seen = ? WHERE mac_address = ?', (timestamp, identifier))
        self.conn.commit()

    def close(self):
        self.conn.close()
