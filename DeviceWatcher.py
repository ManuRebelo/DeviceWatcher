import argparse
from flask import Flask, render_template, jsonify
from wifi_monitor import WiFiMonitor
from bluetooth_classic_monitor import BluetoothClassicMonitor
from ble_monitor import BLEMonitor
from threading import Thread
from database_manager import DatabaseManager

# Create Flask app
app = Flask(__name__)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Monitoring Interfaces')
parser.add_argument('--wifi', type=str, help='Wi-Fi interface to use (e.g., wlan1mon)')
parser.add_argument('--bt', type=int, help='Bluetooth Classic interface index (e.g., 2)')
parser.add_argument('--ble', type=int, help='BLE interface index (e.g., 0)')
args = parser.parse_args()

# Initialize database manager
db_manager = DatabaseManager()
# Initialize monitors conditionally
wifi_monitor = WiFiMonitor(db_manager) if args.wifi else None
bluetooth_monitor = BluetoothClassicMonitor(args.bt, db_manager) if args.bt is not None else None
ble_monitor = BLEMonitor(args.ble, db_manager) if args.ble is not None else None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/future')
def future():
    return render_template('future.html')

@app.route('/data')
def data():
    aps = wifi_monitor.db_manager.fetch_all_aps() if wifi_monitor else []
    clients = wifi_monitor.db_manager.fetch_all_clients() if wifi_monitor else []
    bluetoothDevs = bluetooth_monitor.db_manager.fetch_all_bt_classic() if bluetooth_monitor else []
    bleDevs = ble_monitor.db_manager.fetch_all_ble_devices() if ble_monitor else []

    return jsonify({
        'aps': [dict(zip(['mac_address', 'ssid', 'vendor', 'brand', 'device_type', 'specific_models', 'channel', 'frequency', 'signal_strength', 'security', 'count', 'first_seen', 'last_seen'], ap)) for ap in aps],
        'clients': [dict(zip(['mac_address', 'associated_ap', 'vendor', 'brand', 'device_type', 'specific_models', 'signal_strength', 'count', 'first_seen', 'last_seen'], client)) for client in clients],
        'bluetooths': [dict(zip(['mac_address', 'name', 'vendor', 'brand', 'device_type', 'specific_models', 'signal_strength', 'first_seen', 'last_seen'], bluetoothDev)) for bluetoothDev in bluetoothDevs],
        'bles': [dict(zip(['mac_address', 'vendor', 'brand', 'device_type', 'specific_models', 'signal_strength', 'first_seen', 'last_seen'], bleDev)) for bleDev in bleDevs]
    })

def start_sniffing_wifi():
    if wifi_monitor:
        wifi_monitor.start_sniffing(args.wifi)

def start_sniffing_bt():
    if bluetooth_monitor:
        bluetooth_monitor.start_scan()

def start_sniffing_ble():
    if ble_monitor:
        ble_monitor.start_scan()

if __name__ == "__main__":
    # Start selected monitors in separate threads
    if wifi_monitor:
        Thread(target=start_sniffing_wifi, daemon=True).start()
    if bluetooth_monitor:
        Thread(target=start_sniffing_bt, daemon=True).start()
    if ble_monitor:
        Thread(target=start_sniffing_ble, daemon=True).start()

    # Start the Flask web server
    app.run(host='0.0.0.0', port=5000, debug=False)
