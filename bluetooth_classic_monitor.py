"""
@file bluetooth_classic_monitor.py
@brief Bluetooth Classic device discovery monitor for DeviceWatcher.

Uses ``hcitool inq`` for device inquiry and ``hcitool info`` for per-device
name, Class-of-Device, LMP version, and HCI manufacturer lookups.

@license MIT — see LICENSE for details.
"""

import logging
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from utils import VendorResolver, get_device_info

_MAJOR_CLASS: dict[int, str] = {
    1: 'Computer', 2: 'Phone', 3: 'Network', 4: 'Audio/Video',
    5: 'Peripheral', 6: 'Imaging', 7: 'Wearable', 8: 'Toy', 9: 'Health',
}

_MINOR_CLASS: dict[tuple[int, int], str] = {
    # Computer (1)
    (1, 1): 'Desktop', (1, 2): 'Server', (1, 3): 'Laptop',
    (1, 4): 'Handheld', (1, 5): 'Palm-size', (1, 6): 'Wearable Computer',
    # Phone (2)
    (2, 1): 'Cellular', (2, 2): 'Cordless', (2, 3): 'Smartphone',
    (2, 4): 'Wired Modem', (2, 5): 'ISDN',
    # Audio/Video (4)
    (4, 1): 'Headset', (4, 2): 'Hands-free', (4, 4): 'Microphone',
    (4, 5): 'Loudspeaker', (4, 6): 'Headphones', (4, 7): 'Portable Audio',
    (4, 8): 'Car Audio', (4, 9): 'Set-top Box', (4, 10): 'HiFi Audio',
    (4, 11): 'VCR', (4, 12): 'Video Camera', (4, 14): 'Video Monitor',
    (4, 16): 'Video Conferencing',
    # Peripheral (5)
    (5, 16): 'Keyboard', (5, 32): 'Pointing Device', (5, 48): 'Combo Input',
    # Wearable (7)
    (7, 1): 'Wristwatch', (7, 2): 'Pager', (7, 3): 'Jacket',
    (7, 4): 'Helmet', (7, 5): 'Glasses',
    # Health (9)
    (9, 1): 'Blood Pressure Monitor', (9, 2): 'Thermometer',
    (9, 3): 'Weighing Scale', (9, 4): 'Glucose Meter',
    (9, 5): 'Pulse Oximeter', (9, 6): 'Heart Rate Monitor',
    (9, 7): 'Medical Data Display',
}

_SERVICE_CLASS_BITS: dict[int, str] = {
    13: 'Positioning', 14: 'Networking', 15: 'Rendering',
    16: 'Capturing', 17: 'Object Transfer', 18: 'Audio',
    19: 'Telephony', 20: 'Information',
}

_LMP_RE = re.compile(r'(\d+\.\d+)\s+\(0x', re.IGNORECASE)


def _parse_bt_class(cod_str: str) -> tuple[str, str, str]:
    """Decode a Bluetooth Class-of-Device hex string.

    @param cod_str  Hex string representation of the CoD value (e.g. ``"0x240404"``).
    @return         ``(device_type, minor_label, service_classes_csv)`` triple.
                    Falls back to ``('Unknown', '', '')`` on parse errors.
    """
    try:
        cod         = int(cod_str, 16)
        major       = (cod >> 8) & 0x1F
        minor       = (cod >> 2) & 0x3F
        major_label = _MAJOR_CLASS.get(major, 'Unknown')
        minor_label = _MINOR_CLASS.get((major, minor), '')
        services    = [label for bit, label in _SERVICE_CLASS_BITS.items() if (cod >> bit) & 1]
        device_type = minor_label if minor_label else major_label
        return device_type, minor_label, ', '.join(services)
    except (ValueError, TypeError):
        return 'Unknown', '', ''


class BluetoothClassicMonitor:
    """Continuously scan for Bluetooth Classic devices using ``hcitool``.

    Discovery loop:
    1. ``hcitool inq`` — discover device BD_ADDRs.
    2. ``hcitool info`` (parallel) — resolve name, CoD, LMP version, manufacturer.
    3. Persist each device via :class:`DatabaseManager`.

    @param interface       HCI adapter index (e.g. ``0`` for ``hci0``).
    @param db_manager      Shared :class:`DatabaseManager` instance.
    @param vendor_resolver Shared :class:`VendorResolver` instance.
    @param known_devices   Dict returned by :func:`~utils.load_known_devices`.
    """

    def __init__(self, interface: int, db_manager, vendor_resolver: VendorResolver,
                 known_devices: dict):
        self.interface        = interface
        self.db_manager       = db_manager
        self.vendor_resolver  = vendor_resolver
        self.known_devices    = known_devices
        self.scanning         = False
        self._proc            = None
        self._proc_lock       = threading.Lock()
        self._error_count     = 0
        self._event_listeners: set = set()
        self.logger           = logging.getLogger("BluetoothClassicMonitor")

    # ------------------------------------------------------------------ public

    def start_scan(self, duration: int = 10) -> None:
        """Enter the discovery loop.  Blocks until :meth:`stop_scan` is called.

        @param duration  Inquiry duration hint in seconds (converted to HCI
                         inquiry length units: ``max(1, round(duration / 1.28))``).
        """
        self.scanning     = True
        self._error_count = 0
        self.logger.info("Starting Bluetooth Classic scan…")
        while self.scanning:
            macs = self._inquire(duration)
            if macs and self.scanning:
                info_map = self._resolve_info(macs)
                for mac in macs:
                    if not self.scanning:
                        break
                    name, cod, bt_version, hci_mfr = info_map.get(mac, ('Unknown', None, None, None))
                    self._handle_device(mac, name, cod, bt_version, hci_mfr)
            if self.scanning:
                time.sleep(2)

    def stop_scan(self) -> None:
        """Signal the discovery loop to stop and terminate any active inquiry process."""
        self.scanning = False
        with self._proc_lock:
            proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        self.logger.info("Bluetooth Classic scan stopped.")

    def register_event_listener(self, q) -> None:
        """Register a queue to receive live discovery event dicts.

        @param q  A ``queue.Queue`` instance.
        """
        self._event_listeners.add(q)

    def unregister_event_listener(self, q) -> None:
        """Deregister a previously registered event listener.

        @param q  The queue instance to remove.
        """
        self._event_listeners.discard(q)

    # ------------------------------------------------------------------ internals

    def _inquire(self, duration: int) -> list[str]:
        """Run ``hcitool inq`` and return a list of discovered BD_ADDRs.

        @param duration  Requested inquiry duration in seconds.
        @return          List of lowercase colon-separated BD_ADDR strings.
                         Returns an empty list on error.
        @throws SystemExit  (via ``self.scanning = False``) when ``hcitool``
                             is not installed.
        """
        try:
            length = max(1, round(duration / 1.28))
            proc = subprocess.Popen(
                ['hcitool', f'--device=hci{self.interface}', 'inq',
                 f'--length={length}', '--flush'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            with self._proc_lock:
                self._proc = proc
            try:
                stdout, _ = proc.communicate(timeout=duration + 15)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
            with self._proc_lock:
                self._proc = None
            self._error_count = 0

            macs: list[str] = []
            for line in stdout.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                candidate = parts[0]
                if len(candidate) == 17 and candidate.count(':') == 5:
                    macs.append(candidate.lower())
            return macs

        except FileNotFoundError:
            self.logger.error(
                "hcitool not found — install the 'bluez' package: sudo apt install bluez"
            )
            self.scanning = False
            return []
        except Exception as exc:
            self._error_count += 1
            backoff = min(60, 5 * self._error_count)
            self.logger.error(
                "Bluetooth Classic inquiry error: %s (retry in %ds)", exc, backoff
            )
            time.sleep(backoff)
            return []

    def _get_info(self, mac: str) -> tuple[str, str | None, str | None, str | None]:
        """Query a single device for name, CoD, Bluetooth version, and HCI manufacturer.

        Runs ``hcitool info <mac>`` and parses its stdout.

        @param mac  BD_ADDR of the device to query.
        @return     ``(name, cod, bt_version, hci_manufacturer)`` tuple.
                    Fields that cannot be parsed are ``None``; name defaults to
                    ``"Unknown"``.
        """
        try:
            result = subprocess.run(
                ['hcitool', f'--device=hci{self.interface}', 'info', mac],
                capture_output=True, text=True, timeout=10,
            )
            name       = 'Unknown'
            cod        = None
            bt_version = None
            hci_mfr    = None
            for line in result.stdout.splitlines():
                s = line.strip()
                if s.startswith('Device Name:'):
                    n = s.split(':', 1)[1].strip()
                    if n:
                        name = n
                elif s.startswith('Class:'):
                    c = s.split(':', 1)[1].strip()
                    if c:
                        cod = c
                elif s.startswith('LMP Version:'):
                    rest = s.split(':', 1)[1].strip()
                    m = _LMP_RE.search(rest)
                    if m:
                        bt_version = m.group(1)
                elif s.startswith('Manufacturer:'):
                    raw = s.split(':', 1)[1].strip()
                    hci_mfr = re.sub(r'\s*\(\d+\)\s*$', '', raw).strip() or None
            return name, cod, bt_version, hci_mfr
        except subprocess.TimeoutExpired:
            self.logger.debug("hcitool info timed out for %s", mac)
            return 'Unknown', None, None, None
        except Exception as exc:
            self.logger.debug("hcitool info failed for %s: %s", mac, exc)
            return 'Unknown', None, None, None

    def _resolve_info(self, macs: list[str]) -> dict[str, tuple]:
        """Resolve device info for all *macs* in parallel using a thread pool.

        @param macs  List of BD_ADDR strings to query.
        @return      Mapping of BD_ADDR → ``(name, cod, bt_version, hci_manufacturer)``.
        """
        if not macs:
            return {}
        results: dict[str, tuple] = {}
        with ThreadPoolExecutor(max_workers=max(1, min(8, len(macs)))) as executor:
            futures = {executor.submit(self._get_info, mac): mac for mac in macs}
            for future in as_completed(futures, timeout=60):
                mac = futures[future]
                try:
                    results[mac] = future.result()
                except Exception as exc:
                    self.logger.warning("Info resolution failed for %s: %s", mac, exc)
                    results[mac] = ('Unknown', None, None, None)
        return results

    def _notify_listeners(self, evt: dict) -> None:
        """Push *evt* to all registered live-feed queues (non-blocking).

        @param evt  Event dict to broadcast.
        """
        for q in list(self._event_listeners):
            try:
                q.put_nowait(evt)
            except Exception:
                pass

    def _handle_device(self, mac_address: str, name: str, cod: str | None,
                       bt_version: str | None, hci_mfr: str | None) -> None:
        """Persist a discovered Bluetooth Classic device and notify live-feed listeners.

        @param mac_address  BD_ADDR of the device.
        @param name         Friendly device name, or ``"Unknown"``.
        @param cod          Class-of-Device hex string, or ``None``.
        @param bt_version   LMP version string (e.g. ``"5.2"``), or ``None``.
        @param hci_mfr      HCI manufacturer string, or ``None``.
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        device_type, _minor, service_classes = _parse_bt_class(cod) if cod else ('Unknown', '', '')
        brand, csv_device_type, specific_models = get_device_info(mac_address, self.known_devices)
        if device_type != 'Unknown' and csv_device_type == 'Unknown':
            csv_device_type = device_type
        vendor = self.vendor_resolver.lookup(mac_address)
        self.db_manager.insert_or_update_bt_classic(
            mac_address, name, vendor, brand, csv_device_type, specific_models,
            signal_strength=None, first_seen=now, last_seen=now,
            bluetooth_version=bt_version,
            service_classes=service_classes if service_classes else None,
            hci_manufacturer=hci_mfr,
        )
        self._notify_listeners({
            'time':        datetime.now().strftime('%H:%M:%S'),
            'type':        'Discovered',
            'mac':         mac_address,
            'name':        name if name != 'Unknown' else '',
            'vendor':      vendor,
            'device_type': csv_device_type,
            'bt_version':  bt_version or '',
            'services':    service_classes or '',
        })
        self.logger.info(
            "BT Classic: %s (%s) cod=%s vendor=%s type=%s bt=%s mfr=%s",
            name, mac_address, cod, vendor, csv_device_type, bt_version, hci_mfr,
        )
