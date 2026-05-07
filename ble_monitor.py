"""
@file ble_monitor.py
@brief BLE advertisement scanner for DeviceWatcher.

Uses the bleak library to receive advertisements from a local HCI adapter.
Decodes iBeacon, Eddystone-URL/UID, Apple Nearby, and Xiaomi MiBeacon payloads;
estimates advertisement intervals; and pushes events to registered SSE queues.

@license MIT — see LICENSE for details.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from collections import OrderedDict

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from utils import VendorResolver, get_device_info
from ble_decoders import decode_manufacturer_data

_SERVICE_TYPES: dict[str, str] = {
    '180d': 'Heart Rate Monitor',
    '180f': 'Battery Device',
    '1812': 'HID Device',
    '1810': 'Blood Pressure Monitor',
    '1816': 'Cycling Speed/Cadence',
    '1818': 'Cycling Power',
    '1819': 'Location/Navigation',
    '181a': 'Environmental Sensor',
    '181d': 'Weight Scale',
    '1822': 'Pulse Oximeter',
    '1826': 'Fitness Machine',
    'feaa': 'Eddystone Beacon',
    'fd6f': 'COVID Exposure',
    'fe9f': 'Google Nearby',
}

_BT_BASE_SUFFIX = '00001000800000805f9b34fb'

# Apple 0x004C Nearby Info status-byte high-nibble → device model label
_APPLE_NEARBY_TYPES: dict[int, str] = {
    0x1: 'iPhone (Apple)',
    0x2: 'iPad (Apple)',
    0x3: 'MacBook (Apple)',
    0x5: 'Apple Watch',
    0x6: 'Apple TV',
    0x7: 'iPod (Apple)',
    0x9: 'AirPods',
    0xA: 'AirPods Pro',
}

# Eddystone-URL scheme prefix bytes and expansion codes
_EDDYSTONE_SCHEMES: dict[int, str] = {
    0x00: 'http://www.', 0x01: 'https://www.',
    0x02: 'http://',     0x03: 'https://',
}
_EDDYSTONE_CODES: dict[int, str] = {
    0x00: '.com/', 0x01: '.org/', 0x02: '.edu/', 0x03: '.net/',
    0x04: '.info/', 0x05: '.biz/', 0x06: '.gov/', 0x07: '.com',
    0x08: '.org',  0x09: '.edu',  0x0a: '.net',  0x0b: '.info',
    0x0c: '.biz',  0x0d: '.gov',
}


def _type_from_services(uuids: list[str]) -> str:
    """Map a list of GATT service UUIDs to a human-readable device-type label.

    Only 16-bit Bluetooth SIG UUIDs (embedded in 128-bit base UUIDs) are
    matched.

    @param uuids  List of UUID strings as returned by bleak.
    @return       First matching label from :data:`_SERVICE_TYPES`, or
                  ``"Unknown"`` when no match is found.
    """
    for uuid in (uuids or []):
        clean = uuid.lower().replace('-', '')
        if len(clean) == 32 and clean.startswith('0000') and clean[8:] == _BT_BASE_SUFFIX:
            label = _SERVICE_TYPES.get(clean[4:8])
            if label:
                return label
    return 'Unknown'


def _decode_ibeacon(payload: bytes) -> tuple[str | None, int | None, int | None]:
    """Parse an Apple iBeacon manufacturer-data payload (type byte 0x02).

    @param payload  Raw bytes after the Apple company ID (0x004C), starting
                    with the iBeacon type byte.
    @return         ``(uuid, major, minor)`` triple, or ``(None, None, None)``
                    when the payload does not match the iBeacon format.
    """
    if len(payload) < 22 or payload[0] != 0x02:
        return None, None, None
    uuid_bytes = payload[2:18]
    uuid = '-'.join([
        uuid_bytes[0:4].hex(),
        uuid_bytes[4:6].hex(),
        uuid_bytes[6:8].hex(),
        uuid_bytes[8:10].hex(),
        uuid_bytes[10:16].hex(),
    ]).upper()
    major = int.from_bytes(payload[18:20], 'big') if len(payload) >= 20 else None
    minor = int.from_bytes(payload[20:22], 'big') if len(payload) >= 22 else None
    return uuid, major, minor


def _decode_eddystone_url(data: bytes) -> str | None:
    """Parse an Eddystone-URL service-data frame (frame type 0x10).

    @param data  Raw service-data bytes for the Eddystone service UUID (0xFEAA).
    @return      Decoded URL string, or ``None`` when the frame is invalid.
    """
    if len(data) < 4 or data[0] != 0x10:
        return None
    prefix = _EDDYSTONE_SCHEMES.get(data[1], '')
    body = bytearray()
    for b in data[4:]:
        if b in _EDDYSTONE_CODES:
            body.extend(_EDDYSTONE_CODES[b].encode())
        elif 0x20 <= b <= 0x7E:
            body.append(b)
    try:
        return prefix + body.decode('ascii')
    except Exception:
        return None


def _decode_eddystone_uid(data: bytes) -> str | None:
    """Parse an Eddystone-UID service-data frame (frame type 0x00).

    @param data  Raw service-data bytes for the Eddystone service UUID (0xFEAA).
    @return      ``"NAMESPACE.INSTANCE"`` string (uppercase hex), or ``None``
                 when the frame is too short or the type byte is wrong.
    """
    if len(data) < 18 or data[0] != 0x00:
        return None
    namespace = data[2:12].hex().upper()
    instance  = data[12:18].hex().upper()
    return f"{namespace}.{instance}"


class BLEMonitor:
    """Continuously scan for BLE advertisements using the bleak library.

    Runs an asyncio event loop on the calling thread.  The scan repeats in
    30-second windows (configurable) and retries with exponential back-off on
    adapter errors.

    @param interface       HCI adapter index (e.g. ``0`` for ``hci0``).
    @param db_manager      Shared :class:`~database_manager.DatabaseManager`.
    @param vendor_resolver Shared :class:`~utils.VendorResolver`.
    @param known_devices   Dict returned by :func:`~utils.load_known_devices`.
    """

    def __init__(self, interface: int, db_manager, vendor_resolver: VendorResolver,
                 known_devices: dict):
        self.interface        = interface
        self.db_manager       = db_manager
        self.vendor_resolver  = vendor_resolver
        self.known_devices    = known_devices
        self.scanning         = False
        self._stop_event: asyncio.Event | None       = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._seen: OrderedDict[str, int | None]     = OrderedDict()
        self._adv_times: OrderedDict[str, float]     = OrderedDict()
        self._adv_intervals: dict[str, list[int]]    = {}
        self._error_count     = 0
        self._event_listeners: set                   = set()
        self._last_event_time: dict[str, float]      = {}
        self.logger           = logging.getLogger("BLEMonitor")

    # ------------------------------------------------------------------ public

    def start_scan(self, duration: int = 30) -> None:
        """Start the BLE scan loop.  Blocks until :meth:`stop_scan` is called.

        @param duration  Scan window duration in seconds before the loop
                         restarts and clears the RSSI-change filter.
        """
        self.scanning     = True
        self._error_count = 0
        self.logger.info("Starting BLE scan…")
        asyncio.run(self._scan_loop(duration))

    def stop_scan(self) -> None:
        """Signal the scan loop to exit cleanly."""
        self.scanning = False
        if self._stop_event and self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._stop_event.set)
        self.logger.info("BLE scan stopped.")

    def register_event_listener(self, q) -> None:
        """Register a queue to receive live BLE event dicts.

        @param q  A ``queue.Queue`` instance.
        """
        self._event_listeners.add(q)

    def unregister_event_listener(self, q) -> None:
        """Deregister a previously registered event listener.

        @param q  The queue instance to remove.
        """
        self._event_listeners.discard(q)

    # ------------------------------------------------------------------ internals

    async def _scan_loop(self, duration: int) -> None:
        """Async scan loop: creates a new :class:`BleakScanner` context per window.

        @param duration  Scan window length in seconds.
        """
        self._loop       = asyncio.get_running_loop()
        self._stop_event = asyncio.Event()

        while self.scanning:
            try:
                async with BleakScanner(
                    detection_callback=self._detection_callback,
                    adapter=f"hci{self.interface}",
                ):
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(self._stop_event.wait()),
                            timeout=duration,
                        )
                    except asyncio.TimeoutError:
                        self._error_count = 0
                    except Exception as exc:
                        self._error_count += 1
                        backoff = min(60, 5 * self._error_count)
                        self.logger.error("BLE scan error: %s (retry in %ds)", exc, backoff)
                        await asyncio.sleep(backoff)
            except Exception as exc:
                self._error_count += 1
                backoff = min(60, 5 * self._error_count)
                self.logger.error("BLE scan error: %s (retry in %ds)", exc, backoff)
                await asyncio.sleep(backoff)

            if self.scanning and not self._stop_event.is_set():
                await asyncio.sleep(2)

    def _detection_callback(self, device: BLEDevice, adv_data: AdvertisementData) -> None:
        """Process a BLE advertisement received by the scanner.

        Applies an RSSI-change filter (skips re-processing when RSSI has not
        changed), estimates the advertisement interval, decodes manufacturer-
        specific payloads (iBeacon, Eddystone, Apple Nearby), and persists the
        result.

        @param device    Bleak BLEDevice descriptor.
        @param adv_data  Bleak AdvertisementData for this advertisement.
        """
        mac  = device.address.lower()
        rssi = adv_data.rssi

        # Skip re-processing when RSSI has not changed since last callback.
        if self._seen.get(mac) == rssi:
            return
        if mac in self._seen:
            del self._seen[mac]
        self._seen[mac] = rssi
        if len(self._seen) > 5000:
            for _ in range(2500):
                self._seen.popitem(last=False)

        # Advertisement interval estimation via inter-arrival time.
        now_mono = time.monotonic()
        adv_interval_ms: int | None = None
        if mac in self._adv_times:
            gap_ms = int((now_mono - self._adv_times[mac]) * 1000)
            if 20 <= gap_ms <= 10_000:
                intervals = self._adv_intervals.setdefault(mac, [])
                intervals.append(gap_ms)
                if len(intervals) > 8:
                    intervals.pop(0)
                if len(intervals) >= 3:
                    sorted_iv = sorted(intervals)
                    adv_interval_ms = sorted_iv[len(sorted_iv) // 2]
        if mac in self._adv_times:
            del self._adv_times[mac]
        self._adv_times[mac] = now_mono
        if len(self._adv_times) > 5000:
            for _ in range(2500):
                k, _ = self._adv_times.popitem(last=False)
                self._adv_intervals.pop(k, None)

        name         = adv_data.local_name or device.name or 'Unknown'
        service_type = _type_from_services(adv_data.service_uuids)
        now          = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Build manufacturer-data JSON including decoded fields.
        mfr_raw: dict = adv_data.manufacturer_data or {}
        mfr_json_data: dict = {}
        for k, v in mfr_raw.items():
            hex_str = v.hex()
            mfr_json_data[f'{k:04x}'] = hex_str
            decoded = decode_manufacturer_data(f'{k:04x}{hex_str}')
            if decoded:
                mfr_json_data[f'{k:04x}_decoded'] = decoded
        mfr_json = json.dumps(mfr_json_data) if mfr_json_data else None

        tx_power    = getattr(adv_data, 'tx_power', None)
        connectable = getattr(adv_data, 'connectable', None)

        # iBeacon + Apple Nearby Info decoding.
        ibeacon_uuid = ibeacon_major = ibeacon_minor = None
        apple_device_type: str | None = None

        if 0x004C in mfr_raw:
            payload = mfr_raw[0x004C]
            if payload:
                frame_type = payload[0]
                if frame_type == 0x02:
                    ibeacon_uuid, ibeacon_major, ibeacon_minor = _decode_ibeacon(payload)
                elif frame_type == 0x10 and len(payload) >= 2:
                    nibble = (payload[1] >> 4) & 0x0F
                    apple_device_type = _APPLE_NEARBY_TYPES.get(nibble)

        # Eddystone decoding from service_data.
        eddystone_url = eddystone_uid = None
        for uuid_key, svc_bytes in adv_data.service_data.items():
            if 'feaa' in uuid_key.lower() and svc_bytes:
                if svc_bytes[0] == 0x10:
                    eddystone_url = _decode_eddystone_url(svc_bytes)
                elif svc_bytes[0] == 0x00:
                    eddystone_uid = _decode_eddystone_uid(svc_bytes)
                break

        brand, device_type, specific_models = get_device_info(mac, self.known_devices)
        if service_type != 'Unknown' and device_type == 'Unknown':
            device_type = service_type
        if apple_device_type and device_type == 'Unknown':
            device_type = apple_device_type

        vendor = self.vendor_resolver.lookup(mac)
        self.db_manager.insert_or_update_ble(
            mac, name, vendor, brand, device_type, specific_models,
            signal_strength=rssi, first_seen=now, last_seen=now,
            manufacturer_data=mfr_json,
            tx_power=tx_power,
            connectable=connectable,
            adv_interval_ms=adv_interval_ms,
            ibeacon_uuid=ibeacon_uuid,
            ibeacon_major=ibeacon_major,
            ibeacon_minor=ibeacon_minor,
            eddystone_url=eddystone_url,
            eddystone_uid=eddystone_uid,
        )
        self.logger.info(
            "BLE: %r (%s) rssi=%d vendor=%s type=%s%s%s",
            name, mac, rssi, vendor, device_type,
            f" iBeacon={ibeacon_uuid}" if ibeacon_uuid else "",
            f" eddystone={eddystone_url or eddystone_uid}"
            if (eddystone_url or eddystone_uid) else "",
        )

        # Throttle live-feed events to one per MAC per 2 seconds.
        if now_mono - self._last_event_time.get(mac, 0) < 2.0:
            return
        self._last_event_time[mac] = now_mono

        if ibeacon_uuid:
            evt_type = 'iBeacon'
            info = f"UUID:{ibeacon_uuid} {ibeacon_major}/{ibeacon_minor}"
        elif eddystone_url:
            evt_type = 'Eddystone-URL'
            info = eddystone_url
        elif eddystone_uid:
            evt_type = 'Eddystone-UID'
            info = eddystone_uid
        else:
            evt_type = 'Advertisement'
            info = 'connectable' if connectable else ''

        self._notify_listeners({
            'time':        datetime.now().strftime('%H:%M:%S'),
            'type':        evt_type,
            'mac':         mac,
            'name':        name if name != 'Unknown' else '',
            'vendor':      vendor,
            'device_type': device_type,
            'rssi':        rssi,
            'info':        info,
        })

    def _notify_listeners(self, evt: dict) -> None:
        """Push *evt* to all registered live-feed queues (non-blocking).

        @param evt  Event dict to broadcast.
        """
        for q in list(self._event_listeners):
            try:
                q.put_nowait(evt)
            except Exception:
                pass
