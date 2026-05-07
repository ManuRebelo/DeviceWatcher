# Bluetooth Monitoring

## Overview

DeviceWatcher supports two distinct Bluetooth technologies through separate monitor classes:

| Monitor | Class | Library | Table |
|---------|-------|---------|-------|
| BLE (Bluetooth Low Energy / 4.x–5.x) | `BLEMonitor` | `bleak` (pure Python) | `ble_devices` |
| Bluetooth Classic (BR/EDR) | `BluetoothClassicMonitor` | `hcitool` subprocess | `bt_classic` |

Both are optional and independent — start only the ones you need with `--ble <hci>` and/or `--bt <hci>`.

To find the HCI index of your adapters:
```bash
hcitool dev
# Devices:
#     hci0    AA:BB:CC:DD:EE:FF
#     hci1    11:22:33:44:55:66
```

> [!IMPORTANT]
> When running in **Docker**, you must use `network_mode: host` to allow the container to access the host's Bluetooth adapters.

---

## BLE monitoring (`ble_monitor.py`)

### How it works

`BLEMonitor` uses the [bleak](https://bleak.readthedocs.io/) library, which wraps the Linux BlueZ D-Bus API via asyncio. No kernel modules, C extensions, or compilation are required — bleak installs as a pure-Python wheel.

The monitor runs an asyncio event loop in a dedicated OS thread (`asyncio.run(self._scan_loop(duration))`). The scan loop:

1. Opens a `BleakScanner` context with a **passive scan** (listens for advertisement packets without sending scan requests).
2. Waits `duration` seconds (default 30) or until `self._stop_event` is set.
3. After each scan window, sleeps 2 seconds before starting the next window.
4. On error, backs off exponentially: `min(60, 5 × error_count)` seconds before retrying.

```
┌──────────────────────────────────────────────┐
│ _scan_loop                                   │
│                                              │
│  while scanning:                             │
│    async with BleakScanner(...):             │  ← scan window open
│      wait(stop_event OR timeout=30s)         │
│    sleep(2s)                                 │  ← gap between windows
│                                              │
│  on exception:                               │
│    sleep(5s × n, max 60s)                   │  ← error backoff
└──────────────────────────────────────────────┘
```

### Detection callback

`_detection_callback(device, adv_data)` is called by bleak on every received advertisement. It skips the update if the RSSI is unchanged from the last seen value (stored in `self._seen`) to avoid flooding the database with redundant writes. `_seen` is capped at 5,000 entries; when exceeded the oldest 2,500 are evicted.

Fields extracted per advertisement:

| Field | Source | Notes |
|-------|--------|-------|
| MAC address | `device.address` | Lowercased |
| RSSI | `adv_data.rssi` | dBm, signed integer |
| Device name | `adv_data.local_name` or `device.name` | Falls back to `"Unknown"` |
| Device type | Service UUIDs → `_type_from_services()` | See table below |
| Manufacturer data | `adv_data.manufacturer_data` | JSON-encoded (see below) |

### Device type from service UUIDs

`_type_from_services()` matches advertised 128-bit UUIDs against the Bluetooth base UUID form `0000XXXX-0000-1000-8000-00805F9B34FB`:

| Short UUID | Device type |
|-----------|-------------|
| `180D` | Heart Rate Monitor |
| `180F` | Battery Device |
| `1812` | HID Device (keyboard, mouse, gamepad) |
| `1810` | Blood Pressure Monitor |
| `1816` | Cycling Speed/Cadence |
| `1818` | Cycling Power |
| `1819` | Location/Navigation |
| `181A` | Environmental Sensor |
| `181D` | Weight Scale |
| `1822` | Pulse Oximeter |
| `1826` | Fitness Machine |
| `FEAA` | Eddystone Beacon |
| `FD6F` | COVID Exposure Notification |
| `FE9F` | Google Nearby |

If no UUID matches, the type falls back to `get_device_info()` (MAC-prefix CSV lookup). The UUID-derived type takes priority if the CSV returns `"Unknown"`.

### Manufacturer data storage

`adv_data.manufacturer_data` is a `dict[int, bytes]` where the key is the 16-bit Bluetooth Company Identifier and the value is the raw payload bytes.

DeviceWatcher serialises it as JSON with hex-string keys and hex-string values:
```json
{"004c": "0215...aabbccdd00"}
```

The dashboard's `decodeManufacturerData()` function interprets this, mapping known company IDs to names and additionally decoding Apple frames:

| Company ID | Company |
|-----------|---------|
| `004C` | Apple |
| `00E0` | Google |
| `0006` | Microsoft |
| `0075` | Samsung |
| `0117` | Fitbit |

For Apple frames, the first byte of the payload identifies the frame type:

| Byte | Frame type |
|------|-----------|
| `02` | iBeacon |
| `05` | AirDrop |
| `07` | AirPods / Beats Nearby |
| `0C` | Find My / AirTag |
| `0F` | Nearby Action |
| `10` | Nearby Info |
| `12` | Find My v2 |

### Advertisement enrichment

Beyond the basic RSSI and device name, `_detection_callback` extracts several additional fields from each advertisement:

**TX Power (`tx_power`)**

Read directly from `adv_data.tx_power` (dBm). When combined with RSSI, the dashboard estimates range using the free-space path loss formula: `d = 10 ^ ((txPower − rssi) / 20)`. Stored in `ble_devices.tx_power`.

**Connectable flag (`connectable`)**

`getattr(adv_data, 'connectable', None)` — indicates whether the device accepts connections. Shown as a `Connectable` / `Non-connectable` badge in the BLE Inspector. Stored in `ble_devices.connectable`.

**Advertisement interval (`adv_interval_ms`)**

Estimated from the gap between consecutive advertisements for the same MAC, using `time.monotonic()`. Only gaps between 20 ms and 10,000 ms are recorded; the median of the last 8 gaps is used to smooth out jitter. Stored in `ble_devices.adv_interval_ms`.

| Range | Label |
|-------|-------|
| < 100 ms | aggressive |
| 100–499 ms | normal |
| 500–1999 ms | slow |
| ≥ 2000 ms | low power |

**iBeacon decoding**

Triggered when Apple manufacturer data (company ID `0x004C`) starts with frame type `0x02`. The 22-byte payload is parsed as:
- UUID: bytes 2–17 (formatted as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- Major: bytes 18–19 (big-endian)
- Minor: bytes 20–21 (big-endian)

Stored in `ble_devices.ibeacon_uuid`, `ibeacon_major`, `ibeacon_minor`. Shown in the BLE Inspector card.

**Eddystone URL / UID decoding**

Triggered when service data UUID `FEAA` is present. The first byte of the payload is the frame type:

| Frame type | Parsed as | Fields |
|-----------|----------|--------|
| `0x10` | Eddystone-URL | URL prefix + body (domain codes expanded) |
| `0x00` | Eddystone-UID | `NAMESPACE.INSTANCE` hex string |

Stored in `ble_devices.eddystone_url` and `eddystone_uid`. Shown in the BLE Inspector card.

**Apple Nearby Info device type**

Triggered when Apple manufacturer data (company ID `0x004C`) starts with frame type `0x10` (Nearby Info). The high nibble of the status byte maps to a device model:

| Nibble | Device |
|--------|--------|
| `0x1` | iPhone |
| `0x2` | iPad |
| `0x3` | MacBook |
| `0x5` | Apple Watch |
| `0x6` | Apple TV |
| `0x7` | iPod |
| `0x9` | AirPods |
| `0xA` | AirPods Pro |

This overrides `device_type = "Unknown"` from the CSV lookup.

### Stopping the scan

`stop_scan()` sets `self._stop_event` via `self._loop.call_soon_threadsafe()`, which is the asyncio-safe way to signal an event from a different OS thread. The scan loop exits at the next `wait()` checkpoint.

---

## Bluetooth Classic monitoring (`bluetooth_classic_monitor.py`)

### How it works

Bluetooth Classic discovery uses the `hcitool` command-line utility from the `bluez` package. There is no pure-Python Bluetooth Classic inquiry library that works on modern kernels without C extensions, so DeviceWatcher wraps the subprocess directly.

The scan loop:

```
while scanning:
    macs = _inquire(duration=10)          # hcitool inq (blocks for ~10s)
    if macs:
        info_map = _resolve_info(macs)    # hcitool info <mac> × N (parallel)
        for mac in macs:
            _handle_device(mac, ...)      # write to database
    sleep(2s)
```

### Inquiry — `_inquire(duration)`

Runs `hcitool --device=hci<N> inq --length=<slots> --flush`:

- `--flush` clears the inquiry cache, ensuring fresh results.
- `--length` is `round(duration / 1.28)` — Bluetooth inquiry runs in 1.28-second slots.
- For the default 10-second duration: `round(10 / 1.28) = 8` slots ≈ 10.24 s actual inquiry time.
- The subprocess is given a `timeout = duration + 15` seconds via `communicate(timeout=...)`. If it hangs, it is sent `SIGKILL`.

The `Popen` handle is stored in `self._proc` so that `stop_scan()` can terminate it immediately from another thread.

Output parsing: each non-empty line is split on whitespace; the first token is accepted as a MAC if it is exactly 17 characters with 5 colons.

If `hcitool` is not found, scanning stops immediately with an error message directing the user to `sudo apt install bluez`.

### Info resolution — `_resolve_info(macs)`

Runs `hcitool --device=hci<N> info <mac>` for each discovered MAC. Up to 8 requests run concurrently via `ThreadPoolExecutor(max_workers=min(8, len(macs)))`, with a 60-second total timeout for all futures.

Each `hcitool info` output is parsed line by line:
- `Device Name: <name>` → device name
- `Class: <hex>` → Class of Device (CoD) hex string
- `LMP Version: X.Y (0xN)  …` → Bluetooth version string (e.g. `"5.2"`)
- `Manufacturer: <name>` → HCI chip manufacturer (trailing company-ID parenthetical stripped)

### Class of Device parsing — `_parse_bt_class(cod_str)`

The 24-bit Class of Device field encodes the device's capabilities. DeviceWatcher extracts:

**Major Device Class** — bits 12–8:

| Major | Device type |
|-------|-------------|
| 1 | Computer |
| 2 | Phone |
| 3 | Network |
| 4 | Audio/Video |
| 5 | Peripheral |
| 6 | Imaging |
| 7 | Wearable |
| 8 | Toy |
| 9 | Health |

**Minor Device Class** — bits 7–2 (interpreted relative to Major):

Selected examples:

| Major | Minor | Label |
|-------|-------|-------|
| 2 (Phone) | 3 | Smartphone |
| 4 (Audio/Video) | 1 | Headset |
| 4 | 6 | Headphones |
| 4 | 5 | Loudspeaker |
| 5 (Peripheral) | 16 | Keyboard |
| 5 | 32 | Pointing Device |
| 7 (Wearable) | 1 | Wristwatch |

When a Minor class label is available it overrides the Major label as `device_type`. Stored in `bt_classic.device_type`.

**Service Classes** — bits 23–13:

| Bit | Service |
|-----|---------|
| 13 | Positioning |
| 14 | Networking |
| 15 | Rendering |
| 16 | Capturing |
| 17 | Object Transfer |
| 18 | Audio |
| 19 | Telephony |
| 20 | Information |

Active service classes are joined with `", "` and stored in `bt_classic.service_classes`. Shown in the **Services** column of the Bluetooth Classic table.

### Bluetooth version and HCI manufacturer

Parsed from `hcitool info` output:

- **LMP Version** line: extracted with regex `(\d+\.\d+)\s+\(0x` → version string `"5.2"`. Stored in `bt_classic.bluetooth_version`. Shown in the **BT Ver.** column.
- **Manufacturer** line: company name with trailing `(N)` stripped. Stored in `bt_classic.hci_manufacturer`.

The CoD-derived type takes priority over the MAC-prefix CSV lookup when available.

### Error handling

| Error | Behaviour |
|-------|-----------|
| `hcitool` not found | `scanning = False`, error logged, thread exits |
| Subprocess timeout | Process killed with `SIGKILL`, scan continues |
| Other exception | Error count incremented; backoff `min(60, 5 × n)` seconds |

---

## Database upsert logic

### BLE (`insert_or_update_ble`)

On conflict:
- `name` is updated only if the new value is not `"Unknown"` (preserves a previously resolved name when the device advertises without one).
- `manufacturer_data` is updated only when the new value is not `NULL`.
- `signal_strength` and `last_seen` are always overwritten.

### BT Classic (`insert_or_update_bt_classic`)

On conflict:
- `name` and `signal_strength` are always overwritten (no-signal writes `NULL`).
- `last_seen` is always updated; `first_seen` is preserved.

---

## Limitations

### BLE

- **Passive scan only** — DeviceWatcher does not connect to or query services from discovered devices. The device type is inferred from advertisement data only.
- **Random addresses** — BLE devices may use randomly generated MAC addresses that rotate periodically (privacy feature). Each rotation appears as a new device in the database. There is no correlation between rotated addresses.
- **RSSI accuracy** — BLE RSSI varies with orientation, obstacles, and RF environment. The proximity chart is a rough visual indicator, not a calibrated distance estimate.

### Bluetooth Classic

- **Discoverable devices only** — `hcitool inq` only finds devices in discoverable mode. Most modern phones are non-discoverable by default.
- **Blocking inquiry** — each inquiry blocks the scan thread for the full inquiry duration (~10 seconds). There is no way to interrupt it mid-inquiry without killing the subprocess.
- **No RSSI** — `hcitool inq` does not reliably expose RSSI on all chipsets. `signal_strength` is stored as `NULL` for BT Classic devices and does not appear on the timeline chart.
- **`hcitool` deprecation** — `hcitool` is deprecated in BlueZ 5.x but remains available in current distributions. The `btmgmt` or D-Bus API could replace it in a future version without requiring system calls.
