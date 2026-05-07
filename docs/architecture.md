# Architecture

## Overview

DeviceWatcher is a passive network monitoring tool built around a multi-threaded Python backend and a single-page AdminLTE dashboard. Up to three independent monitors (Wi-Fi, Bluetooth Classic, BLE) write device observations into a shared SQLite database. A Flask web server exposes that data as JSON and Server-Sent Event streams; the browser polls it on an interval and renders tables, graphs, and charts entirely client-side.

```
┌──────────────────────────────────────────────────────────┐
│                        Process                           │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ WiFiMonitor │  │ BTClassic    │  │   BLEMonitor   │  │
│  │  (thread)   │  │ Monitor      │  │ (asyncio thread│  │
│  │  Scapy sniff│  │  (thread)    │  │   bleak)       │  │
│  │  + hopper   │  │  hcitool     │  │                │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                │                   │           │
│         └────────────────┴───────────────────┘           │
│                          │                               │
│                 ┌─────────▼──────────┐                   │
│                 │  DatabaseManager   │                   │
│                 │  (SQLite WAL +     │                   │
│                 │   per-thread conn) │                   │
│                 └─────────┬──────────┘                   │
│                           │                              │
│            ┌──────────────┴──────────────┐               │
│            │                             │               │
│   ┌────────▼────────┐        ┌───────────▼────────────┐  │
│   │  Flask / Waitress│       │    AnalyticsEngine     │  │
│   │  (main thread)  │        │  (called on-request)   │  │
│   └────────┬────────┘        └────────────────────────┘  │
└────────────┼─────────────────────────────────────────────┘
             │ HTTP / SSE
    ┌────────▼────────┐
    │  Browser        │
    │  AdminLTE SPA   │
    └─────────────────┘
```

---

## Components

### `DeviceWatcher.py` — Entry point & Flask app

- Parses CLI arguments (`--wifi`, `--bt`, `--ble`, `--host`, `--port`, `--auth-token`, `--oui-file`, `--enable-vendor-api`).
- Instantiates `DatabaseManager`, `AnalyticsEngine`, `VendorResolver`, and whichever monitors were requested.
- Starts each monitor as a daemon `Thread` (or asyncio event loop for BLE) so they die cleanly when the main process exits.
- Serves via **waitress** (production-grade threaded WSGI server) when installed; falls back to Flask's built-in dev server.
- Installs a `SIGTERM` handler so systemd/Docker stop signals cleanly terminate `hcitool` subprocesses.
- Serves Doxygen-generated API documentation at `/docs`.

**API endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves `index.html` |
| `GET` | `/docs` | Doxygen API documentation index |
| `GET` | `/docs/<path>` | Doxygen static assets |
| `GET` | `/data` | All current devices as JSON |
| `GET` | `/readings` | Recent signal history (last 2 000 rows) |
| `DELETE` | `/device/ap/<mac>` | Remove an AP (and its BSSID group) |
| `DELETE` | `/device/client/<mac>` | Remove a client |
| `DELETE` | `/device/bt/<mac>` | Remove a BT Classic device |
| `DELETE` | `/device/ble/<mac>` | Remove a BLE device |
| `POST` | `/device/cleanup` | Delete devices inactive for `?hours=N` (default 24) |
| `GET/POST` | `/config` | Toggle external vendor API (`external_api_enabled`) |
| `GET/POST` | `/system/settings` | Wi-Fi dwell time and band filter |
| `GET` | `/system/status` | Per-monitor active/error status |
| `GET/POST` | `/system/channel_hopper` | Pause / resume / lock channel |
| `GET` | `/analytics/radar` | RSSI-based distance points |
| `GET` | `/analytics/occupancy` | Hourly device-count histogram |
| `GET` | `/analytics/security` | Detected security threats |
| `GET` | `/analytics/clusters` | Entity clustering results |
| `GET/POST` | `/analytics/clusters/config` | Get/set clustering threshold |
| `POST` | `/analytics/clusters/<id>/rename` | Assign a name to a cluster |
| `GET` | `/live/packets` | SSE stream of Wi-Fi packet summaries |
| `GET` | `/live/bt` | SSE stream of BT Classic discovery events |
| `GET` | `/live/ble` | SSE stream of BLE advertisement events |

DELETE routes validate the MAC with `^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$` and return 400 for bad input, 404 if not found, 204 on success. Most routes return 503 while the database is initialising.

**Authentication:** when `--auth-token` is set (or `DEVICEWATCHER_TOKEN` env var), every request must present `Authorization: Bearer <token>`. The `/live/packets` SSE endpoint additionally accepts `?token=` (EventSource cannot send custom headers). Static files and `/docs` are always public.

---

### `database_manager.py` — Persistence layer

All database access goes through `DatabaseManager`. Each calling thread gets its own `sqlite3.Connection` stored in `threading.local()`. WAL journal mode allows concurrent reads from Flask request threads while writes are serialised by a shared `RLock` (`self._lock`).

A second non-reentrant `Lock` (`self._reading_lock`) protects `self._last_reading` — an `OrderedDict` that throttles `signal_readings` inserts to at most one row per MAC per 30 seconds.

The database file and its WAL/SHM siblings are `chmod`-ed to `0o600` on every new connection open so that other OS users cannot read the observation history.

**Schema:**

```
aps (mac_address PK, ssid, vendor, brand, device_type, specific_models,
     channel, frequency, signal_strength, security, count,
     first_seen, last_seen, channel_width, band, bssid_group,
     wifi_generation, spatial_streams, country_code,
     station_count, channel_utilization, pmf,
     has_11k, has_11v, has_11r, mdid,
     is_hotspot20, network_type, is_mesh, ip_address)

clients (mac_address PK, associated_ap, vendor, brand, device_type,
         specific_models, signal_strength, count, is_streaming,
         first_seen, last_seen,
         hostname, ip_address, os_fingerprint, dhcp_vendor_class)

bt_classic (mac_address PK, name, vendor, brand, device_type,
            specific_models, signal_strength, first_seen, last_seen,
            bluetooth_version, service_classes, hci_manufacturer)

ble_devices (mac_address PK, name, vendor, brand, device_type,
             specific_models, signal_strength, first_seen, last_seen,
             manufacturer_data, tx_power, connectable, adv_interval_ms,
             ibeacon_uuid, ibeacon_major, ibeacon_minor,
             eddystone_url, eddystone_uid)

probe_requests (client_mac, ssid, channel, last_seen,
                PRIMARY KEY (client_mac, ssid))

signal_readings (id AUTOINCREMENT PK, mac_address, device_type,
                 signal_strength, timestamp)
    INDEX: idx_sr_mac ON (mac_address, id DESC)
    TRIGGER: trg_limit_readings — prunes to 60 rows per MAC after each insert

entity_aliases (cluster_id PK, name)
    — user-assigned names for entity clusters
```

All tables are created at startup with `CREATE TABLE IF NOT EXISTS`. New columns on existing databases are added via `ALTER TABLE` migration blocks that silently catch `sqlite3.OperationalError` (column already exists), allowing the schema to evolve without dropping data.

`signal_readings` is automatically trimmed by the `trg_limit_readings` trigger (max 60 rows per MAC). `fetch_signal_readings` further caps responses at 2 000 rows.

---

### `analytics_engine.py` — Analytics

`AnalyticsEngine` runs on-demand (called from Flask request handlers) against the shared database. It does not hold any persistent state.

| Method | Description |
|--------|-------------|
| `get_radar_data()` | Returns RSSI + estimated distance for all devices seen in the last 5 minutes |
| `compute_occupancy()` | Bins unique device sightings into 1-hour windows over the last 24 hours |
| `scan_security_threats()` | Detects WEP/TKIP networks, open APs, possible Evil-Twin attacks, streaming cameras |
| `cluster_devices(threshold)` | Multi-signal union-find clustering across all device tables |

**Entity clustering** uses six weighted affinity signals:

| Signal | Weight |
|--------|--------|
| Temporal co-occurrence (first/last seen within 60 s) | 0.30 |
| Same OUI prefix | 0.25 |
| Adjacent full MAC address (last octet within ±1) | 0.20 |
| Shared associated AP | 0.20 |
| Shared probe SSIDs (≥ 2) | 0.15 |
| Vendor + device-type match | 0.10 |
| iBeacon UUID match (hard floor) | 0.50 |

Pairs whose score meets `threshold` (default 0.40, range 0.05–0.95) are merged by union-find. Clusters of ≥ 2 devices are returned with evidence labels and a confidence score.

---

### `ble_decoders.py` — BLE manufacturer-data decoder

Stateless module-level function `decode_manufacturer_data(hex_data)` decodes common BLE manufacturer-specific advertisement payloads:

| Company ID | Brand | Fields decoded |
|-----------|-------|---------------|
| `0x004C` | Apple | `beacon_type` (iBeacon), `service` (Nearby/Continuity, AirPods/Proximity Pair) |
| `0x015D` | Xiaomi | `temperature_c`, `humidity_pct` (MiBeacon events 0x1004, 0x1006) |
| `0x0006` | Microsoft | `service` (Swift Pair) |

---

### `utils.py` — Shared helpers

**`load_known_devices(csv_file_path)`**

Reads `MAC_Address_Device_List.csv` into a dict keyed on uppercase three-octet MAC prefix (e.g. `"AA:BB:CC"`). Returns an empty dict silently if the file is missing.

**`get_device_info(mac, known_devices)`**

Looks up the first three octets of `mac` in the loaded dict. Returns `(brand, device_type, specific_models)`, falling back to three `"Unknown"` strings.

**`VendorResolver`**

Resolves MAC addresses to vendor names in two stages:

1. **Local IEEE OUI registry** (synchronous, always attempted first):
   - Loads MA-S (`oui36.csv`), MA-M (`mam.csv`), and MA-L (`oui.csv`) from `/usr/share/ieee-data/` (installed by the `ieee-data` package on Debian/Ubuntu/Kali).
   - A user-supplied Wireshark `manuf` file or IEEE CSV can be added via `--oui-file`.
   - Longest-prefix matching: 36-bit > 28-bit > 24-bit.

2. **External REST APIs** (async, opt-in via `--enable-vendor-api`):
   - `https://api.macvendors.com/{mac}` (plain text response)
   - `https://www.macvendorlookup.com/api/v2/{mac}` (JSON array response)
   - `lookup(mac)` returns `"Unknown"` immediately and enqueues the MAC for a background worker thread.
   - The cache is capped at 10 000 entries; oldest 5 000 are evicted when exceeded.

> **Privacy note**: external API lookups send every observed MAC address to a
> third-party server. This feature is disabled by default.

---

### Threading model

| Thread | Name | Notes |
|--------|------|-------|
| Main | Flask / waitress | HTTP request handling |
| WiFiMonitor | `threading.Thread` (daemon) | Runs scapy `sniff()` blocking call |
| Channel hopper | `threading.Thread` (daemon) | Spawned inside `WiFiMonitor.start_sniffing` |
| BT Classic | `threading.Thread` (daemon) | Blocking `hcitool inq` loop |
| BLE | `threading.Thread` (daemon) | Runs `asyncio.run()` — dedicated event loop |
| VendorResolver worker | `threading.Thread` (daemon) | Queue consumer for external API lookups |

All daemon threads die when the main process exits. The BLE monitor runs its own asyncio event loop (`asyncio.run(self._scan_loop(...))`) in a dedicated OS thread — this is safe because bleak manages its own loop internally.

---

## Data flow

```
RF frame (air)
    │
    ▼
WiFiMonitor.packet_handler()          ← called by Scapy on every captured packet
    │  parse: SSID, channel, signal, security, IEs
    ▼
DatabaseManager.insert_or_update_ap/client()
    │  INSERT … ON CONFLICT … DO UPDATE (upsert)
    ├─► DatabaseManager.insert_signal_reading()   ← rate-limited to 1 per MAC per 30 s
    └─► WiFiMonitor._link_bssid_group()           ← once per MAC per session

BLEMonitor._detection_callback()      ← called by bleak on each advertisement
    └─► DatabaseManager.insert_or_update_ble()

BluetoothClassicMonitor._handle_device()
    └─► DatabaseManager.insert_or_update_bt_classic()

Browser polls GET /data every 60 s
    │
    ▼
Flask /data handler → db_manager.fetch_all_*()
    │
    ▼
JSON → fetchData() in main.js
    ├─► DataTables (APs, Clients, BT, BLE)
    ├─► vis.js network graphs
    ├─► Chart.js (activity, spectrum, proximity, presence)
    └─► Association map HTML

Browser polls GET /readings every 30 s → signal timeline charts

Browser connects to SSE endpoints → live packet / discovery feeds

Browser calls GET /analytics/* on demand → radar, occupancy, security, clustering
```

---

## Frontend architecture

The dashboard is a single HTML page (`templates/index.html`) rendered by Flask with Jinja2 (no template variables are injected — it is a static SPA served from Flask). All data arrives via `fetch()` calls.

**Libraries (locally served from `static/adminlte/` and `static/vendor/`):**

| Library | Purpose |
|---------|---------|
| AdminLTE 3.2 | Layout, sidebar, cards |
| Bootstrap 4 | Grid, modals, badges |
| jQuery | DataTables + Bootstrap 4 modal API |
| DataTables + BS4 plugin | Sortable/searchable device tables |
| vis.js 4.21 | Network topology graphs |
| Chart.js | Bar, line, doughnut, bubble charts |
| Font Awesome | Icons |

All user-controlled strings (SSIDs, device names, vendor names) are passed through `escHtml()` before being written to `innerHTML` to prevent XSS from crafted RF payloads.

---

## Containerisation

### Multi-stage Dockerfile

```
Stage 1 – doc-builder
    FROM python:3.11-slim-bookworm
    RUN apt install doxygen graphviz
    COPY . .
    RUN doxygen Doxyfile          → docs/html/

Stage 2 – runtime
    FROM python:3.11-slim-bookworm
    RUN apt install bluez iw libpcap-dev procps iproute2 net-tools ieee-data
    COPY requirements.txt && pip install …
    COPY . .
    COPY --from=doc-builder /app/docs/html /app/docs/html
    EXPOSE 5000
```

Doxygen and Graphviz are not present in the final image; only the pre-generated HTML is injected. This keeps the runtime image the same size as a single-stage build.

### Deployment requirements

| Requirement | Reason |
|------------|--------|
| `privileged: true` | Allows `iw` channel changes and scapy raw-socket capture |
| `network_mode: host` | Gives the container access to the host's physical Wi-Fi and Bluetooth adapters |
| `/var/run/dbus` volume | bleak talks to BlueZ over D-Bus; the socket must be shared from the host |

### Persistence

The SQLite database is stored in `/app/data/` inside the container, mapped to `./data/` on the host:

```yaml
volumes:
  - ./data:/app/data
```

This directory is created automatically on first run. Never mount a bare file path for the database — Docker would create a directory at that path, causing SQLite to fail.
