# Wi-Fi Monitoring

## Overview

Wi-Fi monitoring is implemented in `wifi_monitor.py` using [Scapy](https://scapy.net/). It requires a wireless adapter in **monitor mode** so it can capture all 802.11 frames regardless of their destination. Captured frames are parsed and written to the `aps`, `clients`, and `signal_readings` tables.

---

## Prerequisites

### Monitor mode

The adapter must be in monitor mode before starting DeviceWatcher. The simplest method uses `airmon-ng`:

```bash
sudo airmon-ng check kill          # terminate interfering processes (wpa_supplicant, dhclient)
sudo airmon-ng start wlan1         # creates wlan1mon (exact name varies by driver)
```

Verify with:
```bash
iw dev                             # lists all interfaces and their modes
```

To revert after use:
```bash
sudo airmon-ng stop wlan1mon
sudo systemctl restart NetworkManager
```

### Required system packages

| Package | Provides |
|---------|---------|
| `iw` | Channel-setting via `iw dev <iface> set channel <n>` |
| `aircrack-ng` | `airmon-ng` for enabling monitor mode |

> [!TIP]
> When running in **Docker**, these tools are pre-installed in the image. However, the container must be run in `privileged` mode to allow `iw` to change channels.

---

## Channel hopping

`WiFiMonitor._channel_hopper()` runs as a daemon thread and cycles through all supported channels with `iw dev <iface> set channel <n>`, sleeping 150 ms per channel. One full cycle takes approximately:

| Band | Channels | Time |
|------|----------|------|
| 2.4 GHz | 13 (ch 1–13) | ~2.0 s |
| 5 GHz | 25 (UNII-1 through UNII-3 + ch 144, 149–165) | ~3.75 s |
| 6 GHz | 59 (ch 1–233 step 4, Wi-Fi 6E) | ~8.85 s |
| **Total** | **97 channels** | **~14.5 s/cycle** |

The hopper updates `self.current_channel` on every hop, which `packet_handler` uses as a fallback when channel information is not available in the frame itself.

### UI Controls
Users can pause and resume the channel hopper via the web dashboard. Pausing the hopper keeps the radio locked to a single channel. This is particularly useful for accurately measuring the bandwidth of a specific device without missing traffic that occurs on other channels.

## Packet handling

`WiFiMonitor.packet_handler()` is called by Scapy for every captured frame. It dispatches by `dot11.type` and `dot11.subtype`:

### Management frames (type 0)

| Subtype | Name | Action |
|---------|------|--------|
| 8 | Beacon | Upsert AP with full metadata |
| 4 | Probe Request | Upsert client |
| 5 | Probe Response | Upsert AP with full metadata |
| 0 | Association Request | Upsert client linked to BSSID |
| 1 | Association Response | Upsert client (sent by AP, addr1 is client) |
| 2 | Reassociation Request | Upsert client |
| 3 | Reassociation Response | Upsert client |
| 10 | Disassociation | Clear `associated_ap` for client |
| 11 | Authentication | Register client/AP depending on direction |
| 12 | Deauthentication | Clear `associated_ap` for client |
| 13 | Action | Update `last_seen` for both parties |

### Data frames (type 2)

The `to_ds` and `from_ds` FCfield bits determine the direction:

| to_ds | from_ds | Meaning | Action |
|-------|---------|---------|--------|
| 1 | 1 | WDS / AP-to-AP | Logged at DEBUG only |
| 0 | 1 | AP → client | Register/refresh AP |
| 1 | 0 | client → AP | Upsert client linked to addr3 (BSSID) |

When observing `client → AP` data frames, DeviceWatcher tracks the length of the packet in bytes. An in-memory tracker calculates the upstream bandwidth over a sliding 5-second window. If a client sustains more than **50 KB/s** of upstream traffic, it is flagged with `is_streaming = 1` in the database, allowing the UI and Analytics engine to classify it as a **LIVE Camera**. (Note: Accurate detection requires pausing the channel hopper on the camera's channel).

### Control frames (type 1)

| Subtype | Name | Action |
|---------|------|--------|
| 5 | PS-Poll | Upsert client, register AP if unknown |
| 8, 9 | Block Ack / BAR | Update `last_seen` for both parties |

---

## Information element (IE) parsing

802.11 management frames carry a chain of **Information Elements**. DeviceWatcher walks this chain with `packet.getlayer(Dot11Elt)` and advances via `.payload.getlayer(Dot11Elt)`.

### Wi-Fi Generation — `_wifi_generation_from_ies()`

Detects the highest Wi-Fi generation supported by an AP by looking for capability IEs:

| IE ID | Extended tag | Capability | Generation |
|-------|-------------|-----------|-----------|
| 45 | — | HT Capabilities | Wi-Fi 4 (802.11n) |
| 191 | — | VHT Capabilities | Wi-Fi 5 (802.11ac) |
| 255 | 35 | HE Capabilities | Wi-Fi 6 (802.11ax) or Wi-Fi 6E if on 6 GHz |
| 255 | 107 | EHT Capabilities | Wi-Fi 7 (802.11be) |

Results are stored in `aps.wifi_generation` and shown in the AP table **Gen** column and in the Wi-Fi graph node labels.

### Spatial Streams — `_spatial_streams_from_ies()`

Counts the maximum number of spatial streams (MIMO) advertised by the AP:

- **HT Capabilities (ID 45)**: walks the 4-byte Rx MCS Set (bytes 3–6) — each non-zero byte represents one supported stream.
- **VHT Capabilities (ID 191)**: reads the 16-bit Rx MCS Map (bytes 4–5) — each 2-bit field `!= 0x3` counts as one stream.

VHT result takes priority over HT. Stored in `aps.spatial_streams`; displayed as `N×N` (e.g. `2×2`) in the AP table **Streams** column.

### Country Code — `_country_code_from_ies()`

Reads the **Country IE** (ID 7). The first two bytes are a 2-letter ASCII country code (`US`, `GB`, `DE`, …). Requires a valid alpha string; silently returns `None` on malformed data. Stored in `aps.country_code`.

### BSS Load — `_bss_load_from_ies()`

Reads the **BSS Load IE** (ID 11, 5 bytes):

| Bytes | Field | Conversion |
|-------|-------|-----------|
| 0–1 | Station Count | raw 16-bit LE integer |
| 2 | Channel Utilization | `round(byte / 2.55)` → 0–100 % |

Stored in `aps.station_count` and `aps.channel_utilization`. Displayed as `N sta, X%` in the AP table **Load** column.

### PMF — `_pmf_from_ies()`

Reads the RSN **Capabilities** field (last 2 bytes of RSN IE, ID 48):

| Bit | Meaning | Result |
|-----|---------|--------|
| 6 (MFPR) | Management Frame Protection Required | `"Required"` |
| 7 (MFPC) | Management Frame Protection Capable | `"Capable"` |
| both 0 | No MFP | `"Disabled"` |

Stored in `aps.pmf`. Displayed as a colour-coded badge (green = Required, blue = Capable, grey = Disabled).

### Extended Capabilities — `_extended_caps_from_ies()`

Reads the **Extended Capabilities IE** (ID 127) and **Mobility Domain IE** (ID 54):

| IE | Bit | Feature | Field |
|----|-----|---------|-------|
| 127 | 19 (byte 2, bit 3) | BSS Transition (802.11v) | `has_11v` |
| 127 | 35 (byte 4, bit 3) | Neighbor Reports (802.11k) | `has_11k` |
| 54 | present | Fast BSS Transition (802.11r) | `has_11r` |
| 54 | bytes 0–1 | Mobility Domain ID | `mdid` |

These are stored as boolean columns and displayed as `11k`, `11v`, `11r` badges in the AP table.

### Hotspot 2.0 / Passpoint — `_hotspot20_from_ies()`

| IE | ID | What it signals |
|----|----|----------------|
| Interworking | 107 | Hotspot 2.0; low nibble of byte 0 = access network type |
| Roaming Consortium | 111 | Passpoint roaming policy |

Access network types map to strings like `"Private"`, `"Free Public"`, `"Chargeable Public"`. Stored in `aps.is_hotspot20` and `aps.network_type`.

### Mesh Detection — `parse_mesh()`

Presence of **Mesh Configuration IE** (ID 113) indicates the AP is part of an 802.11s mesh network. Stored as boolean `aps.is_mesh`; shown as a `Mesh` badge in the AP table.

### SSID (IE ID 0) — `_get_ssid()`

- Returns the decoded UTF-8 string, replacing non-decodable bytes with `U+FFFD`.
- Empty or null payload → `"Hidden"`.
- Leading/trailing null bytes are stripped.
- SSIDs are also sanitised in `DatabaseManager._sanitize_ssid()`: only printable ASCII (code points 32–126) is kept, truncated to 32 characters.

### Channel (IE ID 3) — `extract_channel()`

1. Walk IE chain for **DS Parameter Set** (ID 3, 1-byte payload) — most reliable source.
2. Fallback: derive channel from `RadioTap.ChannelFrequency` by reverse-lookup in the frequency tables.
3. Final fallback: `self.current_channel` (hopper position at time of capture).

### Channel width — `extract_channel_width()`

Reads two IEs:
- **HT Operation** (ID 61): byte 1 bits [1:0] — `1` or `3` → 40 MHz, `0` or `2` → 20 MHz.
- **VHT Operation** (ID 192): byte 0 — `1` → 80 MHz, `2` → 160 MHz, `3` → 80+80 MHz.

VHT result takes precedence over HT.

### Security — `parse_security()`

1. **RSN IE (ID 48)** — parsed byte-by-byte to find the AKM suite list. AKM type 8 or 18 → `"WPA3"`, otherwise `"WPA2"`.
2. **WPA vendor IE (ID 221, OUI `00:50:f2:01`)** → `"WPA"`.
3. **No RSN/WPA + Privacy capability bit (`cap & 0x10`)** → `"WEP"`.
4. No security indicators → `"Open"`.

Multiple security modes on the same AP are joined with `", "` (e.g. `"WPA2, WPA3"` for transition mode).

---

## BSSID group detection

Modern tri-band routers broadcast multiple BSSIDs for the same network (one per radio). `_link_bssid_group()` heuristically identifies these:

1. Triggered once per MAC (guarded by `self._grouped_macs`).
2. Queries all APs with the same SSID via `fetch_aps_by_ssid()`.
3. Checks that the candidate shares the same **OUI** (first 3 octets) and its **last octet** differs by ≤ 3.
4. Sets the `bssid_group` column to the lexicographically smallest MAC in the group.

The frontend's `mergeAPs()` uses `bssid_group` to merge these into a single logical AP entry in the tables and graphs.

---

## Signal strength

`_signal(packet)` reads `RadioTap.dBm_AntSignal` (a signed integer, typically −90 to −30 dBm). Returns `None` if the RadioTap layer is absent or the attribute is missing. `None` signals are stored as `NULL` in the database and are excluded from signal history.

---

## Vendor and device enrichment

For every new device, `WiFiMonitor` calls:

1. `get_device_info(mac, self.known_devices)` — synchronous prefix match against `MAC_Address_Device_List.csv`.
2. `self.vendor_resolver.lookup(mac)` — returns immediately from cache or `"Unknown"` while queuing a background API lookup.

Both results are stored on the first insert. The vendor is **not** re-fetched on subsequent updates (the `ON CONFLICT … DO UPDATE` clause does not update the `vendor` column), but it will be correct once the background resolution completes and the next beacon triggers an upsert.

---

## Database upsert logic

### APs (`insert_or_update_ap`)

On conflict (MAC already known):
- `ssid` is **only updated** if the current value is a hidden-placeholder (`"Hidden"`, `"Undetected"`, etc.) and the new value is not.
- `channel`, `frequency`, `signal_strength`, `security` are always overwritten.
- `count` is **incremented** by the incoming count (always 1 per frame).
- `channel_width` and `band` are overwritten only if the incoming value is non-empty.
- `last_seen` is always updated; `first_seen` is preserved.

### Clients (`insert_or_update_client`)

- If the MAC is already in `aps`, any stale client row is deleted and the insert is skipped (avoids double-counting the same hardware).
- `associated_ap` is updated only when the new BSSID is not the broadcast address `ff:ff:ff:ff:ff:ff`.
- On disassociation/deauthentication, `associated_ap` is set to `NULL`.

---

## Probe SSID tracking

When a device sends a Probe Request with a specific SSID (not the wildcard broadcast), DeviceWatcher records it in the `probe_requests` table via `db_manager.insert_probe_request(mac, ssid, timestamp)`. This reveals the device's **Preferred Network List (PNL)** — historical SSIDs it has previously connected to.

Probe entries are displayed in the **Probe SSIDs** section of the dashboard. The table shows the client MAC, the vendor resolved from that MAC, the probed SSID name, and when it was last seen.

Wildcard probes (`ssid == "Hidden"`) are silently dropped — only named SSIDs are recorded.

---

## Limitations

- **Passive only** — no active probing or injection.
- **2.4 GHz frames are captured most frequently** because the 2.4 GHz channels (13) take ~2 s to cycle vs ~12.5 s for all 5/6 GHz channels.
- **SSID is only known from beacons/probe responses** — clients discovered only from data frames will have `ssid = "Hidden or Undetected"` until a beacon is seen on the same BSSID.
- **Encrypted payload** — data frame contents are not decrypted; only MAC-layer metadata is captured.
- **Randomised MACs** — many modern devices use MAC randomisation for probe requests. These appear as short-lived clients and cannot be correlated across sessions.
