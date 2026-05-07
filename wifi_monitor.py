"""
@file wifi_monitor.py
@brief 802.11 passive packet-capture monitor for DeviceWatcher.

Sniffs raw Wi-Fi frames using scapy in monitor mode and persists access points,
clients, and probe requests to the database.  A channel-hopping thread cycles
through 2.4 GHz, 5 GHz, and 6 GHz channels using ``iw``.

@license MIT — see LICENSE for details.
"""

import logging
import subprocess
import threading
import time
from datetime import datetime
from collections import OrderedDict

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap

from database_manager import DatabaseManager
from utils import VendorResolver, get_device_info


_PACKET_ERROR_LOG_EVERY = 500


class WiFiMonitor:
    """Passive 802.11 monitor that persists observed APs and clients.

    Start the monitor by calling :meth:`start_sniffing` from a daemon thread.
    Channel hopping is managed internally by a second daemon thread.

    @param db_manager      Shared :class:`DatabaseManager` instance.
    @param vendor_resolver Shared :class:`VendorResolver` instance.
    @param known_devices   Dict returned by :func:`~utils.load_known_devices`.
    """

    # 2.4 GHz channel → centre frequency (MHz)
    _FREQ_2G: dict[int, int] = {
        1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432, 6: 2437,
        7: 2442, 8: 2447, 9: 2452, 10: 2457, 11: 2462, 12: 2467, 13: 2472,
    }
    # 5 GHz channel → centre frequency (MHz)
    _FREQ_5G: dict[int, int] = {
        36: 5180, 40: 5200, 44: 5220, 48: 5240,
        52: 5260, 56: 5280, 60: 5300, 64: 5320,
        100: 5500, 104: 5520, 108: 5540, 112: 5560, 116: 5580,
        120: 5600, 124: 5620, 128: 5640, 132: 5660, 136: 5680, 140: 5700, 144: 5720,
        149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825,
    }
    # 6 GHz channels (Wi-Fi 6E) — channels 1, 5, 9, … 233
    _FREQ_6G: dict[int, int] = {ch: 5950 + ch * 5 for ch in range(1, 234, 4)}
    _ALL_CHANNELS: list[int] = list(_FREQ_2G) + list(_FREQ_5G) + list(_FREQ_6G)

    # Interworking IE access-network type codes
    _ACCESS_TYPES: dict[int, str] = {
        0: 'Private', 1: 'Private w/ Guest', 2: 'Chargeable Public',
        3: 'Free Public', 4: 'Personal Device', 5: 'Emergency Services',
    }

    def __init__(self, db_manager: DatabaseManager, vendor_resolver: VendorResolver,
                 known_devices: dict):
        self.db_manager       = db_manager
        self.vendor_resolver  = vendor_resolver
        self.known_devices    = known_devices
        self.current_channel  = 1
        self._stop_hopping    = threading.Event()
        self._stop_sniffing   = threading.Event()
        self._grouped_macs: OrderedDict[str, None] = OrderedDict()
        self._packet_errors   = 0
        self.logger           = logging.getLogger("WiFiMonitor")
        self.hopping_paused   = False
        self.dwell_time       = 0.15   # seconds per channel
        self.band_filter      = 'all'  # 'all' | '2.4' | '5' | '6'
        self.interface        = ""
        self._traffic_tracker: dict = {}
        self._packet_listeners: set = set()

    # ------------------------------------------------------------------ public

    def start_sniffing(self, interface: str) -> None:
        """Begin passive packet capture and channel hopping on *interface*.

        Blocks until :meth:`stop_sniffing` is called or scapy raises an
        unrecoverable error.  Channel hopping is performed by an internal
        daemon thread that is joined on exit.

        @param interface  Name of the monitor-mode Wi-Fi interface (e.g. ``wlan1mon``).
        """
        self.interface = interface
        self.logger.info("Starting packet sniffing on %s", interface)
        hopper = threading.Thread(target=self._channel_hopper, args=(interface,), daemon=True)
        hopper.start()
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: self._stop_sniffing.is_set(),
            )
        except Exception as exc:
            self.logger.error("Sniffing stopped: %s", exc)
        finally:
            self._stop_hopping.set()
            hopper.join()

    def stop_sniffing(self) -> None:
        """Signal both the sniffer and the channel hopper to stop."""
        self._stop_sniffing.set()
        self._stop_hopping.set()
        self.logger.info("Wi-Fi sniffing stopping…")

    def register_packet_listener(self, q) -> None:
        """Register a queue to receive live packet-summary dicts.

        @param q  A ``queue.Queue`` instance (maxsize recommended).
        """
        self._packet_listeners.add(q)

    def unregister_packet_listener(self, q) -> None:
        """Deregister a previously registered packet listener.

        @param q  The queue instance to remove.
        """
        self._packet_listeners.discard(q)

    # ------------------------------------------------------------------ channel hopping

    def _channel_hopper(self, interface: str) -> None:
        """Cycle through channels at :attr:`dwell_time` intervals using ``iw``.

        Respects :attr:`band_filter` and :attr:`hopping_paused` at each
        iteration.  Stops when ``_stop_hopping`` is set.

        @param interface  Monitor-mode interface name.
        """
        self.logger.info("Channel hopping started")
        while not self._stop_hopping.is_set():
            if self.hopping_paused:
                time.sleep(0.5)
                continue
            band = self.band_filter
            if band == '2.4':
                channels = list(self._FREQ_2G)
            elif band == '5':
                channels = list(self._FREQ_5G)
            elif band == '6':
                channels = list(self._FREQ_6G)
            else:
                channels = self._ALL_CHANNELS
            for ch in channels:
                if self._stop_hopping.is_set() or self.hopping_paused:
                    break
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(ch)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self.current_channel = ch
                time.sleep(self.dwell_time)

    # ------------------------------------------------------------------ packet dispatch

    def packet_handler(self, packet) -> None:
        """Top-level scapy callback; dispatches frames to type-specific handlers.

        Errors are counted and logged at rate-limited intervals to avoid log
        floods from persistent malformed sources.

        @param packet  Raw scapy packet object.
        """
        try:
            if not packet.haslayer(Dot11):
                return

            dot11   = packet[Dot11]
            mac     = dot11.addr2
            if not self._valid_mac(mac):
                return

            ptype   = dot11.type
            subtype = dot11.subtype

            if self._packet_listeners:
                self._dispatch_to_listeners(packet, dot11, mac, ptype, subtype)

            if ptype == 0:   # Management
                bssid = dot11.addr3
                if   subtype == 8:  self.handle_beacon(packet, mac)
                elif subtype == 4:  self._handle_probe_request(packet, mac, bssid)
                elif subtype == 5:  self.handle_probe_response(packet, mac)
                elif subtype == 0:  self._upsert_client(packet, mac, bssid, "Association request")
                elif subtype == 1:  self.handle_association_response(packet, mac, bssid)
                elif subtype == 2:  self._upsert_client(packet, mac, bssid, "Reassociation request")
                elif subtype == 3:  self.handle_association_response(packet, mac, bssid)
                elif subtype == 10: self.handle_disassociation(packet, mac, bssid)
                elif subtype == 11: self.handle_authentication(packet, mac, bssid)
                elif subtype == 12: self.handle_deauthentication(packet, mac, bssid)
                elif subtype == 13: self.handle_action(packet, mac, bssid)
                return

            if ptype == 2:   # Data
                fc      = dot11.FCfield
                to_ds   = fc & 0x1
                from_ds = (fc & 0x2) >> 1
                if to_ds == 1 and from_ds == 1:
                    self.logger.debug("WDS frame: %s <-> %s", mac, dot11.addr1)
                elif from_ds == 1 and to_ds == 0:
                    if not self.db_manager.ap_exists(mac):
                        self.add_minimal_ap(mac, self.get_frequency(self.current_channel))
                    else:
                        self.db_manager.update_ap_last_seen(mac, self._now())
                elif to_ds == 1 and from_ds == 0:
                    self.handle_client(packet, mac, dot11.addr3)
                return

            if ptype == 1:   # Control
                if subtype == 5:          self.handle_ps_poll(packet, mac, dot11.addr1)
                elif subtype in (8, 9):   self.handle_block_ack(packet, mac, dot11.addr1)

        except Exception as exc:
            self._packet_errors += 1
            if self._packet_errors == 1 or self._packet_errors % _PACKET_ERROR_LOG_EVERY == 0:
                self.logger.warning(
                    "Error processing packet (%d so far): %s",
                    self._packet_errors, exc,
                )

    # ------------------------------------------------------------------ live-feed dispatch

    def _dispatch_to_listeners(self, packet, dot11, mac: str, ptype: int, subtype: int) -> None:
        """Build a packet summary dict and push it to all registered listener queues.

        Errors are logged at DEBUG level rather than silenced so that bugs in
        summary construction surface during development.

        @param packet   Raw scapy packet.
        @param dot11    Dot11 layer extracted from *packet*.
        @param mac      Source MAC address string.
        @param ptype    Dot11 frame type integer (0=mgmt, 1=ctrl, 2=data).
        @param subtype  Dot11 frame subtype integer.
        """
        try:
            info = ""
            if ptype == 0:
                mgmt_types = {
                    0: "Assoc Req", 1: "Assoc Resp", 2: "Reassoc Req", 3: "Reassoc Resp",
                    4: "Probe Req", 5: "Probe Resp", 8: "Beacon",
                    10: "Disassoc", 11: "Auth", 12: "Deauth", 13: "Action",
                }
                type_str = mgmt_types.get(subtype, f"Mgt({subtype})")
                if subtype in (8, 5, 4):
                    info = self._get_ssid(packet)
            elif ptype == 1:
                ctrl_types = {5: "PS-Poll", 8: "Block Ack Req", 9: "Block Ack"}
                type_str = ctrl_types.get(subtype, f"Ctrl({subtype})")
            else:
                data_types = {0: "Data", 4: "Null", 8: "QoS Data", 12: "QoS Null"}
                type_str = data_types.get(subtype, f"Data({subtype})")

            summary = {
                "time":    datetime.now().strftime('%H:%M:%S.%f')[:-3],
                "type":    type_str,
                "src":     mac,
                "dst":     dot11.addr1 if hasattr(dot11, 'addr1') and dot11.addr1 else "",
                "bssid":   dot11.addr3 if hasattr(dot11, 'addr3') and dot11.addr3 else "",
                "signal":  self._signal(packet),
                "info":    info,
                "channel": self.current_channel,
            }

            for q in list(self._packet_listeners):
                try:
                    q.put_nowait(summary)
                except Exception:
                    pass
        except Exception as exc:
            self.logger.debug("_dispatch_to_listeners error: %s", exc)

    # ------------------------------------------------------------------ helpers

    def _valid_mac(self, mac) -> bool:
        """Return True when *mac* is a well-formed, non-broadcast MAC address.

        @param mac  Value to validate (expected: colon-separated hex string).
        @return     True when *mac* is a unicast 48-bit MAC address.
        """
        if not mac or not isinstance(mac, str):
            return False
        mac = mac.lower()
        if mac == 'ff:ff:ff:ff:ff:ff':
            return False
        parts = mac.split(':')
        if len(parts) != 6:
            return False
        try:
            return all(0 <= int(b, 16) <= 255 for b in parts)
        except ValueError:
            return False

    def _now(self) -> str:
        """Return the current local time as an ISO-8601 datetime string.

        @return  String in the format ``YYYY-MM-DD HH:MM:SS``.
        """
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _signal(self, packet) -> int | None:
        """Extract the RSSI from a RadioTap header, if present.

        @param packet  Raw scapy packet.
        @return        RSSI in dBm, or ``None`` when no RadioTap layer exists.
        """
        if packet.haslayer(RadioTap):
            return getattr(packet[RadioTap], 'dBm_AntSignal', None)
        return None

    def _device_info(self, mac: str) -> tuple[str, str, str]:
        """Look up brand, device type, and models for *mac* in the known-devices CSV.

        @param mac  MAC address string.
        @return     ``(brand, device_type, specific_models)`` triple.
        """
        return get_device_info(mac, self.known_devices)

    def _get_ssid(self, packet) -> str:
        """Extract the SSID from a beacon or probe frame's IE chain.

        @param packet  Raw scapy packet containing at least one Dot11Elt.
        @return        SSID string, or ``"Hidden"`` when the SSID IE is absent
                       or empty.
        """
        return self._ssid_from_ies(self._build_ie_map(packet))

    @staticmethod
    def _build_ie_map(packet) -> dict[int, list[bytes]]:
        """Walk the Dot11Elt chain once and return a ``{ie_id: [info_bytes, …]}`` map.

        Multiple IEs may share the same ID (vendor-specific 221, extension 255),
        so each ID maps to a list of raw payloads.

        @param packet  Scapy packet with a Dot11Elt layer.
        @return        Dict mapping IE ID integers to lists of raw payload bytes.
        """
        ies: dict[int, list[bytes]] = {}
        ie = packet.getlayer(Dot11Elt)
        while ie:
            ies.setdefault(ie.ID, []).append(bytes(ie.info or b''))
            ie = ie.payload.getlayer(Dot11Elt)
        return ies

    @staticmethod
    def _ssid_from_ies(ies: dict[int, list[bytes]]) -> str:
        """Extract the SSID string from a pre-built IE map.

        @param ies  IE map as returned by :meth:`_build_ie_map`.
        @return     SSID string; ``"Hidden"`` when IE 0 is absent or zero-length.
        """
        for info in ies.get(0, []):
            if not info:
                return 'Hidden'
            ssid = info.strip(b'\x00').decode('utf-8', errors='replace').strip()
            return ssid if ssid else 'Hidden'
        return 'Hidden'

    def get_frequency(self, channel: int) -> int:
        """Return the centre frequency in MHz for *channel*.

        Falls back to :attr:`current_channel` when *channel* is not found in any
        band table, and returns 0 when that also fails.

        @param channel  802.11 channel number.
        @return         Centre frequency in MHz, or 0 when unknown.
        """
        for table in (self._FREQ_2G, self._FREQ_5G, self._FREQ_6G):
            if channel in table:
                return table[channel]
        for table in (self._FREQ_2G, self._FREQ_5G, self._FREQ_6G):
            if self.current_channel in table:
                return table[self.current_channel]
        return 0

    def _band(self, channel: int) -> str:
        """Return the band string for *channel*: ``"2.4"``, ``"5"``, ``"6"``, or ``""``.

        @param channel  802.11 channel number.
        @return         Band label string.
        """
        if channel in self._FREQ_2G:
            return "2.4"
        if channel in self._FREQ_5G:
            return "5"
        if channel in self._FREQ_6G:
            return "6"
        return ""

    def extract_channel(self, packet, ies: dict | None = None) -> int:
        """Determine the operating channel from a packet's DS Parameter Set IE or RadioTap.

        @param packet  Raw scapy packet.
        @param ies     Pre-built IE map (avoids re-walking the IE chain).
        @return        Channel number, falling back to :attr:`current_channel`.
        """
        if ies is None:
            ies = self._build_ie_map(packet)
        for info in ies.get(3, []):
            if len(info) >= 1:
                return info[0]
        if packet.haslayer(RadioTap):
            freq = getattr(packet[RadioTap], 'ChannelFrequency', None)
            if freq:
                for table in (self._FREQ_2G, self._FREQ_5G, self._FREQ_6G):
                    for ch, f in table.items():
                        if f == freq:
                            return ch
        return self.current_channel

    @staticmethod
    def _channel_width_from_ies(ies: dict[int, list[bytes]]) -> str:
        """Parse HT Operation (IE 61) and VHT Operation (IE 192) for channel width.

        @param ies  Pre-built IE map.
        @return     Channel width string: ``"20"``, ``"40"``, ``"80"``,
                    ``"160"``, ``"80+80"``, or ``""`` when indeterminate.
        """
        ht_width = vht_width = ""
        for info in ies.get(61, []):
            if len(info) >= 2:
                sec_offset = info[1] & 0x3
                ht_width = "40" if sec_offset in (1, 3) else "20"
        for info in ies.get(192, []):
            if len(info) >= 1:
                cw = info[0]
                if cw == 1:   vht_width = "80"
                elif cw == 2: vht_width = "160"
                elif cw == 3: vht_width = "80+80"
        return vht_width or ht_width

    @staticmethod
    def _security_from_ies(ies: dict[int, list[bytes]], packet) -> str:
        """Determine the security suite(s) advertised by an AP.

        Inspects RSN IE (48), WPA vendor IE (221 with Microsoft OUI), and the
        Capability field in Beacon / Probe Response for WEP.

        @param ies     Pre-built IE map.
        @param packet  Raw scapy packet (needed for Capability field).
        @return        Comma-separated security string, e.g. ``"WPA2"``, or
                       ``"Open"`` when no security is advertised.
        """
        security: list[str] = []
        for data in ies.get(48, []):
            try:
                offset = 6
                pc = int.from_bytes(data[offset:offset + 2], 'little')
                offset += 2 + pc * 4
                akm_count = int.from_bytes(data[offset:offset + 2], 'little')
                offset += 2
                wpa3 = any(
                    data[offset + i * 4: offset + i * 4 + 4][3] in (8, 18)
                    for i in range(akm_count)
                )
                security.append('WPA3' if wpa3 else 'WPA2')
            except Exception:
                security.append('WPA2')
        for data in ies.get(221, []):
            if data[:4] == b'\x00\x50\xf2\x01':
                security.append('WPA')
        if not security:
            cap = None
            if packet.haslayer(Dot11Beacon):
                cap = packet[Dot11Beacon].cap
            elif packet.haslayer(Dot11ProbeResp):
                cap = packet[Dot11ProbeResp].cap
            if cap is not None and (cap & 0x10):
                security.append('WEP')
        return ', '.join(security) if security else 'Open'

    # ------------------------------------------------------------------ IE-map parsers

    def _wifi_generation_from_ies(self, ies: dict[int, list[bytes]]) -> str | None:
        """Infer Wi-Fi generation from HT/VHT/HE/EHT capability IEs.

        @param ies  Pre-built IE map.
        @return     Human label such as ``"Wi-Fi 6"`` or ``"b/g"``.
        """
        has_ht  = bool(ies.get(45))
        has_vht = bool(ies.get(191))
        has_he  = any(info and info[0] == 35  for info in ies.get(255, []))
        has_eht = any(info and info[0] == 107 for info in ies.get(255, []))
        if has_eht: return 'Wi-Fi 7'
        if has_he:  return 'Wi-Fi 6E' if self.current_channel in self._FREQ_6G else 'Wi-Fi 6'
        if has_vht: return 'Wi-Fi 5'
        if has_ht:  return 'Wi-Fi 4'
        return 'b/g'

    @staticmethod
    def _spatial_streams_from_ies(ies: dict[int, list[bytes]]) -> int | None:
        """Infer the maximum number of spatial streams from HT/VHT capability IEs.

        @param ies  Pre-built IE map.
        @return     Number of spatial streams (1–8), or ``None`` when not determinable.
        """
        ht_nss = vht_nss = None
        for info in ies.get(45, []):
            if len(info) >= 7:
                nss = 0
                for i in range(4):
                    if info[3 + i] != 0:
                        nss = i + 1
                ht_nss = nss if nss else 1
        for info in ies.get(191, []):
            if len(info) >= 6:
                rx_mcs = int.from_bytes(info[4:6], 'little')
                nss = sum(1 for i in range(8) if (rx_mcs >> (i * 2)) & 0x3 != 0x3)
                vht_nss = nss if nss else None
        return vht_nss or ht_nss

    @staticmethod
    def _country_code_from_ies(ies: dict[int, list[bytes]]) -> str | None:
        """Extract the ISO 3166-1 alpha-2 country code from Country IE (7).

        @param ies  Pre-built IE map.
        @return     Two-letter uppercase country code, or ``None``.
        """
        for info in ies.get(7, []):
            if len(info) >= 2:
                try:
                    cc = info[:2].decode('ascii', errors='ignore').strip()
                    if len(cc) == 2 and cc.replace(' ', '').isalpha():
                        return cc.strip().upper()
                except Exception:
                    pass
        return None

    @staticmethod
    def _bss_load_from_ies(ies: dict[int, list[bytes]]) -> tuple[int | None, int | None]:
        """Parse the BSS Load IE (11) for station count and channel utilisation.

        @param ies  Pre-built IE map.
        @return     ``(station_count, channel_utilisation_pct)`` tuple.  Both
                    values are ``None`` when the IE is absent.
        """
        for info in ies.get(11, []):
            if len(info) >= 3:
                station_count = int.from_bytes(info[0:2], 'little')
                channel_util  = round(info[2] / 2.55)   # 0-255 maps to 0-100 %
                return station_count, channel_util
        return None, None

    @staticmethod
    def _pmf_from_ies(ies: dict[int, list[bytes]]) -> str:
        """Determine Protected Management Frames (PMF) status from the RSN IE caps field.

        @param ies  Pre-built IE map.
        @return     ``"Required"``, ``"Capable"``, ``"Disabled"``, or ``""`` when
                    no RSN IE is present.
        """
        for data in ies.get(48, []):
            try:
                offset = 2 + 4
                if offset + 2 > len(data): continue
                pc = int.from_bytes(data[offset:offset + 2], 'little')
                offset += 2 + pc * 4
                if offset + 2 > len(data): continue
                akm_count = int.from_bytes(data[offset:offset + 2], 'little')
                offset += 2 + akm_count * 4
                if offset + 2 > len(data): continue
                caps = int.from_bytes(data[offset:offset + 2], 'little')
                if (caps >> 6) & 1: return 'Required'
                if (caps >> 7) & 1: return 'Capable'
                return 'Disabled'
            except Exception:
                continue
        return ''

    @staticmethod
    def _extended_caps_from_ies(ies: dict[int, list[bytes]]) -> tuple[bool, bool, bool, str | None]:
        """Parse Extended Capabilities IE (127) and Mobility Domain IE (54).

        @param ies  Pre-built IE map.
        @return     ``(has_11k, has_11v, has_11r, mdid)`` tuple.
        """
        has_11k = has_11v = has_11r = False
        mdid = None
        for info in ies.get(127, []):
            if not info: continue
            if len(info) > 2 and (info[2] & 0x08):   # bit 19 → BSS Transition (11v)
                has_11v = True
            if len(info) > 4 and (info[4] & 0x08):   # bit 35 → RRM (11k)
                has_11k = True
        for info in ies.get(54, []):
            if len(info) >= 2:
                has_11r = True
                mdid = info[:2].hex().upper()
        return has_11k, has_11v, has_11r, mdid

    def _hotspot20_from_ies(self, ies: dict[int, list[bytes]]) -> tuple[bool, str]:
        """Detect Passpoint / Hotspot 2.0 support from Interworking (107) and HS 2.0 (111) IEs.

        @param ies  Pre-built IE map.
        @return     ``(is_hotspot20, network_type)`` tuple.
        """
        network_type = ''
        is_hs20 = False
        for info in ies.get(107, []):
            if info:
                ant = info[0] & 0x0F
                network_type = self._ACCESS_TYPES.get(ant, 'Unknown')
                is_hs20 = True
        if 111 in ies:
            is_hs20 = True
        return is_hs20, network_type

    @staticmethod
    def _is_mesh_from_ies(ies: dict[int, list[bytes]]) -> bool:
        """Return True when the Mesh Configuration IE (113) is present.

        @param ies  Pre-built IE map.
        @return     True for IEEE 802.11s mesh networks.
        """
        return 113 in ies

    # ------------------------------------------------------------------ BSSID grouping

    def _link_bssid_group(self, mac: str, ssid: str) -> None:
        """Group BSSIDs from the same physical AP when they share an SSID and OUI.

        Two BSSIDs are considered part of the same AP when:
          - they advertise the same SSID,
          - the first 3 octets (OUI) match,
          - the last octet differs by at most 3.

        The lowest MAC in the group is designated the group representative.

        @param mac   BSSID to evaluate.
        @param ssid  SSID advertised by *mac*.
        """
        _hidden = {'Hidden', 'Undetected', 'Hidden SSID', 'Hidden or Undetected', ''}
        if not ssid or ssid in _hidden:
            return
        rows = self.db_manager.fetch_aps_by_ssid(ssid)
        if len(rows) < 2:
            return
        mac_parts = mac.lower().split(':')
        if len(mac_parts) != 6:
            return
        group = [mac]
        for (cand_mac,) in rows:
            if cand_mac == mac:
                continue
            cand = cand_mac.lower().split(':')
            if len(cand) != 6:
                continue
            if (cand[:3] == mac_parts[:3]
                    and abs(int(cand[5], 16) - int(mac_parts[5], 16)) <= 3):
                group.append(cand_mac)
        if len(group) < 2:
            return
        group_mac = min(group)
        for member in group:
            self.db_manager.set_bssid_group(member, group_mac)
        self.logger.info("BSSID group [%s]: %s", group_mac, group)

    # ------------------------------------------------------------------ shared upsert helpers

    def _handle_ap_frame(self, packet, mac: str) -> None:
        """Extract AP metadata from a beacon or probe-response frame and persist it.

        @param packet  Raw scapy packet.
        @param mac     BSSID (addr2) of the transmitting AP.
        """
        ies           = self._build_ie_map(packet)
        ssid          = self._ssid_from_ies(ies)
        channel       = self.extract_channel(packet, ies)
        freq          = self.get_frequency(channel)
        sig           = self._signal(packet)
        security      = self._security_from_ies(ies, packet)
        channel_width = self._channel_width_from_ies(ies)
        band          = self._band(channel)
        wifi_gen      = self._wifi_generation_from_ies(ies)
        streams       = self._spatial_streams_from_ies(ies)
        country       = self._country_code_from_ies(ies)
        sta_count, ch_util = self._bss_load_from_ies(ies)
        pmf           = self._pmf_from_ies(ies)
        k, v, r, mdid = self._extended_caps_from_ies(ies)
        hs20, net_type = self._hotspot20_from_ies(ies)
        is_mesh       = self._is_mesh_from_ies(ies)
        now           = self._now()
        brand, device_type, specific_models = self._device_info(mac)
        self.db_manager.insert_or_update_ap(
            mac_address=mac, ssid=ssid,
            vendor=self.vendor_resolver.lookup(mac),
            brand=brand, device_type=device_type, specific_models=specific_models,
            channel=channel, frequency=freq, signal_strength=sig,
            security=security, count=1, first_seen=now, last_seen=now,
            channel_width=channel_width, band=band,
            wifi_generation=wifi_gen, spatial_streams=streams,
            country_code=country, station_count=sta_count,
            channel_utilization=ch_util, pmf=pmf,
            has_11k=k, has_11v=v, has_11r=r, mdid=mdid,
            is_hotspot20=hs20, network_type=net_type, is_mesh=is_mesh,
        )
        if mac not in self._grouped_macs:
            self._link_bssid_group(mac, ssid)
            self._grouped_macs[mac] = None
            if len(self._grouped_macs) > 5000:
                for _ in range(2500):
                    self._grouped_macs.popitem(last=False)

    def _upsert_client(self, packet, mac: str, bssid, label: str = '') -> None:
        """Upsert a client record derived from any management or data frame.

        @param packet  Raw scapy packet.
        @param mac     Client MAC address (addr2).
        @param bssid   BSSID of the associated AP (addr3), or broadcast.
        @param label   Optional log label for the triggering frame type.
        """
        sig    = self._signal(packet)
        now    = self._now()
        ap_ref = bssid if self._valid_mac(bssid) else None
        brand, device_type, specific_models = self._device_info(mac)
        if label:
            self.logger.info("%s: %s → %s sig=%s", label, mac, bssid, sig)
        self.db_manager.insert_or_update_client(
            mac_address=mac, associated_ap=ap_ref,
            vendor=self.vendor_resolver.lookup(mac),
            brand=brand, device_type=device_type, specific_models=specific_models,
            signal_strength=sig, count=1, first_seen=now, last_seen=now,
        )

    # ------------------------------------------------------------------ probe request handler

    def _handle_probe_request(self, packet, mac: str, bssid) -> None:
        """Handle a Probe Request frame: upsert client and record the probed SSID.

        @param packet  Raw scapy packet.
        @param mac     Client MAC address (addr2).
        @param bssid   Destination address (addr3); typically broadcast.
        """
        self._upsert_client(packet, mac, bssid, "Probe request")
        ssid    = self._get_ssid(packet)
        channel = self.extract_channel(packet) or self.current_channel
        if ssid and ssid != 'Hidden':
            self.db_manager.insert_probe_request(mac, ssid, str(channel), self._now())

    # ------------------------------------------------------------------ AP handlers

    def handle_beacon(self, packet, mac: str) -> None:
        """Handle an 802.11 Beacon frame.

        @param packet  Raw scapy packet.
        @param mac     BSSID (addr2).
        """
        ssid    = self._get_ssid(packet)
        channel = self.extract_channel(packet)
        self.logger.info("Beacon: %s (%s) ch=%s sig=%s", ssid, mac, channel, self._signal(packet))
        self._handle_ap_frame(packet, mac)

    def handle_probe_response(self, packet, mac: str) -> None:
        """Handle an 802.11 Probe Response frame.

        @param packet  Raw scapy packet.
        @param mac     BSSID (addr2).
        """
        self._handle_ap_frame(packet, mac)

    def add_minimal_ap(self, mac: str, freq: int) -> None:
        """Insert a stub AP record for a BSSID seen only in data frames.

        @param mac   BSSID of the AP.
        @param freq  Inferred centre frequency in MHz.
        """
        if not self._valid_mac(mac):
            return
        now  = self._now()
        band = self._band(self.current_channel)
        brand, device_type, specific_models = self._device_info(mac)
        self.db_manager.insert_or_update_ap(
            mac_address=mac, ssid='Hidden or Undetected',
            vendor=self.vendor_resolver.lookup(mac),
            brand=brand, device_type=device_type, specific_models=specific_models,
            channel=self.current_channel, frequency=freq, signal_strength=None,
            security='Unknown', count=0, first_seen=now, last_seen=now,
            channel_width="", band=band,
        )

    def handle_association_response(self, packet, mac: str, bssid) -> None:
        """Handle an Association or Reassociation Response frame.

        Records the client (bssid) as associated with the responding AP (mac).

        @param packet  Raw scapy packet.
        @param mac     AP BSSID (addr2).
        @param bssid   Client MAC address (addr3).
        """
        if not self._valid_mac(bssid):
            return
        now   = self._now()
        brand, device_type, specific_models = self._device_info(bssid)
        self.db_manager.insert_or_update_client(
            mac_address=bssid, associated_ap=mac,
            vendor=self.vendor_resolver.lookup(bssid),
            brand=brand, device_type=device_type, specific_models=specific_models,
            signal_strength=self._signal(packet), count=1, first_seen=now, last_seen=now,
        )

    def handle_disassociation(self, packet, mac: str, bssid) -> None:
        """Handle a Disassociation frame.

        @param packet  Raw scapy packet.
        @param mac     Source MAC (addr2).
        @param bssid   BSSID / destination (addr3).
        """
        now = self._now()
        self.logger.info("Disassociation: %s <-> %s", mac, bssid)
        if mac == bssid:
            client = packet[Dot11].addr1
            if self._valid_mac(client):
                self.db_manager.update_client_disassociation(client, now)
        else:
            self.db_manager.update_client_disassociation(mac, now)

    def handle_deauthentication(self, packet, mac: str, bssid) -> None:
        """Handle a Deauthentication frame.

        @param packet  Raw scapy packet.
        @param mac     Source MAC (addr2).
        @param bssid   BSSID / destination (addr3).
        """
        now = self._now()
        self.logger.info("Deauthentication: %s <-> %s", mac, bssid)
        if mac == bssid:
            client = packet[Dot11].addr1
            if self._valid_mac(client):
                self.db_manager.update_client_deauthentication(client, now)
        else:
            self.db_manager.update_client_deauthentication(mac, now)

    def handle_authentication(self, packet, mac: str, bssid) -> None:
        """Handle an Authentication frame.

        When the frame is an AP response (mac == bssid), upsert the client and
        ensure the AP stub exists.  Otherwise treat as a client authentication
        request and upsert only the client.

        @param packet  Raw scapy packet.
        @param mac     Source MAC (addr2).
        @param bssid   BSSID / destination (addr3).
        """
        if mac == bssid:
            client_mac = packet[Dot11].addr1
            if self._valid_mac(client_mac):
                self.logger.info("Authentication response: AP=%s client=%s", mac, client_mac)
                now   = self._now()
                brand, device_type, specific_models = self._device_info(client_mac)
                self.db_manager.insert_or_update_client(
                    mac_address=client_mac, associated_ap=mac,
                    vendor=self.vendor_resolver.lookup(client_mac),
                    brand=brand, device_type=device_type, specific_models=specific_models,
                    signal_strength=self._signal(packet), count=1, first_seen=now, last_seen=now,
                )
            if not self.db_manager.ap_exists(mac):
                self.add_minimal_ap(mac, self.get_frequency(self.current_channel))
        else:
            self._upsert_client(packet, mac, bssid, "Authentication request")

    def handle_action(self, packet, mac: str, bssid) -> None:
        """Handle an Action frame by refreshing last-seen timestamps.

        @param packet  Raw scapy packet (unused beyond timestamp).
        @param mac     Source MAC (addr2).
        @param bssid   BSSID / destination (addr3).
        """
        now = self._now()
        self.db_manager.update_client_last_seen(mac, now)
        if self._valid_mac(bssid):
            self.db_manager.update_ap_last_seen(bssid, now)

    # ------------------------------------------------------------------ client handlers

    def handle_client(self, packet, mac: str, bssid) -> None:
        """Handle an upstream data frame from a client.

        Tracks per-client byte rates to detect high-bandwidth streaming devices.
        A stub AP record is created when the BSSID is unknown.

        @param packet  Raw scapy packet.
        @param mac     Client MAC address (addr2).
        @param bssid   BSSID (addr3) of the AP receiving the frame.
        """
        ap_ref = bssid if self._valid_mac(bssid) else None
        self.logger.debug("Client data: %s → %s sig=%s", mac, bssid, self._signal(packet))
        if ap_ref and not self.db_manager.ap_exists(ap_ref):
            self.add_minimal_ap(ap_ref, self.get_frequency(self.current_channel))
        now    = self._now()
        brand, device_type, specific_models = self._device_info(mac)

        # Per-client bandwidth tracking for streaming-camera detection.
        now_ts  = time.monotonic()
        tracker = self._traffic_tracker.setdefault(
            mac, {"bytes": 0, "start_time": now_ts, "is_streaming": False}
        )
        tracker["bytes"] += len(packet)

        elapsed = now_ts - tracker["start_time"]
        if elapsed >= 5.0:
            bandwidth_kbps = (tracker["bytes"] / elapsed) / 1024
            is_streaming   = bandwidth_kbps > 50   # 50 KB/s threshold
            if is_streaming != tracker["is_streaming"]:
                tracker["is_streaming"] = is_streaming
                self.db_manager.set_client_streaming_status(mac, is_streaming)
                if is_streaming:
                    self.logger.info(
                        "Detected streaming camera: %s (%.2f KB/s)", mac, bandwidth_kbps
                    )
            tracker["bytes"]      = 0
            tracker["start_time"] = now_ts

        self.db_manager.insert_or_update_client(
            mac_address=mac, associated_ap=ap_ref,
            vendor=self.vendor_resolver.lookup(mac),
            brand=brand, device_type=device_type, specific_models=specific_models,
            signal_strength=self._signal(packet), count=1, first_seen=now, last_seen=now,
        )

    def handle_ps_poll(self, packet, mac: str, bssid) -> None:
        """Handle a PS-Poll control frame.

        Upserts the polling client and ensures the target AP stub exists.

        @param packet  Raw scapy packet.
        @param mac     Client MAC address (addr2).
        @param bssid   AP BSSID from AID field (addr1).
        """
        if not self._valid_mac(bssid):
            return
        self.logger.debug("PS-Poll: %s polling %s", mac, bssid)
        self._upsert_client(packet, mac, bssid)
        if not self.db_manager.ap_exists(bssid):
            self.add_minimal_ap(bssid, self.get_frequency(self.current_channel))

    def handle_block_ack(self, packet, mac: str, bssid) -> None:
        """Handle a Block Ack / Block Ack Request frame by refreshing timestamps.

        @param packet  Raw scapy packet (unused beyond timestamp).
        @param mac     Sender MAC address (addr2).
        @param bssid   Recipient BSSID (addr1).
        """
        if not self._valid_mac(bssid):
            return
        now = self._now()
        self.db_manager.update_client_last_seen(mac, now)
        self.db_manager.update_ap_last_seen(bssid, now)
