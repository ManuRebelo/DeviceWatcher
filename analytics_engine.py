"""
@file analytics_engine.py
@brief Higher-level analytics: radar positioning, occupancy histograms,
       security-threat scanning, and multi-signal entity clustering.
@license MIT — see LICENSE for details.
"""

import hashlib
import logging
import math
import sqlite3
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """Compute analytics and entity clustering over the DeviceWatcher database.

    All methods operate on a shared DatabaseManager instance and are safe to
    call from multiple Flask request threads concurrently (reads only).

    @param db_manager  A DatabaseManager instance providing ``db_manager.conn``.
    """

    def __init__(self, db_manager):
        self.db = db_manager

    # ------------------------------------------------------------------ radar

    def calculate_distance(self, rssi: int | None, tx_power: int | None = None) -> float | None:
        """Estimate distance from RSSI using a log-distance path-loss model.

        @param rssi      Received signal strength in dBm.  ``None`` returns ``None``.
        @param tx_power  Reference RSSI at 1 m (dBm).  Defaults to -59 dBm when
                         not provided by the advertising device.
        @return          Estimated distance in metres rounded to 2 d.p., or
                         ``None`` when the calculation fails.
        """
        if rssi is None:
            return None
        # Path-loss exponent N=2.5 approximates a typical indoor environment
        # (open air = 2.0, heavy obstruction = 4.0).
        n = 2.5
        ref_power = tx_power if tx_power is not None else -59
        try:
            ratio = (ref_power - rssi) / (10 * n)
            return round(math.pow(10, ratio), 2)
        except Exception:
            return None

    def get_radar_data(self) -> list[dict]:
        """Return radar points for all devices seen within the last 5 minutes.

        @return  List of dicts with keys ``mac``, ``type``, ``rssi``,
                 ``distance``, and ``last_seen``.
        """
        c = self.db.conn.cursor()
        c.execute('''
            SELECT mac_address, device_type, MAX(signal_strength), MAX(timestamp)
            FROM signal_readings
            WHERE timestamp >= datetime('now', '-5 minutes')
            GROUP BY mac_address
        ''')
        rows = c.fetchall()

        radar_points: list[dict] = []
        for mac, dev_type, rssi, ts in rows:
            tx_power = None
            if dev_type == 'ble':
                c.execute('SELECT tx_power FROM ble_devices WHERE mac_address=?', (mac,))
                ble_row = c.fetchone()
                if ble_row and ble_row[0] is not None:
                    tx_power = ble_row[0]
            radar_points.append({
                'mac':       mac,
                'type':      dev_type,
                'rssi':      rssi,
                'distance':  self.calculate_distance(rssi, tx_power),
                'last_seen': ts,
            })
        return radar_points

    # ------------------------------------------------------------------ occupancy

    def compute_occupancy(self) -> list[dict]:
        """Bin unique device sightings into 1-hour windows over the last 24 hours.

        @return  Ordered list of ``{"hour": ISO-8601-hour-string, "count": int}``.
        """
        c = self.db.conn.cursor()
        c.execute('''
            SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour,
                   COUNT(DISTINCT mac_address)
            FROM signal_readings
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
        ''')
        return [{"hour": row[0], "count": row[1]} for row in c.fetchall()]

    # ------------------------------------------------------------------ security

    def scan_security_threats(self) -> list[dict]:
        """Scan the observed network for common security anomalies.

        Detects:
          - Deprecated encryption (WEP / TKIP).
          - Open / unencrypted access points.
          - Possible Evil-Twin attacks (same SSID, multiple vendors).
          - High-bandwidth clients that appear to be streaming cameras.

        @return  List of threat dicts, each with ``type``, ``severity``,
                 ``mac``, and ``description`` keys.
        """
        c = self.db.conn.cursor()
        threats: list[dict] = []

        c.execute(
            'SELECT mac_address, ssid, security FROM aps '
            'WHERE security LIKE "%WEP%" OR security LIKE "%TKIP%"'
        )
        for mac, ssid, security in c.fetchall():
            threats.append({
                'type':        'WEAK_ENCRYPTION',
                'severity':    'high',
                'mac':         mac,
                'description': f'AP "{ssid}" is using deprecated security: {security}',
            })

        c.execute('SELECT mac_address, ssid FROM aps WHERE security = "Open" OR security = ""')
        for mac, ssid in c.fetchall():
            threats.append({
                'type':        'OPEN_NETWORK',
                'severity':    'medium',
                'mac':         mac,
                'description': f'AP "{ssid}" is open (no password)',
            })

        c.execute(
            'SELECT ssid, COUNT(DISTINCT mac_address), COUNT(DISTINCT vendor) '
            'FROM aps GROUP BY ssid HAVING COUNT(DISTINCT mac_address) > 1'
        )
        _hidden_ssids = {"Unknown", "Hidden", "Hidden SSID", "Hidden or Undetected"}
        for ssid, _count, vendor_count in c.fetchall():
            if ssid and ssid not in _hidden_ssids and vendor_count > 1:
                threats.append({
                    'type':        'POSSIBLE_EVIL_TWIN',
                    'severity':    'high',
                    'mac':         'Multiple',
                    'description': (
                        f'Multiple different vendors ({vendor_count}) are broadcasting '
                        f'SSID "{ssid}". This may indicate an Evil Twin attack.'
                    ),
                })

        try:
            c.execute('SELECT mac_address, vendor FROM clients WHERE is_streaming = 1')
            for mac, vendor in c.fetchall():
                threats.append({
                    'type':        'LIVE_CAMERA',
                    'severity':    'medium',
                    'mac':         mac,
                    'description': (
                        f'High upstream bandwidth detected. Device ({vendor}) '
                        'appears to be actively streaming video.'
                    ),
                })
        except sqlite3.OperationalError:
            # Column may be absent on databases created before this migration.
            pass

        return threats

    # ------------------------------------------------------------------ clustering

    @staticmethod
    def _is_randomized_mac(mac: str) -> bool:
        """Return True if the MAC has the locally-administered (randomised) bit set.

        iOS 14+, Android 10+, and Windows 10+ use randomised MACs whose first
        octet has bit 1 set.  OUI and adjacent-address signals are unreliable for
        such addresses and are suppressed during scoring.

        @param mac  Colon-separated MAC string, case-insensitive.
        @return     True when the locally-administered bit is set.
        """
        try:
            return bool(int(mac.replace(':', '')[:2], 16) & 0x02)
        except (ValueError, IndexError):
            return False

    def _score_pair(self, a: dict, b: dict,
                    probe_map: dict, ap_assoc_map: dict) -> tuple[float, list[str]]:
        """Compute an affinity score and evidence list for a pair of devices.

        Six independent signals contribute to the score (max 1.00):

        | Signal                        | Weight |
        |-------------------------------|--------|
        | Temporal co-occurrence        | 0.30   |
        | Same OUI prefix               | 0.25   |
        | Adjacent full MAC address     | 0.20   |
        | Shared associated AP          | 0.20   |
        | Shared probe SSIDs (≥ 2)      | 0.15   |
        | Vendor + device-type affinity | 0.10   |
        | iBeacon UUID match (override) | 0.50   |

        @param a             Device-info dict (keys: mac, fs, ls, vendor, type,
                             signal, channel, ssid, src, ibeacon_uuid, randomized).
        @param b             Second device-info dict.
        @param probe_map     Mapping of client_mac → set of probed SSIDs.
        @param ap_assoc_map  Mapping of client_mac → set of associated AP BSSIDs.
        @return              ``(score, evidence)`` tuple where score is in [0, 1]
                             and evidence is a list of human-readable signal labels.
        """
        score: float = 0.0
        evidence: list[str] = []

        # Signal 1 – temporal co-occurrence (weight 0.30)
        if abs(a['fs'] - b['fs']) < 60 and abs(a['ls'] - b['ls']) < 60:
            score += 0.30
            evidence.append('temporal:co-occurrence')

        # Signal 2 – OUI prefix / adjacent address (skipped for randomised MACs)
        if not a['randomized'] and not b['randomized']:
            mac_a = a['mac'].replace(':', '').lower()
            mac_b = b['mac'].replace(':', '').lower()
            if mac_a[:6] == mac_b[:6]:
                score += 0.25
                evidence.append('mac:same-oui')
                try:
                    diff = abs(int(mac_a, 16) - int(mac_b, 16))
                    if 0 < diff <= 2:
                        score += 0.20
                        evidence.append('mac:adjacent-address')
                except ValueError:
                    pass

        # Signal 3 – shared associated AP (weight 0.20)
        shared_aps = ap_assoc_map.get(a['mac'], set()) & ap_assoc_map.get(b['mac'], set())
        if shared_aps:
            score += 0.20
            evidence.append(f'wifi:shared-ap({", ".join(list(shared_aps)[:2])})')

        # Signal 4 – shared probe SSIDs (weight 0.15, requires ≥ 2 matches)
        shared_probes = probe_map.get(a['mac'], set()) & probe_map.get(b['mac'], set())
        if len(shared_probes) >= 2:
            score += 0.15
            evidence.append(f'wifi:shared-probes({len(shared_probes)})')

        # Signal 5 – vendor + device-type affinity (weight 0.10)
        if (a['vendor'] not in ('Unknown', '', None)
                and a['vendor'] == b['vendor']
                and a['type'] not in ('Unknown', '', None)
                and a['type'] == b['type']):
            score += 0.10
            evidence.append('meta:vendor-type-match')

        # Signal 6 – iBeacon UUID match (hard floor 0.50)
        if (a.get('ibeacon_uuid') and b.get('ibeacon_uuid')
                and a['ibeacon_uuid'] == b['ibeacon_uuid']):
            score = max(score, 0.50)
            evidence.append('ble:ibeacon-uuid-match')

        return score, evidence

    def cluster_devices(self, threshold: float = 0.40) -> list[dict]:
        """Cluster all observed devices into likely physical entities.

        Algorithm:
        1. Fetch every device from all four source tables with enriched metadata.
        2. Build probe-SSID and AP-association lookup tables.
        3. Score every device pair via :meth:`_score_pair`.
        4. Union-find merges pairs whose score >= *threshold*.
        5. Return clusters of ≥ 2 devices with evidence and confidence.

        @param threshold  Minimum affinity score [0.05, 0.95] for merging two
                          devices into the same entity.  Default 0.40.
        @return           List of cluster dicts (sorted by size descending).
                          Each dict has keys ``id``, ``name``, ``size``,
                          ``reason``, ``signals``, ``confidence``,
                          ``channels``, ``ssids``, ``devices``.
        """
        c = self.db.conn.cursor()

        # 1. Collect all devices from every source table
        c.execute('''\
            SELECT mac_address, first_seen, last_seen, vendor, device_type,
                   signal_strength, src, ibeacon_uuid
            FROM (
                SELECT mac_address, first_seen, last_seen, vendor, device_type,
                       signal_strength, 'ap'     AS src, NULL AS ibeacon_uuid FROM aps
                UNION ALL
                SELECT mac_address, first_seen, last_seen, vendor, device_type,
                       signal_strength, 'client' AS src, NULL AS ibeacon_uuid FROM clients
                UNION ALL
                SELECT mac_address, first_seen, last_seen, vendor, device_type,
                       signal_strength, 'bt'     AS src, NULL AS ibeacon_uuid FROM bt_classic
                UNION ALL
                SELECT mac_address, first_seen, last_seen, vendor, device_type,
                       signal_strength, 'ble'    AS src, ibeacon_uuid          FROM ble_devices
            )
            WHERE first_seen IS NOT NULL AND last_seen IS NOT NULL
        ''')
        rows = c.fetchall()

        c.execute('SELECT mac_address, channel, ssid FROM aps')
        ap_meta: dict = {r[0]: {'channel': r[1], 'ssid': r[2]} for r in c.fetchall()}

        c.execute(
            'SELECT c.mac_address, a.ssid, a.channel '
            'FROM clients c LEFT JOIN aps a ON c.associated_ap = a.mac_address'
        )
        client_meta: dict = {r[0]: {'ssid': r[1], 'channel': r[2]} for r in c.fetchall()}

        def _to_epoch(dt_str: str) -> float:
            if not dt_str:
                return 0.0
            try:
                return datetime.strptime(dt_str.split('.')[0], '%Y-%m-%d %H:%M:%S').timestamp()
            except Exception:
                return 0.0

        # 2. Build auxiliary lookups
        c.execute('SELECT client_mac, ssid FROM probe_requests')
        probe_map: dict[str, set] = {}
        for client_mac, ssid in c.fetchall():
            probe_map.setdefault(client_mac, set()).add(ssid)

        c.execute(
            'SELECT mac_address, associated_ap FROM clients '
            'WHERE associated_ap IS NOT NULL AND associated_ap != "ff:ff:ff:ff:ff:ff"'
        )
        ap_assoc_map: dict[str, set] = {}
        for mac, ap in c.fetchall():
            ap_assoc_map.setdefault(mac, set()).add(ap)

        parsed: list[dict] = []
        for mac, first_seen, last_seen, vendor, dev_type, signal, src, ibeacon_uuid in rows:
            if src == 'ap':
                extras = ap_meta.get(mac, {})
            elif src == 'client':
                extras = client_meta.get(mac, {})
            else:
                extras = {}
            parsed.append({
                'mac':          mac,
                'fs':           _to_epoch(first_seen),
                'ls':           _to_epoch(last_seen),
                'first_seen':   first_seen or '',
                'last_seen':    last_seen or '',
                'vendor':       vendor or 'Unknown',
                'type':         dev_type or 'Unknown',
                'signal':       signal,
                'channel':      extras.get('channel'),
                'ssid':         extras.get('ssid'),
                'src':          src,
                'ibeacon_uuid': ibeacon_uuid,
                'randomized':   self._is_randomized_mac(mac),
            })

        if len(parsed) > 1000:
            logger.warning(
                'cluster_devices: %d devices exceeds optimised limit of 1000; '
                'results may be slow.', len(parsed)
            )

        # 3 & 4. Score pairs + union-find
        parent = {d['mac']: d['mac'] for d in parsed}
        rank   = {d['mac']: 0        for d in parsed}

        def _find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]  # path compression
                x = parent[x]
            return x

        def _union(x: str, y: str) -> None:
            rx, ry = _find(x), _find(y)
            if rx == ry:
                return
            if rank[rx] < rank[ry]:
                rx, ry = ry, rx
            parent[ry] = rx
            if rank[rx] == rank[ry]:
                rank[rx] += 1

        edge_evidence: dict[str, list[str]] = {}

        n = len(parsed)
        for i in range(n):
            for j in range(i + 1, n):
                a, b = parsed[i], parsed[j]
                score, ev = self._score_pair(a, b, probe_map, ap_assoc_map)
                if score >= threshold:
                    _union(a['mac'], b['mac'])
                    key = _find(a['mac'])
                    edge_evidence.setdefault(key, []).extend(ev)

        # 5. Collect clusters
        groups: dict[str, list[dict]] = {}
        for d in parsed:
            groups.setdefault(_find(d['mac']), []).append(d)

        aliases = self.db.get_entity_aliases()
        clusters: list[dict] = []
        _proto_labels = {
            'ap': 'Wi-Fi AP', 'client': 'Wi-Fi client',
            'bt': 'Bluetooth Classic', 'ble': 'BLE',
        }

        for root, members in groups.items():
            if len(members) < 2:
                continue

            macs = sorted(d['mac'] for d in members)
            cluster_id = hashlib.md5(''.join(macs).encode()).hexdigest()[:12]
            name = aliases.get(cluster_id, f'Entity {cluster_id}')

            unique_signals = sorted(set(edge_evidence.get(root, [])))
            channels  = sorted({str(d['channel']) for d in members if d['channel'] is not None})
            ssids     = sorted({d['ssid'] for d in members if d['ssid']})
            src_types = sorted({d['src'] for d in members})

            fs_min = min(d['fs'] for d in members)
            ls_max = max(d['ls'] for d in members)
            try:
                t_start = datetime.fromtimestamp(fs_min).strftime('%H:%M:%S')
                t_end   = datetime.fromtimestamp(ls_max).strftime('%H:%M:%S')
            except Exception:
                t_start = t_end = '?'

            # reason is rendered as HTML in the frontend dashboard
            reason_parts = [
                f'Active window: <strong>{t_start}</strong> → <strong>{t_end}</strong>.'
            ]
            if ssids:
                reason_parts.append(f'Network(s): <em>{", ".join(ssids)}</em>.')
            if channels:
                reason_parts.append(f'Channel(s): <strong>{", ".join(channels)}</strong>.')
            proto_str = ', '.join(_proto_labels.get(s, s) for s in src_types)
            reason_parts.append(f'Protocols seen: {proto_str}.')

            max_possible = 6
            confidence = min(1.0, len({s.split(':')[0] for s in unique_signals}) / max_possible)

            clusters.append({
                'id':         cluster_id,
                'name':       name,
                'size':       len(members),
                'reason':     ' '.join(reason_parts),
                'signals':    unique_signals,
                'confidence': round(confidence, 2),
                'channels':   channels,
                'ssids':      ssids,
                'devices':    members,
            })

        clusters.sort(key=lambda x: x['size'], reverse=True)
        return clusters
