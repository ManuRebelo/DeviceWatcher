"""
@file database_manager.py
@brief Thread-safe SQLite persistence layer for DeviceWatcher.

Each calling thread obtains its own sqlite3 connection (stored in
thread-local storage) while a shared RLock serialises all writes.
WAL journal mode allows concurrent reads from Flask request threads.

@license MIT — see LICENSE for details.
"""

import os
import sqlite3
import threading
import logging
from datetime import datetime, timedelta
from collections import OrderedDict


def _default_db_path() -> str:
    """Return the database file path, preferring /app/data/ inside a container.

    @return  Absolute path to the SQLite database file.
    """
    data_dir = '/app/data'
    if os.path.isdir(data_dir):
        return os.path.join(data_dir, 'device_watcher_data.db')
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device_watcher_data.db')


class DatabaseManager:
    """Thread-safe persistence layer backed by SQLite.

    Connections are per-thread (thread-local storage).  WAL mode allows
    concurrent reads while the shared ``_lock`` serialises writers.

    @param db_file  Optional explicit path to the SQLite database file.
                    Defaults to the value returned by :func:`_default_db_path`.
    """

    def __init__(self, db_file: str | None = None):
        self.db_file = db_file or _default_db_path()
        self._tls = threading.local()
        self._lock = threading.RLock()
        self.logger = logging.getLogger("DatabaseManager")
        self._last_reading: OrderedDict = OrderedDict()
        self._reading_lock = threading.Lock()
        self.create_tables()
        self._restrict_db_permissions()

    # ------------------------------------------------------------------ connection

    @property
    def conn(self) -> sqlite3.Connection:
        """Return this thread's connection, opening one on first use.

        @return  A ``sqlite3.Connection`` configured for WAL mode with a
                 10-second busy timeout.
        """
        c = getattr(self._tls, 'conn', None)
        if c is None:
            c = sqlite3.connect(self.db_file, check_same_thread=False, timeout=10.0)
            try:
                c.execute('PRAGMA journal_mode=WAL')
                c.execute('PRAGMA synchronous=NORMAL')
                c.execute('PRAGMA busy_timeout=10000')
            except sqlite3.OperationalError:
                pass
            self._tls.conn = c
            # Chmod WAL/SHM siblings that were created by this connection open.
            self._restrict_db_permissions()
        return c

    def _restrict_db_permissions(self) -> None:
        """Restrict the database file and its WAL siblings to owner-only (0o600).

        The database contains MAC addresses and network observation history that
        must not be readable by other OS users on the same host.
        """
        for suffix in ('', '-journal', '-wal', '-shm'):
            path = self.db_file + suffix
            try:
                if os.path.exists(path):
                    os.chmod(path, 0o600)
            except OSError as exc:
                self.logger.warning("Could not chmod %s: %s", path, exc)
        os.umask(0o077)

    # ------------------------------------------------------------------ schema

    def create_tables(self) -> None:
        """Create all tables, indexes, and triggers; apply incremental migrations.

        Each ``ALTER TABLE`` is wrapped in a try/except so re-running on an
        existing database is idempotent.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS aps (
                mac_address    TEXT PRIMARY KEY,
                ssid           TEXT,
                vendor         TEXT,
                brand          TEXT,
                device_type    TEXT,
                specific_models TEXT,
                channel        TEXT,
                frequency      TEXT,
                signal_strength INTEGER,
                security       TEXT,
                count          INTEGER DEFAULT 1,
                first_seen     TEXT,
                last_seen      TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS clients (
                mac_address    TEXT PRIMARY KEY,
                associated_ap  TEXT,
                vendor         TEXT,
                brand          TEXT,
                device_type    TEXT,
                specific_models TEXT,
                signal_strength INTEGER,
                count          INTEGER DEFAULT 1,
                is_streaming   BOOLEAN DEFAULT 0,
                first_seen     TEXT,
                last_seen      TEXT
            )''')
            try:
                c.execute("ALTER TABLE clients ADD COLUMN is_streaming BOOLEAN DEFAULT 0")
            except sqlite3.OperationalError:
                pass

            c.execute('''CREATE TABLE IF NOT EXISTS bt_classic (
                mac_address    TEXT PRIMARY KEY,
                name           TEXT,
                vendor         TEXT,
                brand          TEXT,
                device_type    TEXT,
                specific_models TEXT,
                signal_strength INTEGER,
                first_seen     TEXT,
                last_seen      TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS ble_devices (
                mac_address       TEXT PRIMARY KEY,
                name              TEXT DEFAULT 'Unknown',
                vendor            TEXT,
                brand             TEXT,
                device_type       TEXT,
                specific_models   TEXT,
                signal_strength   INTEGER,
                first_seen        TEXT,
                last_seen         TEXT,
                manufacturer_data TEXT
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS signal_readings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address     TEXT    NOT NULL,
                device_type     TEXT    NOT NULL,
                signal_strength INTEGER NOT NULL,
                timestamp       TEXT    NOT NULL
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS probe_requests (
                client_mac TEXT NOT NULL,
                ssid       TEXT NOT NULL,
                channel    TEXT,
                last_seen  TEXT NOT NULL,
                PRIMARY KEY (client_mac, ssid)
            )''')
            try:
                c.execute('ALTER TABLE probe_requests ADD COLUMN channel TEXT')
            except sqlite3.OperationalError:
                pass
            c.execute('''CREATE TABLE IF NOT EXISTS entity_aliases (
                cluster_id TEXT PRIMARY KEY,
                name       TEXT
            )''')
            c.execute(
                'CREATE INDEX IF NOT EXISTS idx_sr_mac '
                'ON signal_readings (mac_address, id DESC)'
            )
            c.execute('''CREATE TRIGGER IF NOT EXISTS trg_limit_readings
                         AFTER INSERT ON signal_readings
                         BEGIN
                            DELETE FROM signal_readings
                            WHERE mac_address = NEW.mac_address
                              AND id <= (
                                SELECT id FROM signal_readings
                                WHERE mac_address = NEW.mac_address
                                ORDER BY id DESC LIMIT 1 OFFSET 60
                              );
                         END;''')

            # ── aps migrations ─────────────────────────────────────────────
            for stmt in [
                "ALTER TABLE aps ADD COLUMN channel_width TEXT",
                "ALTER TABLE aps ADD COLUMN band TEXT",
                "ALTER TABLE aps ADD COLUMN bssid_group TEXT",
                "ALTER TABLE aps ADD COLUMN wifi_generation TEXT",
                "ALTER TABLE aps ADD COLUMN spatial_streams INTEGER",
                "ALTER TABLE aps ADD COLUMN country_code TEXT",
                "ALTER TABLE aps ADD COLUMN station_count INTEGER",
                "ALTER TABLE aps ADD COLUMN channel_utilization INTEGER",
                "ALTER TABLE aps ADD COLUMN pmf TEXT",
                "ALTER TABLE aps ADD COLUMN has_11k INTEGER DEFAULT 0",
                "ALTER TABLE aps ADD COLUMN has_11v INTEGER DEFAULT 0",
                "ALTER TABLE aps ADD COLUMN has_11r INTEGER DEFAULT 0",
                "ALTER TABLE aps ADD COLUMN mdid TEXT",
                "ALTER TABLE aps ADD COLUMN is_hotspot20 INTEGER DEFAULT 0",
                "ALTER TABLE aps ADD COLUMN network_type TEXT",
                "ALTER TABLE aps ADD COLUMN is_mesh INTEGER DEFAULT 0",
                "ALTER TABLE aps ADD COLUMN ip_address TEXT",
            ]:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError:
                    pass

            # ── clients migrations ─────────────────────────────────────────
            for stmt in [
                "ALTER TABLE clients ADD COLUMN hostname TEXT",
                "ALTER TABLE clients ADD COLUMN ip_address TEXT",
                "ALTER TABLE clients ADD COLUMN os_fingerprint TEXT",
                "ALTER TABLE clients ADD COLUMN dhcp_vendor_class TEXT",
            ]:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError:
                    pass

            # ── bt_classic migrations ──────────────────────────────────────
            for stmt in [
                "ALTER TABLE bt_classic ADD COLUMN bluetooth_version TEXT",
                "ALTER TABLE bt_classic ADD COLUMN service_classes TEXT",
                "ALTER TABLE bt_classic ADD COLUMN hci_manufacturer TEXT",
            ]:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError:
                    pass

            # ── ble_devices migrations ─────────────────────────────────────
            for stmt in [
                "ALTER TABLE ble_devices ADD COLUMN name TEXT DEFAULT 'Unknown'",
                "ALTER TABLE ble_devices ADD COLUMN manufacturer_data TEXT",
                "ALTER TABLE ble_devices ADD COLUMN tx_power INTEGER",
                "ALTER TABLE ble_devices ADD COLUMN connectable INTEGER",
                "ALTER TABLE ble_devices ADD COLUMN adv_interval_ms INTEGER",
                "ALTER TABLE ble_devices ADD COLUMN ibeacon_uuid TEXT",
                "ALTER TABLE ble_devices ADD COLUMN ibeacon_major INTEGER",
                "ALTER TABLE ble_devices ADD COLUMN ibeacon_minor INTEGER",
                "ALTER TABLE ble_devices ADD COLUMN eddystone_url TEXT",
                "ALTER TABLE ble_devices ADD COLUMN eddystone_uid TEXT",
            ]:
                try:
                    c.execute(stmt)
                except sqlite3.OperationalError:
                    pass

            # Indexes that depend on migrated columns must run after the ALTERs.
            c.execute('CREATE INDEX IF NOT EXISTS idx_clients_ap ON clients (associated_ap)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_aps_ssid   ON aps     (ssid)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_aps_group  ON aps     (bssid_group)')
            try:
                c.execute('DROP TABLE IF EXISTS mdns_services')
            except sqlite3.OperationalError:
                pass

            self.conn.commit()

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _coerce_signal(value) -> int | None:
        """Coerce *value* to int for storage, returning ``None`` on failure.

        @param value  Any value that may represent a signal-strength integer.
        @return       Integer signal strength, or ``None`` when not convertible.
        """
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _sanitize_ssid(self, ssid: str | None) -> str:
        """Strip non-printable ASCII characters from an SSID and truncate to 32 chars.

        @param ssid  Raw SSID string, or ``None``.
        @return      Printable ASCII SSID, max 32 characters.  Returns
                     ``"Unknown"`` when *ssid* is ``None`` or empty after sanitisation.
        """
        if ssid is None:
            return "Unknown"
        return ''.join(ch for ch in ssid if 32 <= ord(ch) <= 126)[:32]

    # ------------------------------------------------------------------ APs

    def insert_or_update_ap(self, mac_address: str, ssid: str, vendor: str,
                             brand: str, device_type: str, specific_models: str,
                             channel, frequency, signal_strength,
                             security: str, count: int, first_seen: str, last_seen: str,
                             channel_width: str = "", band: str = "",
                             wifi_generation: str | None = None,
                             spatial_streams: int | None = None,
                             country_code: str | None = None,
                             station_count: int | None = None,
                             channel_utilization: int | None = None,
                             pmf: str = "",
                             has_11k: bool = False, has_11v: bool = False,
                             has_11r: bool = False, mdid: str | None = None,
                             is_hotspot20: bool = False, network_type: str = "",
                             is_mesh: bool = False) -> None:
        """Insert or upsert an access-point record.

        On conflict the SSID is updated only when the existing value is a
        placeholder (Hidden/Undetected).  Additive fields (count, boolean
        capability flags) are merged rather than overwritten.

        @param mac_address  BSSID of the access point.
        @param ssid         Advertised network name.
        @param vendor       OUI-resolved vendor string.
        @param brand        Brand from known-devices CSV, or "Unknown".
        @param device_type  Device class from known-devices CSV, or "Unknown".
        @param specific_models  Model hint from known-devices CSV, or "Unknown".
        @param channel      Current operating channel.
        @param frequency    Channel centre frequency in MHz.
        @param signal_strength  RSSI in dBm, or ``None``.
        @param security     Security suite string (e.g. "WPA2", "Open").
        @param count        Number of frames contributed by this call (usually 1).
        @param first_seen   ISO-8601 datetime string.
        @param last_seen    ISO-8601 datetime string.
        @param channel_width    HT/VHT/HE channel width string, e.g. "80".
        @param band             Band string: "2.4", "5", or "6".
        @param wifi_generation  Human label, e.g. "Wi-Fi 6".
        @param spatial_streams  Number of spatial streams, or ``None``.
        @param country_code     ISO 3166-1 alpha-2 country code, or ``None``.
        @param station_count    BSS Load station count, or ``None``.
        @param channel_utilization  BSS Load utilisation 0–100, or ``None``.
        @param pmf          Protected Management Frames status string.
        @param has_11k      True when 802.11k (neighbour reports) is advertised.
        @param has_11v      True when 802.11v (BSS transition) is advertised.
        @param has_11r      True when 802.11r (fast BSS transition) is advertised.
        @param mdid         Mobility Domain ID hex string, or ``None``.
        @param is_hotspot20 True when Passpoint / Hotspot 2.0 is advertised.
        @param network_type Interworking access-network type string.
        @param is_mesh      True when IEEE 802.11s mesh is advertised.
        """
        ssid = self._sanitize_ssid(ssid)
        signal_strength = self._coerce_signal(signal_strength)
        with self._lock:
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO aps (mac_address, ssid, vendor, brand, device_type,
                    specific_models, channel, frequency, signal_strength, security,
                    count, first_seen, last_seen, channel_width, band,
                    wifi_generation, spatial_streams, country_code, station_count,
                    channel_utilization, pmf, has_11k, has_11v, has_11r, mdid,
                    is_hotspot20, network_type, is_mesh)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ssid = CASE
                        WHEN aps.ssid IN ('Hidden','Undetected','Hidden SSID','Hidden or Undetected')
                             AND excluded.ssid NOT IN ('Hidden','Undetected','Hidden SSID','Hidden or Undetected')
                        THEN excluded.ssid ELSE aps.ssid END,
                    channel             = excluded.channel,
                    frequency           = excluded.frequency,
                    signal_strength     = excluded.signal_strength,
                    security            = excluded.security,
                    count               = aps.count + excluded.count,
                    last_seen           = excluded.last_seen,
                    channel_width       = CASE WHEN excluded.channel_width != ''
                                              THEN excluded.channel_width ELSE aps.channel_width END,
                    band                = CASE WHEN excluded.band != ''
                                              THEN excluded.band ELSE aps.band END,
                    wifi_generation     = CASE WHEN excluded.wifi_generation IS NOT NULL
                                              THEN excluded.wifi_generation ELSE aps.wifi_generation END,
                    spatial_streams     = CASE WHEN excluded.spatial_streams IS NOT NULL
                                              THEN excluded.spatial_streams ELSE aps.spatial_streams END,
                    country_code        = CASE WHEN excluded.country_code IS NOT NULL
                                              THEN excluded.country_code ELSE aps.country_code END,
                    station_count       = CASE WHEN excluded.station_count IS NOT NULL
                                              THEN excluded.station_count ELSE aps.station_count END,
                    channel_utilization = CASE WHEN excluded.channel_utilization IS NOT NULL
                                              THEN excluded.channel_utilization ELSE aps.channel_utilization END,
                    pmf                 = CASE WHEN excluded.pmf != ''
                                              THEN excluded.pmf ELSE aps.pmf END,
                    has_11k             = CASE WHEN excluded.has_11k = 1 THEN 1 ELSE aps.has_11k END,
                    has_11v             = CASE WHEN excluded.has_11v = 1 THEN 1 ELSE aps.has_11v END,
                    has_11r             = CASE WHEN excluded.has_11r = 1 THEN 1 ELSE aps.has_11r END,
                    mdid                = CASE WHEN excluded.mdid IS NOT NULL
                                              THEN excluded.mdid ELSE aps.mdid END,
                    is_hotspot20        = CASE WHEN excluded.is_hotspot20 = 1 THEN 1 ELSE aps.is_hotspot20 END,
                    network_type        = CASE WHEN excluded.network_type != ''
                                              THEN excluded.network_type ELSE aps.network_type END,
                    is_mesh             = CASE WHEN excluded.is_mesh = 1 THEN 1 ELSE aps.is_mesh END
            ''', (mac_address, ssid, vendor, brand, device_type, specific_models,
                  channel, frequency, signal_strength, security, count, first_seen, last_seen,
                  channel_width, band, wifi_generation, spatial_streams, country_code,
                  station_count, channel_utilization, pmf,
                  1 if has_11k else 0, 1 if has_11v else 0, 1 if has_11r else 0,
                  mdid, 1 if is_hotspot20 else 0, network_type, 1 if is_mesh else 0))
            self.conn.commit()
        self.insert_signal_reading(mac_address, 'ap', signal_strength, last_seen)

    def fetch_all_aps(self, since: str | None = None) -> list:
        """Return all AP rows, optionally filtered by ``last_seen >= since``.

        @param since  ISO-8601 datetime lower bound, or ``None`` for all rows.
        @return       List of raw row tuples matching the ``aps`` table columns.
        """
        c = self.conn.cursor()
        if since:
            c.execute('SELECT * FROM aps WHERE last_seen >= ?', (since,))
        else:
            c.execute('SELECT * FROM aps')
        return c.fetchall()

    def fetch_ap_by_id(self, ap_id: str):
        """Fetch a single AP row by its MAC address primary key.

        @param ap_id  MAC address string.
        @return       Row tuple, or ``None`` if not found.
        """
        c = self.conn.cursor()
        c.execute('SELECT * FROM aps WHERE mac_address = ?', (ap_id,))
        return c.fetchone()

    def delete_ap(self, ap_id: str) -> None:
        """Delete an AP and all BSSIDs in its BSSID group, plus related signal readings.

        @param ap_id  Primary MAC address of the AP (or group representative).
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'SELECT mac_address FROM aps WHERE mac_address = ? OR bssid_group = ?',
                (ap_id, ap_id)
            )
            macs = [row[0] for row in c.fetchall()]
            if macs:
                placeholders = ','.join('?' * len(macs))
                c.execute(f'DELETE FROM signal_readings WHERE mac_address IN ({placeholders})', macs)
                c.execute(f'DELETE FROM aps WHERE mac_address IN ({placeholders})', macs)
            self.conn.commit()

    def ap_exists(self, mac_address: str) -> bool:
        """Return True when *mac_address* is present in the ``aps`` table.

        @param mac_address  MAC address to check.
        @return             True if at least one matching AP row exists.
        """
        c = self.conn.cursor()
        c.execute('SELECT 1 FROM aps WHERE mac_address = ? LIMIT 1', (mac_address,))
        return c.fetchone() is not None

    def update_ap_last_seen(self, mac_address: str, timestamp: str) -> None:
        """Touch the ``last_seen`` timestamp of an AP record.

        @param mac_address  BSSID of the AP.
        @param timestamp    ISO-8601 datetime string.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'UPDATE aps SET last_seen = ? WHERE mac_address = ?',
                (timestamp, mac_address)
            )
            self.conn.commit()

    def fetch_aps_by_ssid(self, ssid: str) -> list:
        """Return (mac_address,) tuples for all APs advertising *ssid*.

        @param ssid  Exact SSID string to match.
        @return      List of single-element tuples.
        """
        c = self.conn.cursor()
        c.execute('SELECT mac_address FROM aps WHERE ssid = ?', (ssid,))
        return c.fetchall()

    def set_bssid_group(self, mac: str, group_mac: str) -> None:
        """Set the BSSID group representative for a given AP.

        @param mac        MAC address of the AP to update.
        @param group_mac  MAC address of the group representative (lowest BSSID).
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute('UPDATE aps SET bssid_group = ? WHERE mac_address = ?', (group_mac, mac))
            self.conn.commit()

    # ------------------------------------------------------------------ clients

    def insert_or_update_client(self, mac_address: str, associated_ap: str | None,
                                 vendor: str, brand: str, device_type: str,
                                 specific_models: str, signal_strength,
                                 count: int, first_seen: str, last_seen: str,
                                 is_streaming: bool = False) -> None:
        """Insert or upsert a Wi-Fi client record.

        When *mac_address* is already known as an AP, the client row is deleted
        (collision between AP BSSID and client observation is impossible).

        @param mac_address    Client MAC address.
        @param associated_ap  BSSID of the associated AP, or ``None``.
        @param vendor         OUI-resolved vendor string.
        @param brand          Brand from known-devices CSV.
        @param device_type    Device class from known-devices CSV.
        @param specific_models  Model hint.
        @param signal_strength  RSSI in dBm.
        @param count          Frame count contributed by this call (usually 1).
        @param first_seen     ISO-8601 datetime string.
        @param last_seen      ISO-8601 datetime string.
        @param is_streaming   True when high upstream bandwidth was detected.
        """
        if self.ap_exists(mac_address):
            self.delete_client(mac_address)
            return
        signal_strength = self._coerce_signal(signal_strength)
        with self._lock:
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO clients (mac_address, associated_ap, vendor, brand,
                    device_type, specific_models, signal_strength, count, first_seen, last_seen, is_streaming)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    associated_ap = CASE
                        WHEN excluded.associated_ap != 'ff:ff:ff:ff:ff:ff'
                             AND excluded.associated_ap IS NOT clients.associated_ap
                        THEN excluded.associated_ap ELSE clients.associated_ap END,
                    vendor          = excluded.vendor,
                    signal_strength = excluded.signal_strength,
                    count           = clients.count + excluded.count,
                    last_seen       = excluded.last_seen,
                    is_streaming    = COALESCE(excluded.is_streaming, clients.is_streaming)
            ''', (mac_address, associated_ap, vendor, brand, device_type,
                  specific_models, signal_strength, count, first_seen, last_seen, is_streaming))
            self.conn.commit()
        self.insert_signal_reading(mac_address, 'client', signal_strength, last_seen)

    def set_client_streaming_status(self, mac_address: str, status: bool) -> None:
        """Update the streaming flag for a Wi-Fi client.

        @param mac_address  Client MAC address.
        @param status       True when high upstream bandwidth is active.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'UPDATE clients SET is_streaming = ? WHERE mac_address = ?',
                (status, mac_address)
            )
            self.conn.commit()

    def fetch_all_clients(self, since: str | None = None) -> list:
        """Return all client rows, optionally filtered by ``last_seen >= since``.

        @param since  ISO-8601 datetime lower bound, or ``None`` for all rows.
        @return       List of row tuples for the explicit column projection.
        """
        c = self.conn.cursor()
        query = (
            'SELECT mac_address, associated_ap, vendor, brand, device_type, '
            'specific_models, signal_strength, count, is_streaming, first_seen, last_seen '
            'FROM clients'
        )
        if since:
            c.execute(query + ' WHERE last_seen >= ?', (since,))
        else:
            c.execute(query)
        return c.fetchall()

    def fetch_client_by_mac(self, mac_address: str):
        """Fetch a single client row by MAC address.

        @param mac_address  Client MAC address.
        @return             Row tuple, or ``None`` if not found.
        """
        c = self.conn.cursor()
        c.execute('SELECT * FROM clients WHERE mac_address = ?', (mac_address,))
        return c.fetchone()

    def delete_client(self, mac_address: str) -> None:
        """Delete a client and its associated signal readings and probe requests.

        @param mac_address  Client MAC address to remove.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute('DELETE FROM signal_readings WHERE mac_address = ?', (mac_address,))
            c.execute('DELETE FROM clients WHERE mac_address = ?', (mac_address,))
            c.execute('DELETE FROM probe_requests WHERE client_mac = ?', (mac_address,))
            self.conn.commit()

    def update_client_last_seen(self, mac_address: str, timestamp: str) -> None:
        """Touch the ``last_seen`` timestamp of a client record.

        @param mac_address  Client MAC address.
        @param timestamp    ISO-8601 datetime string.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'UPDATE clients SET last_seen = ? WHERE mac_address = ?',
                (timestamp, mac_address)
            )
            self.conn.commit()

    def update_client_disassociation(self, mac_address: str, timestamp: str) -> None:
        """Clear the AP association for a client after a Disassociation frame.

        @param mac_address  Client MAC address.
        @param timestamp    ISO-8601 datetime string.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'UPDATE clients SET associated_ap = NULL, last_seen = ? WHERE mac_address = ?',
                (timestamp, mac_address)
            )
            self.conn.commit()

    def update_client_deauthentication(self, mac_address: str, timestamp: str) -> None:
        """Clear the AP association for a client after a Deauthentication frame.

        The database action is identical to disassociation; both clear
        ``associated_ap`` and update ``last_seen``.

        @param mac_address  Client MAC address.
        @param timestamp    ISO-8601 datetime string.
        """
        self.update_client_disassociation(mac_address, timestamp)

    # ------------------------------------------------------------------ BT Classic

    def insert_or_update_bt_classic(self, mac_address: str, name: str,
                                     vendor: str, brand: str, device_type: str,
                                     specific_models: str, signal_strength,
                                     first_seen: str, last_seen: str,
                                     bluetooth_version: str | None = None,
                                     service_classes: str | None = None,
                                     hci_manufacturer: str | None = None) -> None:
        """Insert or upsert a Bluetooth Classic device record.

        @param mac_address       BD_ADDR of the device.
        @param name              Friendly device name, or "Unknown".
        @param vendor            OUI-resolved vendor string.
        @param brand             Brand from known-devices CSV.
        @param device_type       CoD-derived or CSV device class.
        @param specific_models   Model hint.
        @param signal_strength   RSSI in dBm, or ``None``.
        @param first_seen        ISO-8601 datetime string.
        @param last_seen         ISO-8601 datetime string.
        @param bluetooth_version LMP version string, e.g. "5.2".
        @param service_classes   Comma-separated CoD service class labels.
        @param hci_manufacturer  HCI manufacturer string from ``hcitool info``.
        """
        signal_strength = self._coerce_signal(signal_strength)
        with self._lock:
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO bt_classic (mac_address, name, vendor, brand, device_type,
                    specific_models, signal_strength, first_seen, last_seen,
                    bluetooth_version, service_classes, hci_manufacturer)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    name              = CASE WHEN excluded.name != 'Unknown'
                                            THEN excluded.name ELSE bt_classic.name END,
                    signal_strength   = excluded.signal_strength,
                    last_seen         = excluded.last_seen,
                    bluetooth_version = CASE WHEN excluded.bluetooth_version IS NOT NULL
                                            THEN excluded.bluetooth_version ELSE bt_classic.bluetooth_version END,
                    service_classes   = CASE WHEN excluded.service_classes IS NOT NULL AND excluded.service_classes != ''
                                            THEN excluded.service_classes ELSE bt_classic.service_classes END,
                    hci_manufacturer  = CASE WHEN excluded.hci_manufacturer IS NOT NULL
                                            THEN excluded.hci_manufacturer ELSE bt_classic.hci_manufacturer END
            ''', (mac_address, name, vendor, brand, device_type, specific_models,
                  signal_strength, first_seen, last_seen,
                  bluetooth_version, service_classes, hci_manufacturer))
            self.conn.commit()
        self.insert_signal_reading(mac_address, 'bt', signal_strength, last_seen)

    def fetch_all_bt_classic(self, since: str | None = None) -> list:
        """Return all Bluetooth Classic rows, optionally filtered by ``last_seen >= since``.

        @param since  ISO-8601 datetime lower bound, or ``None`` for all rows.
        @return       List of raw row tuples.
        """
        c = self.conn.cursor()
        if since:
            c.execute('SELECT * FROM bt_classic WHERE last_seen >= ?', (since,))
        else:
            c.execute('SELECT * FROM bt_classic')
        return c.fetchall()

    def fetch_bt_classic_by_mac(self, mac_address: str):
        """Fetch a single Bluetooth Classic row by BD_ADDR.

        @param mac_address  BD_ADDR of the device.
        @return             Row tuple, or ``None`` if not found.
        """
        c = self.conn.cursor()
        c.execute('SELECT * FROM bt_classic WHERE mac_address = ?', (mac_address,))
        return c.fetchone()

    def delete_bt_classic(self, mac_address: str) -> None:
        """Delete a Bluetooth Classic device and its signal readings.

        @param mac_address  BD_ADDR to remove.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute('DELETE FROM signal_readings WHERE mac_address = ?', (mac_address,))
            c.execute('DELETE FROM bt_classic WHERE mac_address = ?', (mac_address,))
            self.conn.commit()

    # ------------------------------------------------------------------ BLE

    def insert_or_update_ble(self, mac_address: str, name: str,
                               vendor: str, brand: str, device_type: str,
                               specific_models: str, signal_strength,
                               first_seen: str, last_seen: str,
                               manufacturer_data: str | None = None,
                               tx_power: int | None = None,
                               connectable: bool | None = None,
                               adv_interval_ms: int | None = None,
                               ibeacon_uuid: str | None = None,
                               ibeacon_major: int | None = None,
                               ibeacon_minor: int | None = None,
                               eddystone_url: str | None = None,
                               eddystone_uid: str | None = None) -> None:
        """Insert or upsert a BLE device record.

        Non-None fields always override existing values; ``None`` preserves
        the previously stored value.

        @param mac_address      BLE device address (lowercased).
        @param name             Local name from advertisement, or "Unknown".
        @param vendor           OUI-resolved vendor string.
        @param brand            Brand from known-devices CSV.
        @param device_type      Service-UUID-derived or CSV device class.
        @param specific_models  Model hint.
        @param signal_strength  RSSI in dBm.
        @param first_seen       ISO-8601 datetime string.
        @param last_seen        ISO-8601 datetime string.
        @param manufacturer_data  JSON-encoded manufacturer-specific data dict.
        @param tx_power         Advertised TX power in dBm, or ``None``.
        @param connectable      True when the device accepts connections.
        @param adv_interval_ms  Estimated advertisement interval in ms.
        @param ibeacon_uuid     iBeacon proximity UUID string, or ``None``.
        @param ibeacon_major    iBeacon major value, or ``None``.
        @param ibeacon_minor    iBeacon minor value, or ``None``.
        @param eddystone_url    Decoded Eddystone-URL string, or ``None``.
        @param eddystone_uid    Decoded Eddystone-UID "NAMESPACE.INSTANCE", or ``None``.
        """
        signal_strength = self._coerce_signal(signal_strength)
        conn_int = None if connectable is None else (1 if connectable else 0)
        with self._lock:
            c = self.conn.cursor()
            c.execute('''
                INSERT INTO ble_devices (mac_address, name, vendor, brand, device_type,
                    specific_models, signal_strength, first_seen, last_seen,
                    manufacturer_data, tx_power, connectable, adv_interval_ms,
                    ibeacon_uuid, ibeacon_major, ibeacon_minor, eddystone_url, eddystone_uid)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    name              = CASE WHEN excluded.name != 'Unknown'
                                            THEN excluded.name ELSE ble_devices.name END,
                    signal_strength   = excluded.signal_strength,
                    last_seen         = excluded.last_seen,
                    manufacturer_data = CASE WHEN excluded.manufacturer_data IS NOT NULL
                                            THEN excluded.manufacturer_data ELSE ble_devices.manufacturer_data END,
                    tx_power          = CASE WHEN excluded.tx_power IS NOT NULL
                                            THEN excluded.tx_power ELSE ble_devices.tx_power END,
                    connectable       = CASE WHEN excluded.connectable IS NOT NULL
                                            THEN excluded.connectable ELSE ble_devices.connectable END,
                    adv_interval_ms   = CASE WHEN excluded.adv_interval_ms IS NOT NULL
                                            THEN excluded.adv_interval_ms ELSE ble_devices.adv_interval_ms END,
                    ibeacon_uuid      = CASE WHEN excluded.ibeacon_uuid IS NOT NULL
                                            THEN excluded.ibeacon_uuid ELSE ble_devices.ibeacon_uuid END,
                    ibeacon_major     = CASE WHEN excluded.ibeacon_major IS NOT NULL
                                            THEN excluded.ibeacon_major ELSE ble_devices.ibeacon_major END,
                    ibeacon_minor     = CASE WHEN excluded.ibeacon_minor IS NOT NULL
                                            THEN excluded.ibeacon_minor ELSE ble_devices.ibeacon_minor END,
                    eddystone_url     = CASE WHEN excluded.eddystone_url IS NOT NULL
                                            THEN excluded.eddystone_url ELSE ble_devices.eddystone_url END,
                    eddystone_uid     = CASE WHEN excluded.eddystone_uid IS NOT NULL
                                            THEN excluded.eddystone_uid ELSE ble_devices.eddystone_uid END
            ''', (mac_address, name, vendor, brand, device_type, specific_models,
                  signal_strength, first_seen, last_seen, manufacturer_data,
                  tx_power, conn_int, adv_interval_ms,
                  ibeacon_uuid, ibeacon_major, ibeacon_minor, eddystone_url, eddystone_uid))
            self.conn.commit()
        self.insert_signal_reading(mac_address, 'ble', signal_strength, last_seen)

    def fetch_all_ble_devices(self, since: str | None = None) -> list:
        """Return all BLE device rows, optionally filtered by ``last_seen >= since``.

        @param since  ISO-8601 datetime lower bound, or ``None`` for all rows.
        @return       List of raw row tuples.
        """
        c = self.conn.cursor()
        if since:
            c.execute('SELECT * FROM ble_devices WHERE last_seen >= ?', (since,))
        else:
            c.execute('SELECT * FROM ble_devices')
        return c.fetchall()

    def fetch_ble_device_by_mac(self, mac_address: str):
        """Fetch a single BLE device row by its address.

        @param mac_address  BLE device address.
        @return             Row tuple, or ``None`` if not found.
        """
        c = self.conn.cursor()
        c.execute('SELECT * FROM ble_devices WHERE mac_address = ?', (mac_address,))
        return c.fetchone()

    def delete_ble_device(self, mac_address: str) -> None:
        """Delete a BLE device and its signal readings.

        @param mac_address  BLE device address to remove.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute('DELETE FROM signal_readings WHERE mac_address = ?', (mac_address,))
            c.execute('DELETE FROM ble_devices WHERE mac_address = ?', (mac_address,))
            self.conn.commit()

    # ------------------------------------------------------------------ entity aliases

    def set_entity_alias(self, cluster_id: str, name: str) -> None:
        """Store or clear a user-assigned name for an entity cluster.

        Passing an empty *name* removes the alias.

        @param cluster_id  MD5-derived cluster identifier string.
        @param name        Human-readable label, or empty string to delete.
        """
        with self._lock:
            c = self.conn.cursor()
            if not name:
                c.execute('DELETE FROM entity_aliases WHERE cluster_id=?', (cluster_id,))
            else:
                c.execute(
                    'INSERT OR REPLACE INTO entity_aliases (cluster_id, name) VALUES (?, ?)',
                    (cluster_id, name)
                )
            self.conn.commit()

    def get_entity_aliases(self) -> dict[str, str]:
        """Return all stored entity aliases as a mapping.

        @return  Dict mapping cluster_id → name.
        """
        c = self.conn.cursor()
        c.execute('SELECT cluster_id, name FROM entity_aliases')
        return {row[0]: row[1] for row in c.fetchall()}

    # ------------------------------------------------------------------ probe requests

    def insert_probe_request(self, client_mac: str, ssid: str,
                              channel: str, timestamp: str) -> None:
        """Upsert a probe-request record, updating channel and timestamp on conflict.

        @param client_mac  Client MAC address that sent the probe.
        @param ssid        Probed network name.
        @param channel     Channel on which the probe was observed (as string).
        @param timestamp   ISO-8601 datetime string.
        """
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'INSERT INTO probe_requests (client_mac, ssid, channel, last_seen) '
                'VALUES (?, ?, ?, ?) '
                'ON CONFLICT(client_mac, ssid) DO UPDATE SET '
                'channel = excluded.channel, last_seen = excluded.last_seen',
                (client_mac, ssid, channel, timestamp)
            )
            self.conn.commit()

    def fetch_all_probe_requests(self, since: str | None = None) -> list:
        """Return probe-request rows ordered by recency.

        @param since  ISO-8601 datetime lower bound, or ``None`` for all rows.
        @return       List of (client_mac, ssid, channel, last_seen) tuples.
        """
        c = self.conn.cursor()
        base = 'SELECT client_mac, ssid, channel, last_seen FROM probe_requests'
        if since:
            c.execute(base + ' WHERE last_seen >= ? ORDER BY last_seen DESC', (since,))
        else:
            c.execute(base + ' ORDER BY last_seen DESC')
        return c.fetchall()

    # ------------------------------------------------------------------ signal readings

    def insert_signal_reading(self, mac_address: str, device_type: str,
                               signal_strength, timestamp: str) -> None:
        """Record a signal reading, rate-limited to one sample per MAC per 30 seconds.

        The SQLite trigger ``trg_limit_readings`` automatically prunes each
        MAC's history to the most recent 60 entries.

        @param mac_address    Device MAC / BD_ADDR.
        @param device_type    One of "ap", "client", "bt", "ble".
        @param signal_strength  RSSI in dBm, or ``None`` (no-op when ``None``).
        @param timestamp      ISO-8601 datetime string for the reading.
        """
        sig = self._coerce_signal(signal_strength)
        if sig is None:
            return
        now = datetime.now()
        with self._reading_lock:
            last = self._last_reading.get(mac_address)
            if last and (now - last).total_seconds() < 30:
                return
            if mac_address in self._last_reading:
                del self._last_reading[mac_address]
            self._last_reading[mac_address] = now
            if len(self._last_reading) > 5000:
                for _ in range(2500):
                    self._last_reading.popitem(last=False)
        with self._lock:
            c = self.conn.cursor()
            c.execute(
                'INSERT INTO signal_readings (mac_address, device_type, signal_strength, timestamp) '
                'VALUES (?,?,?,?)',
                (mac_address, device_type, sig, timestamp)
            )
            self.conn.commit()

    def fetch_signal_readings(self) -> list:
        """Return up to the 2 000 most recent signal readings in chronological order.

        @return  List of (mac_address, device_type, signal_strength, timestamp) tuples.
        """
        c = self.conn.cursor()
        c.execute(
            'SELECT mac_address, device_type, signal_strength, timestamp '
            'FROM (SELECT id, mac_address, device_type, signal_strength, timestamp '
            '      FROM signal_readings ORDER BY id DESC LIMIT 2000) '
            'ORDER BY id ASC'
        )
        return c.fetchall()

    def cleanup_inactive_devices(self, hours: int = 24) -> None:
        """Delete all devices (and orphaned signal readings) not seen within *hours*.

        @param hours  Age threshold in hours.  Devices whose ``last_seen`` is
                      older than ``now - hours`` are removed.  Default 24.
        """
        cutoff = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
        with self._lock:
            c = self.conn.cursor()
            c.execute('DELETE FROM aps         WHERE last_seen < ?', (cutoff,))
            c.execute('DELETE FROM clients     WHERE last_seen < ?', (cutoff,))
            c.execute('DELETE FROM bt_classic  WHERE last_seen < ?', (cutoff,))
            c.execute('DELETE FROM ble_devices WHERE last_seen < ?', (cutoff,))
            c.execute(
                'DELETE FROM signal_readings WHERE mac_address NOT IN ('
                '  SELECT mac_address FROM aps UNION '
                '  SELECT mac_address FROM clients UNION '
                '  SELECT mac_address FROM bt_classic UNION '
                '  SELECT mac_address FROM ble_devices'
                ')'
            )
            self.conn.commit()

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Close this thread's SQLite connection.

        Connections held by other threads are closed when those threads exit
        (they are stored in thread-local storage and not tracked here).
        """
        c = getattr(self._tls, 'conn', None)
        if c is not None:
            c.close()
            self._tls.conn = None
