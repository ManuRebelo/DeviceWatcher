"""
@file utils.py
@brief Vendor/device-info lookup utilities for DeviceWatcher.

Provides:
  - ``load_known_devices`` — load a MAC-prefix → device-info CSV.
  - ``get_device_info``    — look up brand/type/models for a MAC.
  - ``VendorResolver``     — resolve MAC → OUI vendor name from local IEEE
                             registry, with optional external API fallback.

@license MIT — see LICENSE for details.
"""

import csv
import logging
import os
import queue
import threading

import requests

logger = logging.getLogger("utils")

KNOWN_DEVICES_PATH = 'MAC_Address_Device_List.csv'

# Standard locations of IEEE OUI registries on Debian/Ubuntu/Kali (ieee-data pkg).
# Probed in order; longest prefix wins per lookup.  Wireshark's ``manuf`` file is
# also accepted via ``--oui-file``.
_IEEE_FILES = [
    # (path,                              prefix_hex_len, registry_label)
    ('/usr/share/ieee-data/oui36.csv',    9, 'MA-S'),
    ('/usr/share/ieee-data/mam.csv',      7, 'MA-M'),
    ('/usr/share/ieee-data/oui.csv',      6, 'MA-L'),
]


def load_known_devices(csv_file_path: str = KNOWN_DEVICES_PATH) -> dict:
    """Load a MAC-prefix → device-info mapping from a CSV file.

    The CSV must have at least the columns ``MAC_Prefix``, ``Brand``,
    ``DeviceType``, and ``SpecificModels``.

    @param csv_file_path  Path to the CSV file.  Defaults to
                          :data:`KNOWN_DEVICES_PATH`.
    @return               Dict mapping uppercase colon-separated OUI prefix
                          strings to ``{'Brand', 'DeviceType', 'SpecificModels'}``
                          dicts.  Returns an empty dict when the file is absent
                          or malformed.
    """
    data: dict = {}
    try:
        with open(csv_file_path, mode='r') as csv_file:
            for row in csv.DictReader(csv_file):
                prefix = row['MAC_Prefix'].strip().upper()
                data[prefix] = {
                    'Brand':          row['Brand'],
                    'DeviceType':     row['DeviceType'],
                    'SpecificModels': row['SpecificModels'],
                }
    except FileNotFoundError:
        logger.warning("Known devices CSV not found: %s. Running without it.", csv_file_path)
    except Exception as exc:
        logger.warning("Failed to load known devices CSV: %s", exc)
    return data


def get_device_info(mac_address: str, known_devices: dict) -> tuple[str, str, str]:
    """Look up brand, device type, and specific models for *mac_address*.

    Matches the first three octets (OUI) against the *known_devices* mapping.

    @param mac_address   Colon-separated MAC address string.
    @param known_devices Mapping returned by :func:`load_known_devices`.
    @return              ``(brand, device_type, specific_models)`` triple.
                         All three values are ``"Unknown"`` when no match is found.
    """
    prefix = ":".join(mac_address.upper().split(":")[:3])
    info = known_devices.get(prefix)
    if info:
        return info['Brand'], info['DeviceType'], info['SpecificModels']
    return "Unknown", "Unknown", "Unknown"


def _normalize_mac(mac: str) -> str:
    """Return uppercase hex-only MAC (no separators), trimmed to 12 characters.

    @param mac  MAC address in any common notation.
    @return     Uppercase hex string, max 12 characters.
    """
    return ''.join(ch for ch in mac.upper() if ch in '0123456789ABCDEF')[:12]


class VendorResolver:
    """Resolve a MAC address to its OUI vendor name.

    Resolution uses a local IEEE OUI registry loaded at construction time.
    Longest-prefix matching is applied (36-bit MA-S > 28-bit MA-M > 24-bit MA-L).

    External API lookups (macvendors.com / macvendorlookup.com) are opt-in via
    *allow_external_api*.  They are performed asynchronously in a background
    worker thread and **will leak every observed MAC to a third party** — only
    enable when explicitly requested by the operator.

    @param oui_file           Optional path to an additional OUI source: either
                              a Wireshark ``manuf`` (tab-separated) file or an
                              IEEE-style CSV.
    @param allow_external_api Enable external API fallback for unknown MACs.
    """

    _SOURCES = [
        ("macvendors",      "https://api.macvendors.com/{mac}"),
        ("macvendorlookup", "https://www.macvendorlookup.com/api/v2/{mac}"),
    ]

    def __init__(self, oui_file: str | None = None, allow_external_api: bool = False):
        self._cache: dict[str, str] = {}
        self._cache_lock = threading.Lock()
        self._oui: dict[str, str] = {}
        self._allow_external = allow_external_api
        self._queue: queue.Queue | None = None
        self._thread: threading.Thread | None = None
        self.logger = logging.getLogger("VendorResolver")

        self._load_local_oui(oui_file)

        if self._allow_external:
            self._start_worker()

    def set_allow_external(self, enable: bool) -> None:
        """Enable or disable external API lookups at runtime.

        Starting the worker thread is idempotent — calling with ``True``
        multiple times is safe.

        @param enable  True to allow external lookups; False to disable.
        """
        self._allow_external = enable
        if enable and self._queue is None:
            self._start_worker()

    def _start_worker(self) -> None:
        """Initialise and start the background vendor-resolution worker thread."""
        self._queue = queue.Queue()
        self._thread = threading.Thread(
            target=self._worker, daemon=True, name="VendorResolver"
        )
        self._thread.start()

    # ------------------------------------------------------------------ public

    def lookup(self, mac: str) -> str:
        """Return the vendor name for *mac*.  Always returns immediately; never blocks.

        Resolution order:
        1. In-memory cache (hit → immediate return).
        2. Local OUI registry (longest-prefix match).
        3. External API (enqueued for async resolution; returns ``"Unknown"`` now).

        @param mac  MAC address in any common notation.
        @return     Vendor name string, or ``"Unknown"`` when not resolvable.
        """
        norm = _normalize_mac(mac)
        if not norm:
            return "Unknown"

        with self._cache_lock:
            cached = self._cache.get(norm)
        if cached is not None:
            return cached

        # Probe longest prefix first (36-bit MA-S → 28-bit MA-M → 24-bit MA-L).
        vendor: str | None = None
        for n in (9, 7, 6):
            v = self._oui.get(norm[:n])
            if v:
                vendor = v
                break

        if vendor is None and self._allow_external:
            with self._cache_lock:
                if norm not in self._cache:
                    self._cache[norm] = "Unknown"
                    self._queue.put(norm)
            return "Unknown"

        result = vendor or "Unknown"
        with self._cache_lock:
            self._cache[norm] = result
        return result

    # ------------------------------------------------------------------ loaders

    def _load_local_oui(self, custom_path: str | None) -> None:
        """Load all available local OUI registries.

        @param custom_path  Optional user-supplied OUI file path.
        """
        loaded = 0
        if custom_path:
            loaded += self._load_manuf_or_csv(custom_path)
        for path, _prefix_len, _registry in _IEEE_FILES:
            if os.path.exists(path):
                loaded += self._load_ieee_csv(path)
        if loaded:
            self.logger.info("Loaded %d OUI entries from local registry", loaded)
        else:
            self.logger.warning(
                "No local OUI registry found. Vendor lookups will return 'Unknown' "
                "unless --enable-vendor-api is set. Install with: sudo apt install ieee-data"
            )

    def _load_ieee_csv(self, path: str) -> int:
        """Parse an IEEE-data style CSV (columns: Registry, Assignment, Organization Name, …).

        @param path  Absolute path to the CSV file.
        @return      Number of new OUI entries loaded.
        """
        count = 0
        try:
            with open(path, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = (row.get('Assignment') or '').strip().upper()
                    name   = (row.get('Organization Name') or '').strip()
                    if prefix and name and prefix not in self._oui:
                        self._oui[prefix] = name
                        count += 1
        except OSError as exc:
            self.logger.warning("Could not read %s: %s", path, exc)
        return count

    def _load_manuf_or_csv(self, path: str) -> int:
        """Accept either a Wireshark ``manuf`` (tab-separated) file or an IEEE-style CSV.

        @param path  Absolute path to the OUI source file.
        @return      Number of new OUI entries loaded.
        """
        if not os.path.exists(path):
            self.logger.warning("OUI file not found: %s", path)
            return 0
        if path.endswith('.csv'):
            return self._load_ieee_csv(path)

        count = 0
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split('\t')
                    if len(parts) < 2:
                        continue
                    raw_prefix = parts[0].split('/')[0]   # strip optional /N mask
                    prefix = _normalize_mac(raw_prefix)
                    name = (parts[2] if len(parts) > 2 else parts[1]).strip()
                    if prefix and name and prefix not in self._oui:
                        self._oui[prefix] = name
                        count += 1
        except OSError as exc:
            self.logger.warning("Could not read %s: %s", path, exc)
        return count

    # ------------------------------------------------------------------ external

    def _worker(self) -> None:
        """Background thread: drain the queue and resolve MACs via external APIs."""
        while True:
            mac = self._queue.get()
            vendor = self._resolve_external(mac)
            with self._cache_lock:
                self._cache[mac] = vendor
                if len(self._cache) > 10000:
                    # Evict the oldest 5 000 entries (dict insertion-order, Python 3.7+).
                    for k in list(self._cache)[:5000]:
                        self._cache.pop(k, None)
            self._queue.task_done()

    def _resolve_external(self, mac: str) -> str:
        """Query external vendor-lookup APIs for *mac*.

        Tries each source in order and returns the first non-empty result.

        @param mac  Normalised (uppercase, no separators) MAC prefix string.
        @return     Vendor name, or ``"Unknown"`` when all sources fail.
        """
        for name, url_template in self._SOURCES:
            url = url_template.format(mac=mac)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code != 200:
                    continue
                if name == "macvendorlookup":
                    data = response.json()
                    if data and isinstance(data, list) and 'company' in data[0]:
                        vendor = data[0]['company']
                    else:
                        continue
                else:
                    vendor = response.text.strip()
                if vendor:
                    return vendor
            except requests.RequestException as exc:
                self.logger.debug("External vendor lookup failed (%s) for %s: %s", name, mac, exc)
            except Exception as exc:
                self.logger.warning("Unexpected error in vendor lookup (%s) for %s: %s", name, mac, exc)
        return "Unknown"
