// ---------- auth ----------
// If the page was opened with ?token=XYZ, remember it for the session and
// strip it from the visible URL. All subsequent fetches will include it.
const _authToken = (() => {
    const url = new URL(window.location.href);
    const fromUrl = url.searchParams.get('token');
    if (fromUrl) {
        sessionStorage.setItem('dw_token', fromUrl);
        url.searchParams.delete('token');
        window.history.replaceState({}, '', url.toString());
        return fromUrl;
    }
    return sessionStorage.getItem('dw_token') || null;
})();

function authFetch(path, options = {}) {
    if (!_authToken) return fetch(path, options);
    const headers = new Headers(options.headers || {});
    if (!headers.has('Authorization')) {
        headers.set('Authorization', 'Bearer ' + _authToken);
    }
    return fetch(path, { ...options, headers });
}

let networkWifi = null;
let networkBluetooth = null;
let activityChart = null;
let chartSpectrum24 = null;
let chartSpectrum5  = null;
let chartTimeline        = null;
let chartTimelineClients = null;
let chartBtTimeline      = null;
let chartBtType    = null;
let chartBtVendor  = null;
let chartBleType   = null;
let chartBleVendor = null;
let chartProximity = null;
let chartPresence  = null;
let dtAps = null;
let dtClients = null;
let dtBluetooth = null;
let dtBle = null;
let dtProbeSSIDs = null;
let dtIot = null;
let Graph3D = null;
let chartOccupancy = null;
let wifiHierarchical = false;
let lastWifiAps = null;
let lastWifiClients = null;
let lastBleBluetoothData = null;
let lastBleData = null;

// ---------- live packet feed state ----------
let _liveFeedES       = null;   // EventSource instance
let _liveFeedPaused   = false;
let _liveFeedCount    = 0;
const _LIVEFEED_MAX   = 800;    // max rows kept in DOM

// Wi-Fi feed filter state
let _wfFilter = {
    hiddenTypes: new Set(),   // packet type strings to suppress
    macSearch:   '',          // substring match on src or dst
    infoSearch:  '',          // substring match on info field
    hideRandom:  false,
    minSignal:   null,        // dBm or null
};

// BT/BLE feed event-level filter state (stacks on top of _btFeedFilter source selector)
let _btEventFilter = {
    hiddenTypes: new Set(),   // event type strings to suppress
    search:      '',          // substring match on mac/name/vendor
    hideRandom:  false,
    minRssi:     null,        // dBm or null
};

let rawDataStore = { aps: {}, clients: {}, bluetooths: {}, bles: {}, probe_requests: [] };
let lastFetchSince = null;

// ---------- UI prefs (persisted in localStorage) ----------
let _uiPageLength      = 25;
let _uiRefreshInterval = 60;   // seconds
let _dataRefreshTimer  = null;
let _overviewRealOnly  = false;

function _loadUiPrefs() {
    try {
        const pl = parseInt(localStorage.getItem('dw_pageLength') || '25', 10);
        const ri = parseInt(localStorage.getItem('dw_refreshInterval') || '60', 10);
        if (pl >= 10 && pl <= 100) _uiPageLength = pl;
        if (ri >= 15 && ri <= 300) _uiRefreshInterval = ri;
        _overviewRealOnly = localStorage.getItem('dw_overview_real_only') === '1';
    } catch (_) {}
}

function toggleOverviewRealOnly() {
    _overviewRealOnly = !_overviewRealOnly;
    try { localStorage.setItem('dw_overview_real_only', _overviewRealOnly ? '1' : '0'); } catch (_) {}
    const mAPs     = mergeAPs(rawDataStore.aps);
    const mClients = mergeClients(rawDataStore.clients);
    displayGeneralInfo(rawDataStore, mAPs, mClients);
}

const vizPalette = ["#2563eb","#10b981","#ef4444","#f59e42","#a21caf","#0ea5e9","#6d4c41","#c026d3","#6366f1","#14b8a6","#facc15","#e11d48","#84cc16","#9333ea","#3b82f6","#f97316","#475569","#22c55e","#fb7185","#8b5cf6"];

function escHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ---------- helpers ----------

function averageSignal(devices) {
    let sum = 0, count = 0, min = null, max = null;
    for (const d of Object.values(devices)) {
        if (d.signal_strength !== undefined && d.signal_strength !== null && d.signal_strength !== "") {
            let s = parseInt(d.signal_strength, 10);
            if (!isNaN(s)) {
                sum += s; count++;
                if (min === null || s < min) min = s;
                if (max === null || s > max) max = s;
            }
        }
    }
    return count ? { avg: (sum / count).toFixed(1), min, max } : { avg: "N/A", min: "N/A", max: "N/A" };
}

function mostCommonVendor(devices) {
    const vendorCount = {};
    const seenMacs = new Set();
    for (const d of Object.values(devices)) {
        const mac = d.mac_address;
        const vendor = d.vendor;
        if (!mac || seenMacs.has(mac) || !vendor || vendor === 'Unknown') continue;
        seenMacs.add(mac);
        vendorCount[vendor] = (vendorCount[vendor] || 0) + 1;
    }
    let max = 0, maxVendor = null;
    for (const [vendor, count] of Object.entries(vendorCount)) {
        if (count > max) { max = count; maxVendor = vendor; }
    }
    return maxVendor ? `${maxVendor} (${max})` : "N/A";
}

function mergeAPs(aps) {
    const merged = {};
    for (const ap of Object.values(aps)) {
        const groupKey = ap.bssid_group || ap.mac_address;
        if (!merged[groupKey]) {
            merged[groupKey] = {
                mac_address: groupKey,
                ssids: new Set(), vendors: new Set(), device_types: new Set(),
                signals: [], channels: [], securities: new Set(),
                bands: new Set(), channel_widths: new Set(), freq_info: [], raw: [],
                first_seen: null, last_seen: null,
                wifi_generations: new Set(),
                spatial_streams: null,
                country_code: null,
                station_count: null,
                channel_utilization: null,
                pmf: null,
                has_11k: false, has_11v: false, has_11r: false,
                mdid: null,
                is_mesh: false, is_hotspot20: false,
                network_type: null,
            };
        }
        const m = merged[groupKey];
        m.ssids.add(ap.ssid || 'Unknown');
        m.vendors.add(ap.vendor || '');
        if (ap.device_type && ap.device_type !== 'Unknown') m.device_types.add(ap.device_type);
        if (ap.signal_strength != null && ap.signal_strength !== "") m.signals.push(ap.signal_strength);
        if (ap.channel != null && ap.channel !== "") m.channels.push(ap.channel);
        m.securities.add(ap.security || 'Unknown');
        if (ap.band) m.bands.add(ap.band + ' GHz');
        if (ap.channel_width) m.channel_widths.add(ap.channel_width + ' MHz');
        if (ap.first_seen && (!m.first_seen || ap.first_seen < m.first_seen)) m.first_seen = ap.first_seen;
        if (ap.last_seen  && (!m.last_seen  || ap.last_seen  > m.last_seen))  m.last_seen  = ap.last_seen;
        m.freq_info.push({ channel: ap.channel, signal: ap.signal_strength, security: ap.security, ssid: ap.ssid || 'Unknown', band: ap.band, channel_width: ap.channel_width });
        m.raw.push(ap);
        // new fields
        if (ap.wifi_generation) m.wifi_generations.add(ap.wifi_generation);
        if (ap.spatial_streams != null && ap.spatial_streams > (m.spatial_streams || 0)) m.spatial_streams = ap.spatial_streams;
        if (!m.country_code && ap.country_code) m.country_code = ap.country_code;
        if (ap.station_count != null) m.station_count = ap.station_count;
        if (ap.channel_utilization != null) m.channel_utilization = ap.channel_utilization;
        if (!m.pmf && ap.pmf) m.pmf = ap.pmf;
        if (ap.has_11k) m.has_11k = true;
        if (ap.has_11v) m.has_11v = true;
        if (ap.has_11r) m.has_11r = true;
        if (!m.mdid && ap.mdid) m.mdid = ap.mdid;
        if (ap.is_mesh) m.is_mesh = true;
        if (ap.is_hotspot20) m.is_hotspot20 = true;
        if (!m.network_type && ap.network_type) m.network_type = ap.network_type;
    }
    for (const key in merged) {
        const m = merged[key];
        m.ssids          = Array.from(m.ssids);
        m.vendors        = Array.from(m.vendors);
        m.device_types   = Array.from(m.device_types);
        m.securities     = Array.from(m.securities);
        m.bands          = Array.from(m.bands);
        m.channel_widths = Array.from(m.channel_widths);
        m.wifi_generations = Array.from(m.wifi_generations);
    }
    return merged;
}

function mergeClients(clients) {
    const merged = {};
    for (const client of Object.values(clients)) {
        const baseMac = client.mac_address.split('_')[0];
        if (!merged[baseMac]) {
            merged[baseMac] = {
                mac_address: baseMac,
                vendors: new Set(), device_types: new Set(),
                signals: [], associated_aps: new Set(), counts: [], raw: [],
                first_seen: null, last_seen: null, is_streaming: false
            };
        }
        const m = merged[baseMac];
        m.vendors.add(client.vendor || '');
        if (client.device_type && client.device_type !== 'Unknown') m.device_types.add(client.device_type);
        if (client.signal_strength != null && client.signal_strength !== "") m.signals.push(client.signal_strength);
        if (client.associated_ap) m.associated_aps.add(client.associated_ap.split('_')[0]);
        m.counts.push(client.count || 0);
        m.raw.push(client);
        if (client.is_streaming) m.is_streaming = true;
        if (client.first_seen && (!m.first_seen || client.first_seen < m.first_seen)) m.first_seen = client.first_seen;
        if (client.last_seen  && (!m.last_seen  || client.last_seen  > m.last_seen))  m.last_seen  = client.last_seen;
    }
    for (const mac in merged) {
        const m = merged[mac];
        m.vendors        = Array.from(m.vendors);
        m.device_types   = Array.from(m.device_types);
        m.associated_aps = Array.from(m.associated_aps);
    }
    return merged;
}

function mergeBluetooths(bluetooths) {
    const merged = {};
    for (const bt of Object.values(bluetooths)) {
        const mac = bt.mac_address;
        if (!merged[mac]) {
            merged[mac] = {
                mac_address: mac,
                names: new Set(), vendors: new Set(), device_types: new Set(),
                signals: [], raw: [], first_seen: null, last_seen: null,
                bluetooth_version: null, service_classes_set: new Set(),
            };
        }
        const m = merged[mac];
        m.names.add(bt.name || 'Unknown');
        m.vendors.add(bt.vendor || '');
        if (bt.device_type && bt.device_type !== 'Unknown') m.device_types.add(bt.device_type);
        if (bt.signal_strength != null && bt.signal_strength !== "") m.signals.push(bt.signal_strength);
        m.raw.push(bt);
        if (bt.first_seen && (!m.first_seen || bt.first_seen < m.first_seen)) m.first_seen = bt.first_seen;
        if (bt.last_seen  && (!m.last_seen  || bt.last_seen  > m.last_seen))  m.last_seen  = bt.last_seen;
        if (!m.bluetooth_version && bt.bluetooth_version) m.bluetooth_version = bt.bluetooth_version;
        if (bt.service_classes) bt.service_classes.split(', ').forEach(s => s && m.service_classes_set.add(s));
    }
    for (const mac in merged) {
        const m = merged[mac];
        m.names         = Array.from(m.names);
        m.vendors       = Array.from(m.vendors);
        m.device_types  = Array.from(m.device_types);
        m.service_classes = Array.from(m.service_classes_set);
        delete m.service_classes_set;
    }
    return merged;
}

function mergeBLEs(bles) {
    const merged = {};
    for (const ble of Object.values(bles)) {
        const mac = ble.mac_address;
        if (!merged[mac]) {
            merged[mac] = {
                mac_address: mac,
                names: new Set(), vendors: new Set(), device_types: new Set(),
                signals: [], raw: [], first_seen: null, last_seen: null,
                tx_power: null, connectable: null, adv_interval_ms: null,
                ibeacon_uuid: null, ibeacon_major: null, ibeacon_minor: null,
                eddystone_url: null, eddystone_uid: null,
            };
        }
        const m = merged[mac];
        if (ble.name && ble.name !== 'Unknown') m.names.add(ble.name);
        m.vendors.add(ble.vendor || '');
        if (ble.device_type && ble.device_type !== 'Unknown') m.device_types.add(ble.device_type);
        if (ble.signal_strength != null && ble.signal_strength !== "") m.signals.push(ble.signal_strength);
        m.raw.push(ble);
        if (ble.first_seen && (!m.first_seen || ble.first_seen < m.first_seen)) m.first_seen = ble.first_seen;
        if (ble.last_seen  && (!m.last_seen  || ble.last_seen  > m.last_seen))  m.last_seen  = ble.last_seen;
        if (ble.tx_power != null) m.tx_power = ble.tx_power;
        if (ble.connectable != null) m.connectable = ble.connectable;
        if (ble.adv_interval_ms != null) m.adv_interval_ms = ble.adv_interval_ms;
        if (!m.ibeacon_uuid && ble.ibeacon_uuid) { m.ibeacon_uuid = ble.ibeacon_uuid; m.ibeacon_major = ble.ibeacon_major; m.ibeacon_minor = ble.ibeacon_minor; }
        if (!m.eddystone_url && ble.eddystone_url) m.eddystone_url = ble.eddystone_url;
        if (!m.eddystone_uid && ble.eddystone_uid) m.eddystone_uid = ble.eddystone_uid;
    }
    for (const mac in merged) {
        const m = merged[mac];
        m.names       = Array.from(m.names);
        m.vendors     = Array.from(m.vendors);
        m.device_types = Array.from(m.device_types);
    }
    return merged;
}

// ---------- device-type inference ----------
// Most rows arrive with device_type "Unknown" because the bundled
// MAC_Address_Device_List.csv only has a few hundred prefixes. These helpers
// fall back to inference from data we already have (vendor, SSID, Wi-Fi flags,
// MAC randomization). Inferred values are rendered italic+muted so a reader
// can tell them apart from authoritative ones from the CSV.

function inferApType(r) {
    if (r.is_mesh) return 'Mesh Node';
    if (r.is_hotspot20) return 'Hotspot 2.0';
    const ssid = (r.ssids || []).find(s => s && s !== 'Unknown' && s !== 'Hidden or Undetected') || '';
    if (/^DIRECT-/i.test(ssid))                                   return 'P2P / Direct';
    if (/(iphone|android|hotspot|mifi|pixel|galaxy)/i.test(ssid)) return 'Mobile Hotspot';
    if (/(carplay|tesla|bmw|audi|mercedes|toyota|ford|volvo)/i.test(ssid)) return 'Vehicle';
    if (/(gopro|70mai|viofo|thinkware|blackvue)/i.test(ssid)) return 'Camera / Dashcam';
    if (/(wyze|ring setup|arlo)/i.test(ssid)) return 'Camera Setup';
    const gen = (r.wifi_generations || []).find(g => g) || '';
    if (gen) return `${gen} Router`;
    return 'Access Point';
}

const _vendorTypeMap = [
    [/apple/i,                                'Apple device'],
    [/samsung/i,                              'Samsung device'],
    [/espressif/i,                            'IoT (ESP)'],
    [/amazon technologies/i,                  'Amazon device'],
    [/google|nest labs/i,                     'Camera/Smart Home (Nest)'],
    [/sonos/i,                                'Speaker (Sonos)'],
    [/ring inc/i,                             'Camera/Smart Home (Ring)'],
    [/arlo/i,                                 'Camera (Arlo)'],
    [/(hikvision|dahua|axis|vivotek|uniview|reolink|amcrest|wyze|lorex|swann|ezviz|foscam|yi technology)/i, 'Security Camera'],
    [/(gopro|garmin)/i,                       'Action Camera / GPS'],
    [/philips lighting|signify/i,             'Smart Lighting'],
    [/tesla/i,                                'Vehicle (Tesla)'],
    [/sony/i,                                 'Sony device'],
    [/lg electronics/i,                       'LG device'],
    [/microsoft/i,                            'Microsoft device'],
    [/(hewlett.?packard|hp inc)/i,            'Computer / Printer'],
    [/(brother industries|canon|epson|kyocera)/i, 'Printer'],
    [/intel corporate/i,                      'Computer (Intel Wi-Fi)'],
    [/realtek/i,                              'Generic / Realtek'],
    [/qualcomm/i,                             'Phone / Module'],
    [/broadcom/i,                             'Embedded'],
    [/xiaomi|beijing xiaomi/i,                'Xiaomi device'],
    [/(huawei|honor)/i,                       'Huawei device'],
    [/oneplus/i,                              'OnePlus phone'],
    [/(oppo|guangdong oppo)/i,                'Oppo phone'],
    [/bticino/i,                              'Smart Home (BTicino)'],
    [/(roku|chromecast)/i,                    'Streaming device'],
    [/(playstation|nintendo|xbox|sony interactive)/i, 'Console'],
    [/(d-link|tp-link|netgear|asus|linksys|ubiquiti|aruba|ruckus|mikrotik|zyxel|tenda)/i, 'Networking'],
];

function inferClientType(r) {
    if (r.is_streaming) return '🔴 LIVE Camera';
    const vendor = (r.vendors || []).find(v => v && v !== 'Unknown') || '';
    for (const [re, label] of _vendorTypeMap) {
        if (re.test(vendor)) return label;
    }
    const hex = (r.mac_address || '').replace(/:/g, '');
    if (hex.length >= 2) {
        const firstByte = parseInt(hex.slice(0, 2), 16);
        if (!isNaN(firstByte) && (firstByte & 0x02)) return 'Random MAC';
    }
    return '';
}

function typeCell(r, inferFn) {
    if (r.device_types && r.device_types.length) return escHtml(r.device_types.join(', '));
    const guess = inferFn(r);
    return guess
        ? `<span class="text-muted font-italic" title="Inferred from vendor / SSID">${escHtml(guess)}</span>`
        : '';
}

function getMostActive(data) {
    let mostActive = { count: 0 };
    for (const key in data) {
        if (data[key].count > mostActive.count) { mostActive = { ...data[key], mac: key }; }
    }
    return mostActive;
}

// ---------- graph helpers ----------

function signalColor(dBm) {
    if (dBm >= -50) return { bg: '#22c55e', border: '#16a34a' };
    if (dBm >= -65) return { bg: '#84cc16', border: '#65a30d' };
    if (dBm >= -75) return { bg: '#f59e0b', border: '#d97706' };
    if (dBm >= -85) return { bg: '#f97316', border: '#ea580c' };
    return { bg: '#ef4444', border: '#dc2626' };
}

function signalQuality(dBm) {
    if (dBm >= -50) return 'Excellent';
    if (dBm >= -65) return 'Good';
    if (dBm >= -75) return 'Fair';
    if (dBm >= -85) return 'Weak';
    return 'Poor';
}

function estimateRange(txPower, rssi) {
    if (txPower == null || rssi == null) return null;
    const d = Math.pow(10, (txPower - rssi) / 20);
    if (d < 1)  return '< 1 m';
    if (d < 3)  return '~1–3 m';
    if (d < 10) return '~3–10 m';
    return '> 10 m';
}

function advIntervalLabel(ms) {
    if (ms == null) return null;
    if (ms < 100)  return ms + ' ms (aggressive)';
    if (ms < 500)  return ms + ' ms (normal)';
    if (ms < 2000) return ms + ' ms (slow)';
    return ms + ' ms (low power)';
}

function showGraphOverlay(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('d-none'); el.classList.add('d-flex'); }
}

function hideGraphOverlay(id) {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('d-flex'); el.classList.add('d-none'); }
}

function fitWifi() {
    if (networkWifi) networkWifi.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
}

function fitBluetooth() {
    if (networkBluetooth) networkBluetooth.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
}

function toggleWifiLayout() {
    wifiHierarchical = !wifiHierarchical;
    const btn = document.getElementById('wifiLayoutBtn');
    btn.innerHTML = wifiHierarchical
        ? '<i class="fas fa-project-diagram mr-1"></i> Force Layout'
        : '<i class="fas fa-sitemap mr-1"></i> Hierarchical';
    if (lastWifiAps !== null) updateWifiGraph(lastWifiAps, lastWifiClients);
}

function onGraphHideRandomMacChange() {
    if (lastWifiAps !== null) updateWifiGraph(lastWifiAps, lastWifiClients);
}

function on3DMapHideRandomMacChange() {
    update3DNetworkMap(rawDataStore.aps, rawDataStore.clients);
}

// ---------- navigation ----------

const wifiSections      = ['aps', 'clients', 'probessids', 'activity', 'wifigraph', 'spectrum', 'assocmap', 'timeline', 'livefeed'];
const bluetoothSections = ['bluetooth', 'ble', 'blegraph', 'btanalytics', 'proximity', 'presence', 'bleinspector', 'bttimeline', 'btlivefeed'];
const analyticsSections = ['radar', 'clusters', 'occupancy', 'security', 'iot'];

function switchSection(name) {
    const target = document.getElementById('section-' + name);
    if (!target) return;
    document.querySelectorAll('.dw-section').forEach(s => s.classList.add('d-none'));
    document.querySelectorAll('.nav-sidebar .nav-link').forEach(l => l.classList.remove('active'));
    target.classList.remove('d-none');

    const link = document.querySelector(`.nav-link[onclick*="'${name}'"]`);
    if (link) link.classList.add('active');

    if (wifiSections.includes(name)) {
        const groupLink = document.querySelector('#nav-group-wifi > .nav-link');
        if (groupLink) groupLink.classList.add('active');
    } else if (bluetoothSections.includes(name)) {
        const groupLink = document.querySelector('#nav-group-bluetooth > .nav-link');
        if (groupLink) groupLink.classList.add('active');
    } else if (analyticsSections.includes(name)) {
        const groupLink = document.querySelector('#nav-group-analytics > .nav-link');
        if (groupLink) groupLink.classList.add('active');
    }

    if (window.location.hash !== '#' + name) {
        try { history.replaceState(null, '', '#' + name); } catch (_) {}
    }

    if (name === 'wifigraph' && lastWifiAps !== null) updateWifiGraph(lastWifiAps, lastWifiClients);
    if (name === 'blegraph' && lastBleBluetoothData !== null) updateBLEGraph(lastBleBluetoothData, lastBleData);
    if (name === 'radar' && Graph3D) {
        const container = document.getElementById('3d-graph');
        if (container) {
            setTimeout(() => {
                Graph3D.width(container.clientWidth);
                Graph3D.height(container.clientHeight);
            }, 50);
        }
    }
    if (name === 'livefeed') {
        startLiveFeed();
    } else {
        stopLiveFeed();
    }
    if (name === 'btlivefeed') {
        startBtLiveFeed();
    } else {
        stopBtLiveFeed();
    }
    if (name === 'settings') renderSettings();
}

function toggleNightMode() {
    const on = document.body.classList.toggle('night');
    try { localStorage.setItem('dw_night', on ? '1' : '0'); } catch (_) {}
    _syncNightButton(on);
}

function _syncNightButton(on) {
    const btn = document.getElementById('nightModeBtn');
    if (btn) btn.innerHTML = on
        ? '<i class="fas fa-sun mr-1"></i> Day Mode'
        : '<i class="fas fa-moon mr-1"></i> Night Mode';
    const chk = document.getElementById('settingsNightMode');
    if (chk) chk.checked = on;
}

(function _restoreNightEarly() {
    try {
        if (localStorage.getItem('dw_night') === '1') {
            document.documentElement.classList.add('night-pending');
        }
    } catch (_) {}
})();

// ---------- data fetch ----------

async function fetchData() {
    try {
        const url = lastFetchSince ? `/data?since=${encodeURIComponent(lastFetchSince)}` : '/data';
        const response = await authFetch(url);
        if (!response.ok) { console.warn(`/data returned ${response.status}`); return; }
        const data = await response.json();

        for (const row of data.aps || []) rawDataStore.aps[row.mac_address] = row;
        for (const row of data.clients || []) rawDataStore.clients[row.mac_address] = row;
        for (const row of data.bluetooths || []) rawDataStore.bluetooths[row.mac_address] = row;
        for (const row of data.bles || []) rawDataStore.bles[row.mac_address] = row;

        if (data.probe_requests) {
            const prMap = {};
            for (const pr of rawDataStore.probe_requests) prMap[pr.client_mac + '|' + pr.ssid] = pr;
            for (const pr of data.probe_requests) prMap[pr.client_mac + '|' + pr.ssid] = pr;
            rawDataStore.probe_requests = Object.values(prMap);
        }

        let maxSeen = null;
        const allRows = [].concat(data.aps || [], data.clients || [], data.bluetooths || [], data.bles || [], data.probe_requests || []);
        for (const row of allRows) {
            if (row.last_seen && (!maxSeen || row.last_seen > maxSeen)) maxSeen = row.last_seen;
        }
        if (maxSeen) lastFetchSince = maxSeen;

        const mAPs     = mergeAPs(rawDataStore.aps);
        const mClients = mergeClients(rawDataStore.clients);
        displayGeneralInfo(rawDataStore, mAPs, mClients);
        displayMiniStats(rawDataStore);
        displayAPs(mAPs);
        displayClients(mAPs, mClients);
        displayBluetooth(rawDataStore.bluetooths);
        displayBLE(rawDataStore.bles);
        updateAssocMap(rawDataStore.aps, rawDataStore.clients);
        update3DNetworkMap(rawDataStore.aps, rawDataStore.clients);
        updateChannelSpectrum(rawDataStore.aps);
        displayProbeSSIDs(rawDataStore.probe_requests, rawDataStore.clients);
        updateWifiGraph(rawDataStore.aps, rawDataStore.clients);
        updateBLEGraph(rawDataStore.bluetooths, rawDataStore.bles);
        updateActivityChart(mAPs, mClients);
        updateChannelSpectrum(rawDataStore.aps);
        updateAssocMap(rawDataStore.aps, rawDataStore.clients);
        updateBtAnalytics(rawDataStore.bluetooths, rawDataStore.bles);
        updateProximityChart(rawDataStore.bluetooths, rawDataStore.bles);
        updatePresenceChart(rawDataStore.bluetooths, rawDataStore.bles);
        updateBleInspector(rawDataStore.bles);
        displayIoT(rawDataStore.bles);
        fetchAnalytics();
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}

async function fetchAnalytics() {
    try {
        const occRes = await authFetch('/analytics/occupancy');
        if (occRes.ok) {
            updateOccupancyChart(await occRes.json());
        }
        
        const secRes = await authFetch('/analytics/security');
        if (secRes.ok) {
            displaySecurity(await secRes.json());
        }
        
        const clusRes = await authFetch('/analytics/clusters');
        if (clusRes.ok) {
            displayClusters(await clusRes.json());
        }
    } catch (e) {
        console.error("Analytics fetch error:", e);
    }
}

function update3DNetworkMap(aps, clients) {
    const container = document.getElementById('3d-graph');
    if (!container) return;

    const nodes = [];
    const links = [];
    const nodeIds = new Set();

    for (const ap of Object.values(aps)) {
        if (!nodeIds.has(ap.mac_address)) {
            nodes.push({
                id: ap.mac_address,
                name: ap.ssid || 'Unknown AP',
                group: 'ap',
                val: 10,
                color: '#3b82f6'
            });
            nodeIds.add(ap.mac_address);
        }
    }

    const map3dHideRandom = document.getElementById('map3dHideRandomMac')?.checked;
    for (const c of Object.values(clients)) {
        if (map3dHideRandom && isRandomMac(c.mac_address)) continue;
        if (!nodeIds.has(c.mac_address)) {
            let vendor = c.vendor || 'Unknown';
            nodes.push({
                id: c.mac_address,
                name: c.is_streaming ? 'LIVE Camera' : vendor,
                group: 'client',
                val: 5,
                color: c.is_streaming ? '#ef4444' : '#f59e0b'
            });
            nodeIds.add(c.mac_address);
        }

        if (c.associated_ap && c.associated_ap !== 'ff:ff:ff:ff:ff:ff') {
            if (!nodeIds.has(c.associated_ap)) {
                 nodes.push({
                    id: c.associated_ap,
                    name: 'Unknown AP',
                    group: 'ap',
                    val: 10,
                    color: '#3b82f6'
                 });
                 nodeIds.add(c.associated_ap);
            }
            links.push({
                source: c.mac_address,
                target: c.associated_ap
            });
        }
    }

    const gData = { nodes, links };

    if (!Graph3D && typeof ForceGraph3D === 'function') {
        Graph3D = ForceGraph3D()(container)
            .graphData(gData)
            .nodeLabel(node => `${node.name} (${node.id})`)
            .nodeColor(node => node.color)
            .nodeRelSize(4)
            .linkColor(() => 'rgba(255,255,255,0.2)')
            .backgroundColor('#111111')
            .enableNodeDrag(false)
            .width(container.clientWidth)
            .height(container.clientHeight);
            
        window.addEventListener('resize', () => {
            if (Graph3D && container.clientWidth) {
                Graph3D.width(container.clientWidth);
                Graph3D.height(container.clientHeight);
            }
        });
    } else if (Graph3D) {
        Graph3D.graphData(gData);
    }
}

function updateOccupancyChart(data) {
    const ctx = document.getElementById('occupancyChart');
    if (!ctx) return;
    
    const labels = data.map(d => {
        const date = new Date(d.hour + 'Z'); // Assume UTC for simplicity
        return date.getHours() + ':00';
    });
    const values = data.map(d => d.count);
    
    if (chartOccupancy) {
        chartOccupancy.data.labels = labels;
        chartOccupancy.data.datasets[0].data = values;
        chartOccupancy.update();
    } else {
        chartOccupancy = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Unique Devices',
                    data: values,
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.2)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    }
}

function displaySecurity(threats) {
    const container = document.getElementById('securityContainer');
    if (!container) return;
    
    if (threats.length === 0) {
        container.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle mr-2"></i> No immediate security threats detected.</div>';
        return;
    }
    
    let html = '';
    threats.forEach(t => {
        const badgeClass = t.severity === 'high' ? 'badge-danger' : (t.severity === 'medium' ? 'badge-warning' : 'badge-info');
        html += `<div class="alert alert-secondary text-dark" style="background:#f8f9fa; border-left:4px solid ${t.severity==='high'?'#dc3545':'#ffc107'}">
            <h5><span class="badge ${badgeClass} mr-2">${t.type}</span> ${t.mac}</h5>
            <p class="mb-0">${escHtml(t.description)}</p>
        </div>`;
    });
    container.innerHTML = html;
}

let clusterControlsInitialized = false;

async function initClusterControls() {
    if (clusterControlsInitialized) return;
    const container = document.getElementById('clusters-controls');
    if (!container) return;

    try {
        const res = await authFetch('/analytics/clusters/config');
        if (!res.ok) return;
        const config = await res.ok ? await res.json() : { threshold: 0.40 };
        const threshold = config.threshold || 0.40;

        container.innerHTML = `
            <div class="card card-outline card-primary shadow-sm">
                <div class="card-body py-2 px-3">
                    <div class="row align-items-center">
                        <div class="col-md-4">
                            <label class="mb-0 mr-2 small font-weight-bold">Clustering Sensitivity:</label>
                            <input type="range" class="custom-range align-middle" style="width:120px" 
                                   min="0.05" max="0.95" step="0.05" value="${threshold}" 
                                   id="clusterThresholdSlider" onchange="handleThresholdChange(this.value)">
                            <span class="ml-2 badge badge-primary" id="thresholdVal">${threshold}</span>
                        </div>
                        <div class="col-md-8 text-right">
                            <span class="small font-weight-bold mr-2 text-muted">Evidence Signals:</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-clock text-primary mr-1"></i>Temporal</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-microchip text-purple mr-1"></i>OUI</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-link text-indigo mr-1"></i>MAC Dist</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-wifi text-teal mr-1"></i>Shared AP</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-search text-cyan mr-1"></i>Probes</span>
                            <span class="badge badge-light border mr-1"><i class="fas fa-tag text-orange mr-1"></i>Vendor</span>
                            <span class="badge badge-light border"><i class="fas fa-broadcast-tower text-danger mr-1"></i>Beacon</span>
                        </div>
                    </div>
                </div>
            </div>`;
        clusterControlsInitialized = true;
    } catch (e) {
        console.error("Error initializing cluster controls:", e);
    }
}

let thresholdTimer = null;
function handleThresholdChange(val) {
    document.getElementById('thresholdVal').innerText = val;
    if (thresholdTimer) clearTimeout(thresholdTimer);
    thresholdTimer = setTimeout(() => setClusterThreshold(val), 400);
}

async function setClusterThreshold(val) {
    try {
        const res = await authFetch('/analytics/clusters/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threshold: parseFloat(val) })
        });
        if (res.ok) fetchAnalytics();
    } catch (e) {
        console.error("Error setting threshold:", e);
    }
}

function _srcBadge(src) {
    const map = {
        ap:     { cls: 'badge-primary',   label: 'Wi-Fi AP'  },
        client: { cls: 'badge-warning',   label: 'Wi-Fi Client' },
        bt:     { cls: 'badge-success',   label: 'BT Classic'  },
        ble:    { cls: 'badge-danger',    label: 'BLE'          },
    };
    const m = map[src] || { cls: 'badge-secondary', label: src || 'Unknown' };
    return `<span class="badge ${m.cls} mr-1" style="font-size:0.7em">${m.label}</span>`;
}

function _sigBadge(sig) {
    if (sig == null || sig === '') return '';
    const n = parseInt(sig, 10);
    if (isNaN(n)) return '';
    const { bg } = signalColor(n);
    return `<span class="badge mr-1" style="background:${bg};color:#fff;font-size:0.7em" title="${signalQuality(n)}">${n} dBm</span>`;
}

function _evBadge(sigLabel) {
    const map = {
        'temporal:co-occurrence': { icon: 'fa-clock', color: 'primary' },
        'mac:same-oui':           { icon: 'fa-microchip', color: 'purple' },
        'mac:adjacent-address':   { icon: 'fa-link', color: 'indigo' },
        'wifi:shared-ap':         { icon: 'fa-wifi', color: 'teal' },
        'wifi:shared-probes':     { icon: 'fa-search', color: 'cyan' },
        'meta:vendor-type-match': { icon: 'fa-tag', color: 'orange' },
        'ble:ibeacon-uuid-match': { icon: 'fa-broadcast-tower', color: 'danger' }
    };
    const key = Object.keys(map).find(k => sigLabel.startsWith(k)) || '';
    const m = map[key] || { icon: 'fa-info-circle', color: 'secondary' };
    return `<span class="badge badge-light border mr-1 mb-1" title="${sigLabel}">
        <i class="fas ${m.icon} text-${m.color} mr-1"></i>${sigLabel.split(':')[0]}
    </span>`;
}

function displayClusters(clusters) {
    const container = document.getElementById('clustersContainer');
    if (!container) return;

    initClusterControls();

    if (clusters.length === 0) {
        container.innerHTML = `
            <div class="text-center text-muted py-5">
              <i class="fas fa-object-group fa-3x mb-3"></i>
              <p>No entities found with current sensitivity.<br>
                 <small>Try lowering the threshold to see looser matches.</small>
              </p>
            </div>`;
        return;
    }

    let html = '<div class="row">';
    clusters.forEach(c => {
        const isCustomName = c.name && !c.name.startsWith('Entity');
        const displayName  = isCustomName ? escHtml(c.name) : `Entity <code style="font-size:0.8em">${c.id}</code>`;

        let evBadges = (c.signals || []).map(_evBadge).join('');
        const confPct = Math.round((c.confidence || 0) * 100);

        let sharedPills = '';
        (c.ssids || []).forEach(s => {
            sharedPills += `<span class="badge badge-info mr-1" title="Shared SSID"><i class="fas fa-wifi mr-1"></i>${escHtml(s)}</span>`;
        });
        (c.channels || []).forEach(ch => {
            sharedPills += `<span class="badge badge-secondary mr-1" title="Shared channel">CH&nbsp;${escHtml(ch)}</span>`;
        });

        let devRows = '';
        c.devices.forEach(d => {
            const ssidInfo    = d.ssid    ? `<span class="text-muted small ml-1"><i class="fas fa-wifi"></i>&nbsp;${escHtml(d.ssid)}</span>`    : '';
            const channelInfo = d.channel != null ? `<span class="text-muted small ml-1"><i class="fas fa-broadcast-tower"></i>&nbsp;CH&nbsp;${escHtml(String(d.channel))}</span>` : '';
            const fsLabel     = d.first_seen ? `<span class="text-muted small" title="First seen">${escHtml(d.first_seen.split('.')[0])}</span>` : '';
            const lsLabel     = d.last_seen  ? `<span class="text-muted small" title="Last seen">&nbsp;→&nbsp;${escHtml(d.last_seen.split('.')[0])}</span>` : '';

            devRows += `
              <tr>
                <td style="white-space:nowrap;font-family:monospace;font-size:0.78em">${escHtml(d.mac)}</td>
                <td>${_srcBadge(d.src)}${_sigBadge(d.signal)}</td>
                <td style="font-size:0.82em">${escHtml(d.vendor)}${ssidInfo}${channelInfo}</td>
                <td style="font-size:0.75em;white-space:nowrap">${fsLabel}${lsLabel}</td>
              </tr>`;
        });

        html += `
          <div class="col-xl-6 col-lg-12 mb-4">
            <div class="card shadow-sm h-100" style="border-top:3px solid #007bff">
              <div class="card-header d-flex align-items-center justify-content-between py-2" style="background:#f8f9fa">
                <div class="flex-grow-1">
                  <strong style="font-size:1.05em">${displayName}</strong>
                  <button class="btn btn-xs btn-outline-primary ml-2"
                          onclick="renameEntity('${c.id}', '${escHtml(c.name || '')}')"
                          title="Rename entity"><i class="fas fa-edit"></i></button>
                </div>
                <div class="text-right" style="min-width:120px">
                    <div class="small text-muted mb-1">Confidence: ${confPct}%</div>
                    <div class="progress" style="height:6px">
                        <div class="progress-bar bg-success" role="progressbar" style="width: ${confPct}%"></div>
                    </div>
                </div>
              </div>
              <div class="card-body py-2">
                <div class="mb-2 d-flex flex-wrap align-items-center">
                    <span class="small font-weight-bold mr-2">Signals:</span>
                    ${evBadges}
                </div>
                ${sharedPills ? `<div class="mb-2">${sharedPills}</div>` : ''}
                
                <div class="table-responsive mb-2">
                  <table class="table table-sm table-borderless mb-0" style="font-size:0.85em">
                    <thead class="thead-light">
                      <tr>
                        <th>MAC</th>
                        <th>Protocol / Signal</th>
                        <th>Vendor / Network</th>
                        <th>Seen</th>
                      </tr>
                    </thead>
                    <tbody>${devRows}</tbody>
                  </table>
                </div>

                <details class="small mt-2">
                    <summary class="text-primary cursor-pointer" style="cursor:pointer">Why are they together?</summary>
                    <div class="mt-2 text-muted bg-light p-2 rounded border">
                        ${c.reason}
                    </div>
                </details>
              </div>
            </div>
          </div>`;
    });
    html += '</div>';
    container.innerHTML = html;
}

function renameEntity(id, currentName) {
    document.getElementById('renameEntityId').value = id;
    document.getElementById('renameEntityName').value = currentName.startsWith("Entity") ? "" : currentName;
    $('#renameEntityModal').modal('show');
}

async function submitRenameEntity() {
    const id = document.getElementById('renameEntityId').value;
    const newName = document.getElementById('renameEntityName').value;
    
    try {
        const res = await authFetch(`/analytics/clusters/${id}/rename`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: newName })
        });
        
        if (res.ok) {
            $('#renameEntityModal').modal('hide');
            fetchAnalytics(); // Refresh to show new name
        } else {
            alert('Failed to rename entity.');
        }
    } catch (e) {
        console.error(e);
        alert('Error renaming entity.');
    }
}

function displayIoT(bles) {
    const iotRows = [];
    for (const mac in bles) {
        const ble = bles[mac];
        if (ble.manufacturer_data) {
            try {
                const mfr = JSON.parse(ble.manufacturer_data);
                let hasDecoded = false;
                let metrics = [];
                for (const key in mfr) {
                    if (key.endsWith('_decoded')) {
                        hasDecoded = true;
                        metrics.push(JSON.stringify(mfr[key]));
                    }
                }
                if (hasDecoded) {
                    iotRows.push({
                        mac: ble.mac_address,
                        brand: ble.brand || ble.vendor || 'Unknown',
                        type: ble.device_type || 'Unknown',
                        metrics: metrics.join('<br>')
                    });
                }
            } catch (e) {}
        }
    }
    dtIot = initOrRefreshDT(dtIot, 'iotTable', iotRows, [
        r => escHtml(r.mac),
        r => escHtml(r.brand),
        r => escHtml(r.type),
        r => r.metrics,
    ]);
}

// ---------- display ----------

function displayGeneralInfo(data, mergedAPs, mergedClients) {
    const apCount        = Object.keys(mergedAPs).length;
    const clientCount    = Object.keys(mergedClients).length;
    const realClientCount = Object.keys(mergedClients).filter(mac => !isRandomMac(mac)).length;
    const shownClientCount = _overviewRealOnly ? realClientCount : clientCount;
    const bluetoothCount = Object.keys(mergeBluetooths(data.bluetooths)).length;
    const bleCount       = Object.keys(mergeBLEs(data.bles)).length;
    const deviceCount    = apCount + shownClientCount + bluetoothCount + bleCount;
    const mostActiveAP     = getMostActive(data.aps);
    const mostActiveClient = getMostActive(data.clients);

    let apClientCount = {};
    for (const apMac in mergedAPs) apClientCount[apMac] = 0;
    for (const clientMac in mergedClients) {
        for (const ap of mergedClients[clientMac].associated_aps) {
            if (apClientCount[ap] !== undefined) apClientCount[ap]++;
        }
    }
    let maxClients = 0, maxApMac = null;
    for (const [apMac, count] of Object.entries(apClientCount)) {
        if (count > maxClients) { maxClients = count; maxApMac = apMac; }
    }
    const busyAP = maxApMac && mergedAPs[maxApMac]
        ? mergedAPs[maxApMac].ssids.map(escHtml).join(", ") + ` (${maxClients} clients)`
        : "N/A";

    function smallBox(color, count, label, icon, section) {
        const more = section
            ? `<a href="#${section}" class="small-box-footer" onclick="switchSection('${section}'); return false;">View <i class="fas fa-arrow-circle-right"></i></a>`
            : `<span class="small-box-footer">&nbsp;</span>`;
        return `<div class="col-lg-2 col-6">
          <div class="small-box bg-${color}">
            <div class="inner"><h3>${count}</h3><p>${label}</p></div>
            <div class="icon"><i class="${icon}"></i></div>
            ${more}
          </div>
        </div>`;
    }

    const clientTogglePill = _overviewRealOnly
        ? `<span class="badge badge-warning" style="cursor:pointer;font-size:0.7em" onclick="toggleOverviewRealOnly()" title="Showing real MACs only — click to show all">Real only</span>`
        : `<span class="badge badge-secondary" style="cursor:pointer;font-size:0.7em;opacity:0.75" onclick="toggleOverviewRealOnly()" title="Showing all MACs — click to exclude randomized">All MACs</span>`;
    const clientLabel = _overviewRealOnly ? 'Clients (real)' : 'Clients';
    const clientBox = `<div class="col-lg-2 col-6">
      <div class="small-box bg-warning">
        <div class="inner">
          <h3>${shownClientCount}</h3>
          <p>${clientLabel} ${clientTogglePill}</p>
        </div>
        <div class="icon"><i class="fas fa-laptop"></i></div>
        <a href="#clients" class="small-box-footer" onclick="switchSection('clients'); return false;">View <i class="fas fa-arrow-circle-right"></i></a>
      </div>
    </div>`;

    document.getElementById('generalInfo').innerHTML =
        smallBox('info',    deviceCount,    'Total Devices', 'fas fa-globe',          null) +
        smallBox('primary', apCount,        'Wi-Fi APs',     'fas fa-wifi',           'aps') +
        clientBox +
        smallBox('success', bluetoothCount, 'Bluetooth',     'fab fa-bluetooth-b',    'bluetooth') +
        smallBox('danger',  bleCount,       'BLE',           'fas fa-broadcast-tower','ble') + `
        <div class="col-lg-12">
          <div class="card card-outline card-primary">
            <div class="card-body p-0">
              <table class="table table-sm mb-0">
                <tbody>
                  <tr><th style="width:220px">AP with Most Clients</th><td>${busyAP}</td></tr>
                  <tr><th>Most Active AP</th><td>${escHtml(mostActiveAP.ssid || 'Unknown')} <span class="text-muted">(${mostActiveAP.count || 0} packets)</span></td></tr>
                  <tr><th>Most Active Client</th><td>${escHtml(mostActiveClient.mac_address || 'Unknown')} <span class="text-muted">(${mostActiveClient.count || 0} packets)</span></td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>`;
}

function displayMiniStats(data) {
    const apStats     = averageSignal(data.aps);
    const clientStats = averageSignal(data.clients);
    const btStats     = averageSignal(data.bluetooths);
    const bleStats    = averageSignal(data.bles);
    const apVendor    = mostCommonVendor(data.aps);
    const clientVendor = mostCommonVendor(data.clients);

    function infoBox(icon, color, label, value) {
        return `<div class="col-md-4 col-6">
          <div class="info-box">
            <span class="info-box-icon bg-${color}"><i class="${icon}"></i></span>
            <div class="info-box-content">
              <span class="info-box-text">${label}</span>
              <span class="info-box-number">${escHtml(value)}</span>
            </div>
          </div>
        </div>`;
    }

    document.getElementById('miniStatsBar').innerHTML =
        infoBox('fas fa-wifi', 'primary', 'AP Signal (avg/min/max)', `${apStats.avg} / ${apStats.min} / ${apStats.max} dBm`) +
        infoBox('fas fa-laptop', 'warning', 'Client Signal (avg/min/max)', `${clientStats.avg} / ${clientStats.min} / ${clientStats.max} dBm`) +
        infoBox('fab fa-bluetooth-b', 'success', 'BT Signal (avg/min/max)', `${btStats.avg} / ${btStats.min} / ${btStats.max} dBm`) +
        infoBox('fas fa-broadcast-tower', 'danger', 'BLE Signal (avg/min/max)', `${bleStats.avg} / ${bleStats.min} / ${bleStats.max} dBm`) +
        infoBox('fas fa-building', 'info', 'Top AP Vendor', apVendor) +
        infoBox('fas fa-user', 'secondary', 'Top Client Vendor', clientVendor);
}

function initOrRefreshDT(dtVar, tableId, rows, columns) {
    const rowData = rows.map(row => columns.map(c => c(row)));
    if (dtVar) {
        dtVar.clear();
        dtVar.rows.add(rowData);
        dtVar.draw(false);
        return dtVar;
    }
    const tbody = document.getElementById(tableId + 'Body');
    tbody.innerHTML = '';
    for (const cells of rowData) {
        const tr = document.createElement('tr');
        tr.innerHTML = cells.map(c => `<td>${c}</td>`).join('');
        tbody.appendChild(tr);
    }
    return $('#' + tableId).DataTable({ responsive: true, pageLength: _uiPageLength, order: [] });
}

function _pmfBadge(pmf) {
    if (!pmf) return '';
    const cls = pmf === 'Required' ? 'badge-success' : pmf === 'Capable' ? 'badge-info' : 'badge-secondary';
    return `<span class="badge ${cls}">${escHtml(pmf)}</span>`;
}

function _flagBadges(r) {
    const flags = [];
    if (r.has_11k) flags.push('<span class="badge badge-primary" title="802.11k Neighbor Reports">11k</span>');
    if (r.has_11v) flags.push('<span class="badge badge-primary" title="802.11v BSS Transition">11v</span>');
    if (r.has_11r) flags.push('<span class="badge badge-primary" title="802.11r Fast Roaming">11r</span>');
    if (r.is_mesh) flags.push('<span class="badge badge-warning" title="802.11s Mesh">Mesh</span>');
    if (r.is_hotspot20) flags.push('<span class="badge badge-info" title="Hotspot 2.0 / Passpoint">HS2</span>');
    return flags.join(' ');
}

function displayAPs(mergedAPs) {
    const merged = Object.values(mergedAPs);
    dtAps = initOrRefreshDT(dtAps, 'apsTable', merged, [
        r => escHtml(r.mac_address),
        r => escHtml(r.ssids.join(', ')),
        r => escHtml(r.vendors.join(', ')),
        r => typeCell(r, inferApType),
        r => r.signals.length ? r.signals.join(', ') : '',
        r => r.channels.length ? r.channels.join(', ') : '',
        r => r.bands.length ? r.bands.join(', ') : '',
        r => escHtml(r.securities.join(', ')),
        r => r.channel_widths.length ? r.channel_widths.join(', ') : '',
        r => escHtml(r.wifi_generations.join(', ')),
        r => r.spatial_streams ? `${r.spatial_streams}×${r.spatial_streams}` : '',
        r => escHtml(r.country_code || ''),
        r => r.station_count != null ? `${r.station_count} sta, ${r.channel_utilization ?? '?'}%` : '',
        r => _pmfBadge(r.pmf) + (_flagBadges(r) ? ' ' + _flagBadges(r) : ''),
        r => r.first_seen || '',
        r => r.last_seen || '',
        r => `<button class="btn btn-xs btn-danger" onclick="deleteDevice('ap','${escHtml(r.mac_address)}')"><i class="fas fa-trash"></i></button>`,
    ]);
}

function isRandomMac(mac) {
    if (!mac) return false;
    const firstOctet = parseInt(mac.split(':')[0], 16);
    return Number.isFinite(firstOctet) && (firstOctet & 0x02) !== 0;
}

function displayClients(mergedAPs, mergedClients) {
    const hideRandom = document.getElementById('hideRandomMac')?.checked;
    let arr = Object.values(mergedClients);
    if (hideRandom) arr = arr.filter(r => !isRandomMac(r.mac_address));
    dtClients = initOrRefreshDT(dtClients, 'clientsTable', arr, [
        r => {
            let label = escHtml(r.mac_address);
            if (r.is_streaming) label += ' <span class="badge badge-pill badge-live float-right">LIVE</span>';
            return label;
        },
        r => escHtml(r.vendors.join(', ')),
        r => typeCell(r, inferClientType),
        r => r.signals.length ? r.signals.join(', ') : '',
        r => r.associated_aps.map(apMac => {
            if (!apMac || apMac.toLowerCase() === 'ff:ff:ff:ff:ff:ff') return 'Unknown';
            return mergedAPs[apMac] ? `${escHtml(mergedAPs[apMac].ssids.join(', '))} (${escHtml(apMac)})` : `Unknown (${escHtml(apMac)})`;
        }).join(', ') || 'Unknown',
        r => r.counts.reduce((a, b) => a + b, 0),
        r => r.first_seen || '',
        r => r.last_seen || '',
        r => `<button class="btn btn-xs btn-danger" onclick="deleteDevice('client','${escHtml(r.mac_address)}')"><i class="fas fa-trash"></i></button>`,
    ]);
}

function displayBluetooth(bluetooths) {
    const merged = Object.values(mergeBluetooths(bluetooths));
    dtBluetooth = initOrRefreshDT(dtBluetooth, 'bluetoothTable', merged, [
        r => escHtml(r.names.join(', ')),
        r => escHtml(r.mac_address),
        r => r.signals.length ? r.signals.join(', ') : '',
        r => escHtml(r.vendors.join(', ')),
        r => escHtml(r.device_types.join(', ') || ''),
        r => escHtml(r.bluetooth_version || ''),
        r => escHtml(r.service_classes.join(', ')),
        r => r.first_seen || '',
        r => r.last_seen || '',
        r => `<button class="btn btn-xs btn-danger" onclick="deleteDevice('bt','${escHtml(r.mac_address)}')"><i class="fas fa-trash"></i></button>`,
    ]);
}

function displayBLE(bles) {
    const merged = Object.values(mergeBLEs(bles));
    dtBle = initOrRefreshDT(dtBle, 'bleTable', merged, [
        r => escHtml(r.mac_address),
        r => escHtml(r.names.join(', ')),
        r => r.signals.length ? r.signals.join(', ') : '',
        r => r.tx_power != null ? r.tx_power + ' dBm' : '',
        r => escHtml(r.vendors.join(', ')),
        r => escHtml(r.device_types.join(', ') || ''),
        r => r.first_seen || '',
        r => r.last_seen || '',
        r => `<button class="btn btn-xs btn-danger" onclick="deleteDevice('ble','${escHtml(r.mac_address)}')"><i class="fas fa-trash"></i></button>`,
    ]);
}

function displayProbeSSIDs(probeRequests, clients) {
    const vendorMap = {};
    for (const c of Object.values(clients)) {
        if (c.mac_address) vendorMap[c.mac_address] = c.vendor || '';
    }
    const hideRandom = document.getElementById('hideRandomMacProbe')?.checked;
    let rows = probeRequests.map(p => ({
        client_mac: p.client_mac,
        vendor: vendorMap[p.client_mac] || '',
        ssid: p.ssid,
        channel: p.channel || '',
        last_seen: p.last_seen,
    }));
    if (hideRandom) rows = rows.filter(r => !isRandomMac(r.client_mac));
    dtProbeSSIDs = initOrRefreshDT(dtProbeSSIDs, 'probeSSIDsTable', rows, [
        r => escHtml(r.client_mac),
        r => escHtml(r.vendor),
        r => escHtml(r.ssid),
        r => escHtml(r.channel),
        r => r.last_seen || '',
    ]);
}

// ---------- graphs ----------

function updateWifiGraph(aps, clients) {
    lastWifiAps = aps;
    lastWifiClients = clients;
    if (networkWifi !== null) networkWifi.destroy();
    showGraphOverlay('networkGraphOverlay');

    const nodesSet = new vis.DataSet();
    const edgesSet = new vis.DataSet();
    const apMap = {};
    const ssidGroups = {};

    const clientPackets = {};
    for (const c of Object.values(clients)) {
        const mac = c.mac_address.split('_')[0];
        clientPackets[mac] = (clientPackets[mac] || 0) + (c.count || 0);
    }

    for (const ap of Object.values(aps)) {
        const baseMac = ap.mac_address.split('_')[0];
        if (baseMac === 'ff:ff:ff:ff:ff:ff') continue;
        const ssid = ap.ssid || 'Unknown';
        if (!ssidGroups[ssid]) ssidGroups[ssid] = [];
        ssidGroups[ssid].push(ap);
    }

    const palette = vizPalette;
    const ssidColors = {};
    let colorIdx = 0;

    for (const [ssid, group] of Object.entries(ssidGroups)) {
        const color = palette[colorIdx++ % palette.length];
        ssidColors[ssid] = color;
        for (const ap of group) {
            const baseMac = ap.mac_address.split('_')[0];
            if (nodesSet.get(baseMac)) continue;
            let sig = parseInt(ap.signal_strength, 10);
            if (isNaN(sig)) sig = -70;
            const ssidLabel = ssid.length > 16 ? ssid.slice(0, 15) + '…' : ssid;
            const vendor = ap.vendor && ap.vendor !== 'Unknown' ? `\n${ap.vendor.slice(0, 16)}` : '';
            const genLabel = ap.wifi_generation ? ` [${ap.wifi_generation}]` : '';
            nodesSet.add({
                id: baseMac,
                label: `${ssidLabel}${vendor}${genLabel}\n${baseMac}`,
                shape: 'hexagon',
                size: Math.max(35, Math.min(65, (sig + 200) / 2)),
                level: 0,
                color: { background: color, border: '#111', highlight: { background: color, border: '#fff' } },
                borderWidth: 3,
                font: { color: '#fff', size: 12, face: 'monospace' },
                shadow: { enabled: true, color: color + '88', size: 14, x: 0, y: 0 },
                title: `<b>SSID:</b> ${escHtml(ssid)}<br><b>BSSID:</b> ${escHtml(baseMac)}<br><b>Vendor:</b> ${escHtml(ap.vendor || 'Unknown')}<br><b>Signal:</b> ${sig} dBm (${signalQuality(sig)})<br><b>Security:</b> ${escHtml(ap.security || 'Unknown')}<br><b>Channel:</b> ${escHtml(String(ap.channel || 'Unknown'))}<br><b>Generation:</b> ${escHtml(ap.wifi_generation || '?')}<br><b>Country:</b> ${escHtml(ap.country_code || '?')}`
            });
            apMap[baseMac] = true;
        }
    }

    const graphHideRandom = document.getElementById('graphHideRandomMac')?.checked;
    for (const client of Object.values(clients)) {
        const clientMac = client.mac_address.split('_')[0];
        const apId = client.associated_ap ? client.associated_ap.split('_')[0] : '';
        if (clientMac === 'ff:ff:ff:ff:ff:ff') continue;
        if (graphHideRandom && isRandomMac(clientMac)) continue;
        let sig = parseInt(client.signal_strength, 10);
        if (isNaN(sig)) sig = -75;
        const sc = signalColor(sig);
        const packets = clientPackets[clientMac] || client.count || 0;
        const vendorLine = client.vendor && client.vendor !== 'Unknown' ? `\n${client.vendor.slice(0, 16)}` : '';
        if (!nodesSet.get(clientMac)) {
            nodesSet.add({
                id: clientMac,
                label: `${clientMac}${vendorLine}`,
                shape: 'dot',
                size: Math.max(12, Math.min(28, 12 + Math.log(packets + 1) * 3)),
                level: 1,
                color: { background: sc.bg, border: sc.border, highlight: { background: sc.bg, border: '#fff' } },
                borderWidth: 2,
                font: { color: '#fff', size: 10, face: 'monospace' },
                shadow: { enabled: true, color: sc.bg + '66', size: 8, x: 0, y: 0 },
                title: `<b>Client:</b> ${escHtml(client.mac_address)}<br><b>Vendor:</b> ${escHtml(client.vendor || 'Unknown')}<br><b>Signal:</b> ${sig} dBm (${signalQuality(sig)})<br><b>Packets:</b> ${packets}`
            });
        }
        if (apMap[apId]) {
            edgesSet.add({
                from: clientMac, to: apId,
                arrows: { to: { enabled: true, scaleFactor: 0.6 } },
                color: { color: sc.bg + 'bb', highlight: sc.bg, opacity: 0.8 },
                width: Math.max(1, Math.min(7, 1 + Math.log(packets + 1))),
                smooth: { type: wifiHierarchical ? 'cubicBezier' : 'dynamic' },
                title: `${escHtml(clientMac)} → ${escHtml(apId)}<br>Packets: ${packets}`
            });
        }
    }

    let legendHTML = '<div class="d-flex flex-wrap align-items-center mb-1"><b class="mr-2">AP SSIDs:</b>';
    for (const [ssid, color] of Object.entries(ssidColors)) {
        legendHTML += `<span class="badge mr-1" style="background:${color};color:#fff;font-size:0.8em;">${escHtml(ssid)}</span>`;
    }
    legendHTML += '</div><div class="d-flex flex-wrap align-items-center"><b class="mr-2">Client signal:</b>';
    for (const [label, dBm] of [['Excellent ≥-50', -45], ['Good ≥-65', -60], ['Fair ≥-75', -70], ['Weak ≥-85', -80], ['Poor <-85', -90]]) {
        const sc = signalColor(dBm);
        legendHTML += `<span class="badge mr-1" style="background:${sc.bg};color:#fff;font-size:0.8em;">${label}</span>`;
    }
    legendHTML += '</div>';
    document.getElementById('wifi-legend').innerHTML = legendHTML;

    const physicsConfig = wifiHierarchical
        ? { enabled: true, solver: 'hierarchicalRepulsion', hierarchicalRepulsion: { nodeDistance: 130, centralGravity: 0, springLength: 80, springConstant: 0.01, damping: 0.5 } }
        : { enabled: true, stabilization: { iterations: 200 }, barnesHut: { gravitationalConstant: -30000, centralGravity: 0.2, springLength: 120, springConstant: 0.04, damping: 0.12, avoidOverlap: 0.3 } };

    const layoutConfig = wifiHierarchical
        ? { hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: 160, nodeSpacing: 120 } }
        : { improvedLayout: false, randomSeed: 2 };

    networkWifi = new vis.Network(document.getElementById('networkGraph'), { nodes: nodesSet, edges: edgesSet }, {
        interaction: { hover: true, tooltipDelay: 100, navigationButtons: false, keyboard: true },
        physics: physicsConfig, layout: layoutConfig,
        nodes: { borderWidth: 2 }, edges: { shadow: false }
    });

    if (nodesSet.length === 0) { hideGraphOverlay('networkGraphOverlay'); return; }

    const wifiStabilizeTimeout = setTimeout(() => hideGraphOverlay('networkGraphOverlay'), 8000);
    networkWifi.on('stabilized', () => {
        clearTimeout(wifiStabilizeTimeout);
        networkWifi.setOptions({ physics: { enabled: false } });
        networkWifi.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } });
        hideGraphOverlay('networkGraphOverlay');
    });
}

function updateBLEGraph(bluetooths, bles) {
    lastBleBluetoothData = bluetooths;
    lastBleData = bles;
    if (networkBluetooth !== null) networkBluetooth.destroy();
    showGraphOverlay('BLEGraphOverlay');

    const nodesSet = new vis.DataSet();

    for (const ble of Object.values(bles)) {
        let sig = parseInt(ble.signal_strength, 10);
        if (isNaN(sig)) sig = -75;
        const sc = signalColor(sig);
        const vendor = ble.vendor && ble.vendor !== 'Unknown' ? `\n${ble.vendor.slice(0, 16)}` : '';
        const rangeTip = ble.tx_power != null ? `<br><b>Range est.:</b> ${estimateRange(ble.tx_power, sig)}` : '';
        nodesSet.add({
            id: 'ble_' + ble.mac_address,
            label: `${ble.mac_address}${vendor}\n${sig} dBm`,
            shape: 'dot',
            size: Math.max(14, Math.min(36, 14 + (sig + 100) / 4)),
            color: { background: sc.bg, border: sc.border, highlight: { background: sc.bg, border: '#fff' } },
            borderWidth: 2,
            font: { color: '#fff', size: 11, face: 'monospace' },
            shadow: { enabled: true, color: sc.bg + '66', size: 8, x: 0, y: 0 },
            title: `<b>Type:</b> BLE<br><b>MAC:</b> ${escHtml(ble.mac_address)}<br><b>Vendor:</b> ${escHtml(ble.vendor || 'Unknown')}<br><b>Signal:</b> ${sig} dBm (${signalQuality(sig)})${rangeTip}`
        });
    }

    for (const bt of Object.values(bluetooths)) {
        let sig = parseInt(bt.signal_strength, 10);
        if (isNaN(sig)) sig = -50;
        const sc = signalColor(sig);
        const name = (bt.name || 'Unknown').slice(0, 16);
        nodesSet.add({
            id: 'bt_' + bt.mac_address,
            label: `${name}\n${bt.mac_address}\n${sig} dBm`,
            shape: 'diamond',
            size: Math.max(20, Math.min(44, 20 + (sig + 100) / 4)),
            color: { background: sc.bg, border: sc.border, highlight: { background: sc.bg, border: '#fff' } },
            borderWidth: 3,
            font: { color: '#fff', size: 12, face: 'monospace' },
            shadow: { enabled: true, color: sc.bg + '88', size: 12, x: 0, y: 0 },
            title: `<b>Type:</b> Bluetooth Classic<br><b>Name:</b> ${escHtml(bt.name || 'Unknown')}<br><b>MAC:</b> ${escHtml(bt.mac_address)}<br><b>Vendor:</b> ${escHtml(bt.vendor || 'Unknown')}<br><b>BT Version:</b> ${escHtml(bt.bluetooth_version || '?')}<br><b>Signal:</b> ${sig} dBm (${signalQuality(sig)})`
        });
    }

    let legendHTML = '<div class="d-flex flex-wrap align-items-center mb-1"><b class="mr-2">Signal Quality:</b>';
    for (const [label, dBm] of [['Excellent ≥-50', -45], ['Good ≥-65', -60], ['Fair ≥-75', -70], ['Weak ≥-85', -80], ['Poor <-85', -90]]) {
        const sc = signalColor(dBm);
        legendHTML += `<span class="badge mr-1" style="background:${sc.bg};color:#fff;font-size:0.8em;">${label}</span>`;
    }
    legendHTML += '</div><div class="d-flex align-items-center"><b class="mr-2">Shape:</b>';
    legendHTML += '<span class="mr-3">● BLE (circle)</span><span>◆ Bluetooth Classic (diamond)</span>';
    legendHTML += '</div>';
    document.getElementById('ble-legend').innerHTML = legendHTML;

    networkBluetooth = new vis.Network(document.getElementById('BLEGraph'), { nodes: nodesSet, edges: new vis.DataSet() }, {
        interaction: { hover: true, tooltipDelay: 100, navigationButtons: false, keyboard: true },
        physics: { enabled: true, stabilization: { iterations: 150 }, solver: 'repulsion',
            repulsion: { centralGravity: 0.2, springLength: 130, springConstant: 0.05, nodeDistance: 120, damping: 0.2 } },
        layout: { improvedLayout: false, randomSeed: 42 },
        nodes: { borderWidth: 2 }
    });

    if (nodesSet.length === 0) { hideGraphOverlay('BLEGraphOverlay'); return; }

    const bleStabilizeTimeout = setTimeout(() => hideGraphOverlay('BLEGraphOverlay'), 8000);
    networkBluetooth.on('stabilized', () => {
        clearTimeout(bleStabilizeTimeout);
        networkBluetooth.setOptions({ physics: { enabled: false } });
        networkBluetooth.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } });
        hideGraphOverlay('BLEGraphOverlay');
    });
}

function updateActivityChart(mergedAPs, mergedClients) {
    const devices = [];
    for (const ap of Object.values(mergedAPs)) {
        const total = ap.raw.reduce((s, d) => s + (d.count || 0), 0);
        if (total > 0) devices.push({ name: ap.ssids.join(', ') || ap.mac_address, packets: total });
    }
    for (const client of Object.values(mergedClients)) {
        const total = client.counts.reduce((a, b) => a + b, 0);
        if (total > 0) devices.push({ name: client.mac_address, packets: total });
    }
    devices.sort((a, b) => b.packets - a.packets);
    const top = devices.slice(0, 10);
    const ctx = document.getElementById('activityChart').getContext('2d');
    if (activityChart) activityChart.destroy();
    activityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: top.map(d => d.name),
            datasets: [{ label: 'Number of Packets', data: top.map(d => d.packets), backgroundColor: 'rgba(37,99,235,0.6)', borderColor: 'rgba(37,99,235,1)', borderWidth: 1 }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
            scales: { y: { beginAtZero: true, title: { display: true, text: 'Packets' } }, x: { title: { display: true, text: 'Device' } } }
        }
    });
}

// ---------- channel spectrum ----------

function buildSpectrumSeries(aps, xMin, xMax) {
    const nPts = 200;
    const step = (xMax - xMin) / (nPts - 1);
    return aps.map((ap, idx) => {
        const color  = vizPalette[idx % vizPalette.length];
        const height = Math.max(4, Math.min(78, (ap.signal || -85) + 100));
        const sigma  = 2.0;
        const data   = [];
        for (let i = 0; i < nPts; i++) {
            const x = +(xMin + step * i).toFixed(2);
            const y = +(height * Math.exp(-((x - ap.channel) ** 2) / (2 * sigma ** 2))).toFixed(2);
            data.push({ x, y });
        }
        return {
            label: `${ap.ssid}  ch${ap.channel}  (${ap.signal} dBm)`,
            data, borderColor: color, backgroundColor: color + '40',
            fill: 'origin', tension: 0.4, borderWidth: 2, pointRadius: 0,
        };
    });
}

function spectrumOpts(xLabel, xMin, xMax) {
    return {
        responsive: true, animation: false,
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
        scales: {
            x: { type: 'linear', min: xMin, max: xMax, title: { display: true, text: xLabel }, ticks: { stepSize: 1 } },
            y: { min: 0, max: 82, title: { display: true, text: 'Signal Level' }, ticks: { callback: v => v > 0 ? (v - 100) + ' dBm' : '' } },
        },
    };
}

function renderSpectrumChart(existing, canvasId, datasets, xMin, xMax, xLabel) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return existing;
    if (existing) { existing.data.datasets = datasets; existing.update('none'); return existing; }
    return new Chart(canvas, { type: 'line', data: { datasets }, options: spectrumOpts(xLabel, xMin, xMax) });
}

function updateChannelSpectrum(aps) {
    const band24 = [], band5 = [];
    for (const ap of Object.values(aps)) {
        const ch  = parseInt(ap.channel);
        const sig = parseInt(ap.signal_strength);
        if (isNaN(ch)) continue;
        const entry = { mac: ap.mac_address, ssid: ap.ssid || '?', channel: ch, signal: isNaN(sig) ? -85 : sig };
        if (ch <= 14) band24.push(entry); else band5.push(entry);
    }
    chartSpectrum24 = renderSpectrumChart(chartSpectrum24, 'spectrumChart24', buildSpectrumSeries(band24, 0.5, 13.5), 0.5, 13.5, 'Channel (2.4 GHz)');
    chartSpectrum5  = renderSpectrumChart(chartSpectrum5,  'spectrumChart5',  buildSpectrumSeries(band5, 34, 168),   34,  168,  'Channel (5 GHz)');
}

// ---------- association map ----------

function signalBadge(dBm) {
    const s = parseInt(dBm);
    if (isNaN(s))  return 'badge-secondary';
    if (s >= -50)  return 'badge-success';
    if (s >= -65)  return 'badge-info';
    if (s >= -75)  return 'badge-warning';
    return 'badge-danger';
}

function updateAssocMap(aps, clients) {
    const container = document.getElementById('assocMapContainer');
    if (!container) return;

    const ssidGroups = {};
    for (const ap of Object.values(aps)) {
        const ssid = ap.ssid || 'Unknown';
        if (!ssidGroups[ssid]) ssidGroups[ssid] = [];
        ssidGroups[ssid].push(ap);
    }

    const clientsByAP = {};
    const unassociated = [];
    for (const c of Object.values(clients)) {
        const ap = c.associated_ap;
        if (ap && ap !== 'ff:ff:ff:ff:ff:ff') {
            if (!clientsByAP[ap]) clientsByAP[ap] = [];
            clientsByAP[ap].push(c);
        } else {
            unassociated.push(c);
        }
    }

    if (!Object.keys(ssidGroups).length) {
        container.innerHTML = '<p class="text-muted">No Wi-Fi data available.</p>';
        return;
    }

    let html = '';
    let si = 0;
    for (const [ssid, apList] of Object.entries(ssidGroups)) {
        const total  = apList.reduce((n, ap) => n + (clientsByAP[ap.mac_address] || []).length, 0);
        const ssidId = 'am-s' + (si++);
        html += `
        <div class="assoc-group">
          <div class="assoc-header assoc-ssid-hdr" onclick="toggleAssoc('${ssidId}')">
            <i class="fas fa-chevron-down assoc-chv" id="${ssidId}-chv"></i>
            <i class="fas fa-wifi text-primary mx-2"></i><strong>${escHtml(ssid)}</strong>
            <span class="badge badge-primary ml-2">${apList.length} AP${apList.length > 1 ? 's' : ''}</span>
            <span class="badge badge-success ml-1">${total} client${total !== 1 ? 's' : ''}</span>
          </div>
          <div class="assoc-body" id="${ssidId}">`;
        let ai = 0;
        for (const ap of apList) {
            const apClients = clientsByAP[ap.mac_address] || [];
            const apId      = ssidId + '-a' + (ai++);
            const hasClients = apClients.length > 0;
            html += `
            <div class="assoc-ap">
              <div class="assoc-header assoc-ap-hdr" onclick="toggleAssoc('${apId}')">
                <i class="fas fa-chevron-${hasClients ? 'down' : 'right'} assoc-chv" id="${apId}-chv"></i>
                <i class="fas fa-broadcast-tower text-warning mx-2"></i>
                <code>${escHtml(ap.mac_address)}</code>
                <span class="badge badge-secondary ml-2">Ch ${ap.channel || '?'}</span>
                <span class="badge ${signalBadge(ap.signal_strength)} ml-1">${ap.signal_strength ?? '?'} dBm</span>
                <span class="text-muted small ml-2">${escHtml(ap.security || '')}</span>
                ${ap.wifi_generation ? `<span class="badge badge-info ml-2">${escHtml(ap.wifi_generation)}</span>` : ''}
                ${ap.country_code ? `<span class="badge badge-secondary ml-1">${escHtml(ap.country_code)}</span>` : ''}
                ${hasClients ? `<span class="badge badge-info ml-2">${apClients.length} client${apClients.length > 1 ? 's' : ''}</span>` : ''}
              </div>
              <div class="assoc-body" id="${apId}"${!hasClients ? ' style="display:none"' : ''}>`;
            if (!hasClients) {
                html += '<p class="text-muted small my-1 ml-4">No associated clients</p>';
            }
            for (const cl of apClients) {
                html += `
                <div class="assoc-client">
                  <i class="fas fa-laptop text-info mr-2"></i>
                  <code>${escHtml(cl.mac_address)}</code>
                  <span class="badge ${signalBadge(cl.signal_strength)} ml-2">${cl.signal_strength ?? '?'} dBm</span>
                  ${cl.vendor && cl.vendor !== 'Unknown' ? `<span class="text-muted small ml-2">${escHtml(cl.vendor)}</span>` : ''}
                  <span class="badge badge-light ml-2">${cl.count || 0} pkts</span>
                </div>`;
            }
            html += '</div></div>';
        }
        html += '</div></div>';
    }

    if (unassociated.length) {
        const uId = 'am-unassoc';
        html += `
        <div class="assoc-group mt-2">
          <div class="assoc-header assoc-ssid-hdr" onclick="toggleAssoc('${uId}')">
            <i class="fas fa-chevron-down assoc-chv" id="${uId}-chv"></i>
            <i class="fas fa-question-circle text-secondary mx-2"></i>
            <strong>Unassociated Clients</strong>
            <span class="badge badge-secondary ml-2">${unassociated.length}</span>
          </div>
          <div class="assoc-body" id="${uId}">`;
        for (const cl of unassociated) {
            html += `
            <div class="assoc-client">
              <i class="fas fa-laptop text-secondary mr-2"></i>
              <code>${escHtml(cl.mac_address)}</code>
              <span class="badge ${signalBadge(cl.signal_strength)} ml-2">${cl.signal_strength ?? '?'} dBm</span>
              ${cl.vendor && cl.vendor !== 'Unknown' ? `<span class="text-muted small ml-2">${escHtml(cl.vendor)}</span>` : ''}
            </div>`;
        }
        html += '</div></div>';
    }

    container.innerHTML = html;
}

function toggleAssoc(id) {
    const body    = document.getElementById(id);
    const chevron = document.getElementById(id + '-chv');
    if (!body) return;
    const hidden = body.style.display === 'none';
    body.style.display = hidden ? '' : 'none';
    if (chevron) {
        chevron.classList.toggle('fa-chevron-down', hidden);
        chevron.classList.toggle('fa-chevron-right', !hidden);
    }
}

// ---------- signal timeline ----------

async function fetchReadings() {
    try {
        const resp = await authFetch('/readings');
        if (!resp.ok) { console.warn(`/readings returned ${resp.status}`); return; }
        const readings = await resp.json();
        updateSignalTimeline(readings);
        updateBtSignalTimeline(readings);
        const ts = new Date().toLocaleTimeString();
        const el = document.getElementById('timelineLastUpdate');
        if (el) el.textContent = 'Updated ' + ts;
        const el2 = document.getElementById('timelineBtLastUpdate');
        if (el2) el2.textContent = 'Updated ' + ts;
    } catch (e) {
        console.error('Timeline fetch error:', e);
    }
}

function _buildTimelineChart(canvasId, chartRef, readings, types) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return chartRef;
    const filtered = readings.filter(r => types.includes(r.type));
    if (!filtered.length) return chartRef;

    const byMac = {};
    for (const r of filtered) {
        if (!byMac[r.mac]) byMac[r.mac] = [];
        byMac[r.mac].push(r);
    }
    const typeLabel = { ap: 'AP', client: 'CLI', bt: 'BT', ble: 'BLE' };
    const allTs     = [...new Set(filtered.map(r => r.ts))].sort();
    const tsLabels  = allTs.map(ts => ts.slice(11, 19));
    const datasets  = Object.entries(byMac).map(([mac, pts], idx) => {
        const color = vizPalette[idx % vizPalette.length];
        const tsMap = {};
        pts.forEach(p => { tsMap[p.ts] = p.signal; });
        const type = pts[0].type;
        const tag = typeLabel[type] || type;
        
        let devName = null;
        if (type === 'ap' && rawDataStore.aps[mac]) {
            devName = rawDataStore.aps[mac].ssid;
        } else if (type === 'client' && rawDataStore.clients[mac]) {
            const vendor = rawDataStore.clients[mac].vendor || '';
            const brand = rawDataStore.clients[mac].brand || '';
            devName = brand && brand !== 'Unknown' ? brand : (vendor !== 'Unknown' ? vendor : null);
        } else if (type === 'bt' && rawDataStore.bluetooths[mac]) {
            devName = rawDataStore.bluetooths[mac].name;
        } else if (type === 'ble' && rawDataStore.bles[mac]) {
            devName = rawDataStore.bles[mac].name;
        }

        let labelText = `${mac.slice(-8)}`;
        if (devName && devName !== 'Unknown' && devName !== 'Hidden') {
            labelText += ` [${devName}]`;
        }
        labelText += ` (${tag})`;

        return {
            label: labelText,
            data: allTs.map(ts => tsMap[ts] ?? null),
            borderColor: color, backgroundColor: 'transparent',
            borderWidth: 2, pointRadius: 2, tension: 0.3, spanGaps: true,
        };
    });

    if (chartRef) {
        chartRef.data.labels = tsLabels;
        chartRef.data.datasets = datasets;
        chartRef.update('none');
        return chartRef;
    }
    return new Chart(canvas, {
        type: 'line',
        data: { labels: tsLabels, datasets },
        options: {
            responsive: true, animation: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } } },
            scales: {
                x: { title: { display: true, text: 'Time' }, ticks: { maxTicksLimit: 20, maxRotation: 45 } },
                y: { title: { display: true, text: 'Signal (dBm)' }, ticks: { callback: v => v + ' dBm' } },
            },
        },
    });
}

function updateSignalTimeline(readings) {
    if (!readings || !readings.length) return;
    chartTimeline        = _buildTimelineChart('timelineChart',        chartTimeline,        readings, ['ap']);
    chartTimelineClients = _buildTimelineChart('timelineClientsChart', chartTimelineClients, readings, ['client']);
}

function updateBtSignalTimeline(readings) {
    if (!readings || !readings.length) return;
    chartBtTimeline = _buildTimelineChart('timelineBtChart', chartBtTimeline, readings, ['bt', 'ble']);
}

// ---------- bluetooth analytics ----------

const _emptyDonutPlugin = {
    id: 'emptyDonutLabel',
    afterDraw(chart) {
        const ds = chart.data.datasets[0];
        const total = (ds && ds.data || []).reduce((a, b) => a + (b || 0), 0);
        if (total > 0) return;
        const { ctx, chartArea } = chart;
        if (!chartArea) return;
        const cx = (chartArea.left + chartArea.right) / 2;
        const cy = (chartArea.top + chartArea.bottom) / 2;
        ctx.save();
        ctx.fillStyle = '#9ca3af';
        ctx.font = '13px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('No data', cx, cy);
        ctx.restore();
    }
};

function buildDonutChart(canvasId, existing, labels, values, title) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return existing;
    const colors = labels.map((_, i) => vizPalette[i % vizPalette.length]);
    if (existing) {
        existing.data.labels = labels;
        existing.data.datasets[0].data = values;
        existing.data.datasets[0].backgroundColor = colors;
        existing.update('none');
        return existing;
    }
    return new Chart(canvas, {
        type: 'doughnut',
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 2 }] },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: title, font: { size: 13 } },
                legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } },
            }
        },
        plugins: [_emptyDonutPlugin],
    });
}

function updateBtAnalytics(bluetooths, bles) {
    function countField(devices, field) {
        const counts = {};
        for (const d of Object.values(devices)) {
            const v = d[field] || 'Unknown';
            counts[v] = (counts[v] || 0) + 1;
        }
        return counts;
    }
    const btTypeC   = countField(bluetooths, 'device_type');
    const btVendorC = countField(bluetooths, 'vendor');
    const bleTypeC  = countField(bles, 'device_type');
    const bleVendorC = countField(bles, 'vendor');

    chartBtType   = buildDonutChart('chartBtType',   chartBtType,   Object.keys(btTypeC),   Object.values(btTypeC),   'BT Classic – Device Types');
    chartBtVendor = buildDonutChart('chartBtVendor', chartBtVendor, Object.keys(btVendorC), Object.values(btVendorC), 'BT Classic – Vendors');
    chartBleType  = buildDonutChart('chartBleType',  chartBleType,  Object.keys(bleTypeC),  Object.values(bleTypeC),  'BLE – Device Types');
    chartBleVendor = buildDonutChart('chartBleVendor', chartBleVendor, Object.keys(bleVendorC), Object.values(bleVendorC), 'BLE – Vendors');
}

// ---------- proximity chart ----------

function macToXY(mac, rssi) {
    let h = 0;
    for (let i = 0; i < mac.length; i++) h = (Math.imul(31, h) + mac.charCodeAt(i)) | 0;
    const angle  = ((h >>> 0) % 10000) / 10000 * 2 * Math.PI;
    const jitter = ((h >>> 0) % 100) / 1000;
    const sig = (typeof rssi === 'number' && !isNaN(rssi)) ? rssi : -90;
    let baseR;
    if      (sig >= -50) baseR = 0.12;
    else if (sig >= -65) baseR = 0.30;
    else if (sig >= -75) baseR = 0.50;
    else if (sig >= -85) baseR = 0.68;
    else                 baseR = 0.85;
    const r = Math.min(0.95, baseR + jitter);
    return { x: +(r * Math.cos(angle)).toFixed(3), y: +(r * Math.sin(angle)).toFixed(3) };
}

const _proximityRingPlugin = {
    id: 'proximityRings',
    beforeDraw(chart) {
        const { ctx, chartArea } = chart;
        if (!chartArea) return;
        const { left, right, top, bottom } = chartArea;
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2;
        const maxR = Math.min(right - left, bottom - top) / 2;
        const rings = [
            { r: 0.95, fill: '#ef444418' }, { r: 0.75, fill: '#f9731618' },
            { r: 0.55, fill: '#f59e0b18' }, { r: 0.35, fill: '#84cc1618' },
            { r: 0.15, fill: '#22c55e18' },
        ];
        ctx.save();
        for (const ring of rings) {
            ctx.beginPath();
            ctx.arc(cx, cy, maxR * ring.r, 0, 2 * Math.PI);
            ctx.fillStyle = ring.fill;
            ctx.fill();
        }
        ctx.restore();
    }
};

function updateProximityChart(bluetooths, bles) {
    const canvas = document.getElementById('proximityChart');
    if (!canvas) return;

    const btData  = Object.values(bluetooths).map(bt => {
        const sig = parseInt(bt.signal_strength);
        const pos = macToXY(bt.mac_address, isNaN(sig) ? null : sig);
        return { ...pos, r: 10, _mac: bt.mac_address, _name: bt.name || 'Unknown', _sig: isNaN(sig) ? -90 : sig };
    });
    const bleData = Object.values(bles).map(ble => {
        const sig = parseInt(ble.signal_strength);
        const pos = macToXY(ble.mac_address, isNaN(sig) ? null : sig);
        return { ...pos, r: 7, _mac: ble.mac_address, _name: ble.name || 'Unknown', _sig: isNaN(sig) ? -90 : sig };
    });

    const datasets = [
        { label: 'Bluetooth Classic', data: btData,
          backgroundColor: ctx => signalColor(ctx.dataset.data[ctx.dataIndex]?._sig ?? -90).bg + 'bb',
          borderColor:     ctx => signalColor(ctx.dataset.data[ctx.dataIndex]?._sig ?? -90).border, borderWidth: 2 },
        { label: 'BLE', data: bleData,
          backgroundColor: ctx => signalColor(ctx.dataset.data[ctx.dataIndex]?._sig ?? -90).bg + '99',
          borderColor:     ctx => signalColor(ctx.dataset.data[ctx.dataIndex]?._sig ?? -90).border, borderWidth: 1 },
    ];

    if (chartProximity) { chartProximity.data.datasets = datasets; chartProximity.update('none'); return; }
    chartProximity = new Chart(canvas, {
        type: 'bubble', data: { datasets },
        options: {
            responsive: true, animation: false, aspectRatio: 1,
            plugins: {
                legend: { position: 'bottom' },
                tooltip: { callbacks: { label: ctx => { const d = ctx.raw; return [`${d._name} (${d._mac})`, `Signal: ${d._sig} dBm`]; } } }
            },
            scales: { x: { min: -1, max: 1, display: false }, y: { min: -1, max: 1, display: false } },
        },
        plugins: [_proximityRingPlugin],
    });
}

// ---------- device presence ----------

function updatePresenceChart(bluetooths, bles) {
    const canvas = document.getElementById('presenceChart');
    if (!canvas) return;

    function parseTs(ts) { return ts ? new Date(ts.replace(' ', 'T')).getTime() : null; }

    const rows = [];
    for (const bt of Object.values(bluetooths)) {
        rows.push({ label: ((bt.name && bt.name !== 'Unknown') ? bt.name : bt.mac_address).slice(0, 22), start: parseTs(bt.first_seen), end: parseTs(bt.last_seen), color: '#2563ebcc' });
    }
    for (const ble of Object.values(bles)) {
        rows.push({ label: ((ble.name && ble.name !== 'Unknown') ? ble.name : ble.mac_address).slice(0, 22), start: parseTs(ble.first_seen), end: parseTs(ble.last_seen), color: '#10b981cc' });
    }
    rows.sort((a, b) => (a.start || 0) - (b.start || 0));

    const labels = rows.map(r => r.label);
    const data   = rows.map(r => { if (!r.start || !r.end) return null; return [r.start, r.end > r.start ? r.end : r.start + 1000]; });
    const colors = rows.map(r => r.color);
    const allTs  = rows.flatMap(r => [r.start, r.end]).filter(Boolean);
    const xMin   = allTs.length ? Math.min(...allTs) : Date.now() - 3600000;
    const xMax   = allTs.length ? Math.max(...allTs) : Date.now();
    const xPad   = Math.max(xMax - xMin, 60000) * 0.05;

    if (chartPresence) {
        chartPresence.data.labels = labels;
        chartPresence.data.datasets[0].data = data;
        chartPresence.data.datasets[0].backgroundColor = colors;
        chartPresence.options.scales.x.min = xMin - xPad;
        chartPresence.options.scales.x.max = xMax + xPad;
        chartPresence.update('none');
        return;
    }
    chartPresence = new Chart(canvas, {
        type: 'bar',
        data: { labels, datasets: [{ label: 'Presence', data, backgroundColor: colors, borderSkipped: false, borderRadius: 3 }] },
        options: {
            indexAxis: 'y', responsive: true, animation: false,
            plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => {
                const v = ctx.raw;
                if (!Array.isArray(v)) return 'No data';
                const fmt = ms => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                return `${fmt(v[0])} → ${fmt(v[1])}`;
            } } } },
            scales: {
                x: { type: 'linear', min: xMin - xPad, max: xMax + xPad,
                     ticks: { callback: v => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), maxTicksLimit: 8 },
                     title: { display: true, text: 'Time' } },
                y: { title: { display: true, text: 'Device' } }
            }
        }
    });
}

// ---------- BLE inspector ----------

function decodeApplePayload(hex) {
    const TYPES = {
        '02': 'iBeacon', '05': 'AirDrop', '07': 'AirPods/Beats Nearby',
        '0c': 'Find My / AirTag', '0f': 'Nearby Action', '10': 'Nearby Info', '12': 'Find My v2',
    };
    const ft = hex.slice(0, 2).toLowerCase();
    return TYPES[ft] || `Frame 0x${ft.toUpperCase()}`;
}

function decodeManufacturerData(mfrJsonStr) {
    if (!mfrJsonStr) return null;
    let mfr;
    try { mfr = JSON.parse(mfrJsonStr); } catch { return null; }
    const COMPANIES = { '004c': 'Apple', '00e0': 'Google', '0006': 'Microsoft', '0075': 'Samsung', '0117': 'Fitbit' };
    const results = [];
    for (const [cid, payload] of Object.entries(mfr)) {
        const key     = cid.toLowerCase();
        const company = COMPANIES[key] || `0x${cid.toUpperCase()}`;
        let decoded   = payload.length > 24 ? payload.slice(0, 24) + '…' : payload;
        if (key === '004c') decoded = decodeApplePayload(payload) + `  (${decoded})`;
        results.push({ company, decoded });
    }
    return results;
}

function updateBleInspector(bles) {
    const container = document.getElementById('bleInspectorContainer');
    if (!container) return;
    const list = Object.values(bles);
    if (!list.length) { container.innerHTML = '<p class="text-muted">No BLE devices found.</p>'; return; }

    let html = '<div class="row">';
    for (const ble of list) {
        const sig = parseInt(ble.signal_strength);
        const sc  = signalColor(isNaN(sig) ? -90 : sig);
        const name = (ble.name && ble.name !== 'Unknown') ? ble.name : '—';
        const mfr  = decodeManufacturerData(ble.manufacturer_data);
        const range = estimateRange(ble.tx_power, isNaN(sig) ? null : sig);
        const advIv = advIntervalLabel(ble.adv_interval_ms);

        html += `
        <div class="col-xl-3 col-lg-4 col-md-6">
          <div class="card card-outline" style="border-top:3px solid ${sc.bg}">
            <div class="card-header p-2 d-flex align-items-center justify-content-between">
              <h6 class="card-title mb-0" style="font-size:.85rem">
                <i class="fab fa-bluetooth-b mr-1" style="color:${sc.bg}"></i>${escHtml(name)}
              </h6>
              <span class="badge" style="background:${sc.bg};color:#fff">${isNaN(sig) ? '?' : sig} dBm</span>
            </div>
            <div class="card-body p-2" style="font-size:.8rem">
              <div><b>MAC:</b> <code style="font-size:.75rem">${escHtml(ble.mac_address)}</code></div>
              <div><b>Vendor:</b> ${escHtml(ble.vendor || 'Unknown')}</div>
              <div><b>Type:</b> ${escHtml(ble.device_type || 'Unknown')}</div>`;

        if (ble.tx_power != null) {
            html += `<div><b>TX Power:</b> ${ble.tx_power} dBm${range ? ` &rarr; <em>${escHtml(range)}</em>` : ''}</div>`;
        }
        if (ble.connectable != null) {
            const connLabel = ble.connectable ? '<span class="badge badge-success">Connectable</span>' : '<span class="badge badge-secondary">Non-connectable</span>';
            html += `<div><b>Connectable:</b> ${connLabel}</div>`;
        }
        if (advIv) {
            html += `<div><b>Adv Interval:</b> ${escHtml(advIv)}</div>`;
        }

        // iBeacon section
        if (ble.ibeacon_uuid) {
            html += `<div class="mt-1 pt-1 border-top">
              <b><i class="fas fa-map-marker-alt mr-1"></i>iBeacon</b>
              <div class="text-muted pl-1" style="font-size:.75rem;word-break:break-all"><b>UUID:</b> ${escHtml(ble.ibeacon_uuid)}</div>
              <div class="text-muted pl-1"><b>Major:</b> ${ble.ibeacon_major ?? '?'} &nbsp; <b>Minor:</b> ${ble.ibeacon_minor ?? '?'}</div>
            </div>`;
        }

        // Eddystone section
        if (ble.eddystone_url) {
            html += `<div class="mt-1 pt-1 border-top">
              <b><i class="fas fa-link mr-1"></i>Eddystone URL</b>
              <div class="text-muted pl-1" style="word-break:break-all">${escHtml(ble.eddystone_url)}</div>
            </div>`;
        }
        if (ble.eddystone_uid) {
            html += `<div class="mt-1 pt-1 border-top">
              <b><i class="fas fa-fingerprint mr-1"></i>Eddystone UID</b>
              <div class="text-muted pl-1" style="font-size:.75rem;word-break:break-all">${escHtml(ble.eddystone_uid)}</div>
            </div>`;
        }

        if (mfr && mfr.length) {
            html += `<div class="mt-1 pt-1 border-top"><b>Manufacturer Data:</b>`;
            for (const m of mfr) {
                html += `<div class="text-muted pl-1"><i class="fas fa-microchip mr-1"></i><b>${escHtml(m.company)}:</b> ${escHtml(m.decoded)}</div>`;
            }
            html += `</div>`;
        }
        html += `</div></div></div>`;
    }
    html += '</div>';
    container.innerHTML = html;
}

// ---------- delete ----------

function deleteDevice(type, mac) {
    document.getElementById('deleteModalMac').textContent  = mac;
    document.getElementById('deleteModalType').textContent = type.toUpperCase();
    $('#deleteModal').modal('show');
    document.getElementById('deleteModalConfirm').onclick = async () => {
        $('#deleteModal').modal('hide');
        try {
            const resp = await authFetch(`/device/${encodeURIComponent(type)}/${encodeURIComponent(mac)}`, { method: 'DELETE' });
            if (resp.ok) {
                const searchMac = mac.toLowerCase();
                if (type === 'ap' || type === 'client') {
                    for (const k in rawDataStore.aps) if (k.toLowerCase() === searchMac) delete rawDataStore.aps[k];
                    for (const k in rawDataStore.clients) if (k.toLowerCase() === searchMac) delete rawDataStore.clients[k];
                } else if (type === 'bt') {
                    for (const k in rawDataStore.bluetooths) if (k.toLowerCase() === searchMac) delete rawDataStore.bluetooths[k];
                } else if (type === 'ble') {
                    for (const k in rawDataStore.bles) if (k.toLowerCase() === searchMac) delete rawDataStore.bles[k];
                }
                fetchData();
            } else {
                const body = await resp.json().catch(() => ({}));
                alert(`Delete failed: ${body.error || resp.status}`);
            }
        } catch (e) {
            alert(`Delete failed: ${e.message}`);
        }
    };
}

async function clearInactive() {
    if (!confirm('Are you sure you want to delete all devices not seen in the last 24 hours?')) return;
    try {
        const resp = await authFetch('/device/cleanup?hours=24', { method: 'POST' });
        if (resp.ok) {
            rawDataStore = { aps: {}, clients: {}, bluetooths: {}, bles: {}, probe_requests: [] };
            lastFetchSince = null;
            fetchData();
        } else {
            alert(`Cleanup failed: ${resp.status}`);
        }
    } catch (e) {
        alert(`Cleanup failed: ${e.message}`);
    }
}

// ---------- graph controls ----------

function zoomInWifi()       { if (networkWifi)      networkWifi.moveTo({ scale: networkWifi.getScale() * 1.2 }); }
function zoomOutWifi()      { if (networkWifi)      networkWifi.moveTo({ scale: networkWifi.getScale() / 1.2 }); }
function zoomInBluetooth()  { if (networkBluetooth) networkBluetooth.moveTo({ scale: networkBluetooth.getScale() * 1.2 }); }
function zoomOutBluetooth() { if (networkBluetooth) networkBluetooth.moveTo({ scale: networkBluetooth.getScale() / 1.2 }); }

// ---------- init ----------

function _initNightFromStorage() {
    let on = false;
    try { on = localStorage.getItem('dw_night') === '1'; } catch (_) {}
    document.documentElement.classList.remove('night-pending');
    if (on) document.body.classList.add('night');
    _syncNightButton(on);
}

function _initSectionFromHash() {
    const hash = (window.location.hash || '').replace(/^#/, '');
    const known = new Set(['overview', ...wifiSections, ...bluetoothSections]);
    if (known.has(hash)) switchSection(hash);
}

window.addEventListener('hashchange', _initSectionFromHash);

window.onload = async function () {
    _initNightFromStorage();
    _initSectionFromHash();
    
    try {
        const cfgResp = await authFetch('/config');
        if (cfgResp.ok) {
            const cfg = await cfgResp.json();
            if (cfg.external_api_enabled) {
                const badge = document.getElementById('externalApiBadge');
                if (badge) badge.classList.remove('d-none');
            }
        }
    } catch (e) {}

    document.getElementById('hideRandomMac')?.addEventListener('change', () => {
        displayClients(mergeAPs(rawDataStore.aps), mergeClients(rawDataStore.clients));
    });

    document.getElementById('hideRandomMacProbe')?.addEventListener('change', () => {
        displayProbeSSIDs(rawDataStore.probe_requests, rawDataStore.clients);
    });

    _loadUiPrefs();
    fetchData();
    fetchReadings();
    _dataRefreshTimer = setInterval(fetchData, _uiRefreshInterval * 1000);
    setInterval(fetchReadings, 30000);
    fetchInterfaceStatus();
    setInterval(fetchInterfaceStatus, 10000);
};

// ---------- Settings ----------

async function renderSettings() {
    const [statusRes, settingsRes, configRes, clusterRes] = await Promise.all([
        authFetch('/system/status'),
        authFetch('/system/settings'),
        authFetch('/config'),
        authFetch('/analytics/clusters/config'),
    ]);
    const status   = statusRes.ok   ? await statusRes.json()   : {};
    const settings = settingsRes.ok ? await settingsRes.json() : {};
    const config   = configRes.ok   ? await configRes.json()   : {};
    const cluster  = clusterRes.ok  ? await clusterRes.json()  : { threshold: 0.40 };

    _renderInterfacesPanel(status);
    _renderWifiPanel(status, settings);
    _renderApiPanel(config);

    const thresh = cluster.threshold || 0.40;
    const tSlider = document.getElementById('settingsThresholdSlider');
    const tVal    = document.getElementById('settingsThresholdVal');
    if (tSlider) tSlider.value = thresh;
    if (tVal)    tVal.innerText = thresh;

    const nightEl = document.getElementById('settingsNightMode');
    if (nightEl) nightEl.checked = document.body.classList.contains('night');

    const plSlider = document.getElementById('settingsPageLenSlider');
    const plVal    = document.getElementById('settingsPageLenVal');
    if (plSlider) plSlider.value = _uiPageLength;
    if (plVal)    plVal.innerText = _uiPageLength;

    const riSlider = document.getElementById('settingsRefreshSlider');
    const riVal    = document.getElementById('settingsRefreshVal');
    if (riSlider) riSlider.value = _uiRefreshInterval;
    if (riVal)    riVal.innerText = _uiRefreshInterval;
}

function _renderInterfacesPanel(status) {
    const panel = document.getElementById('settings-interfaces-panel');
    if (!panel) return;
    const ifaces = [
        { icon: 'fas fa-wifi',            label: 'Wi-Fi',      info: status.wifi },
        { icon: 'fab fa-bluetooth-b',     label: 'BT Classic', info: status.bt   },
        { icon: 'fas fa-broadcast-tower', label: 'BLE',        info: status.ble  },
    ];
    panel.innerHTML = ifaces.map(({ icon, label, info }) => {
        const iface      = info?.interface;
        const active     = info?.active;
        const erroring   = info?.error;
        const configured = !!iface;
        const badgeCls   = !configured ? 'badge-secondary' : active ? 'badge-success' : erroring ? 'badge-warning' : 'badge-danger';
        const statusText = !configured ? 'Not configured' : active ? 'Active' : erroring ? 'Error / retrying' : 'Inactive';
        return `<div class="d-flex align-items-center mb-2">
          <i class="${icon} fa-fw mr-2 text-muted"></i>
          <strong class="mr-2" style="min-width:80px">${escHtml(label)}</strong>
          <code class="mr-2">${iface ? escHtml(iface) : '—'}</code>
          <span class="badge ${badgeCls}">${statusText}</span>
        </div>`;
    }).join('');
}

function _renderWifiPanel(status, settings) {
    const panel = document.getElementById('settings-wifi-panel');
    if (!panel) return;
    if (!status.wifi?.interface) {
        panel.innerHTML = '<p class="text-muted mb-0">Wi-Fi interface not configured.</p>';
        return;
    }
    const dwell = settings.wifi?.dwell_time  ?? 0.15;
    const band  = settings.wifi?.band_filter ?? 'all';
    const bands = [
        { val: 'all', label: 'All' },
        { val: '2.4', label: '2.4 GHz' },
        { val: '5',   label: '5 GHz'   },
        { val: '6',   label: '6 GHz'   },
    ];
    panel.innerHTML = `
      <div class="form-group">
        <label class="font-weight-bold">Channel Hopping</label>
        <div class="btn-group btn-group-sm d-block">
          <button class="btn btn-info" id="settingsHoppingToggle" onclick="toggleChannelHopping()">
            <i class="fas fa-satellite-dish mr-1"></i> Hopping: …
          </button>
          <button class="btn btn-outline-secondary" id="settingsHoppingChannel" onclick="promptSetChannel()">
            CH: …
          </button>
        </div>
      </div>
      <div class="form-group">
        <label class="font-weight-bold">Band filter</label>
        <div class="btn-group btn-group-sm d-block" id="settingsBandGroup">
          ${bands.map(b =>
            `<button class="btn ${band === b.val ? 'btn-primary' : 'btn-outline-secondary'}"
                     onclick="setBandFilter('${b.val}')">${escHtml(b.label)}</button>`
          ).join('')}
        </div>
      </div>
      <div class="form-group mb-0">
        <label class="font-weight-bold">Dwell time: <strong><span id="settingsDwellVal">${Math.round(dwell * 1000)}</span> ms</strong></label>
        <input type="range" class="form-control-range" id="settingsDwellSlider"
               min="50" max="500" step="10" value="${Math.round(dwell * 1000)}"
               oninput="handleDwellChange(this.value)">
        <small class="form-text text-muted">Time spent on each channel before moving to the next</small>
      </div>`;
    fetchHoppingStatus();
}

function _renderApiPanel(config) {
    const panel = document.getElementById('settings-api-panel');
    if (!panel) return;
    const enabled = config.external_api_enabled;
    panel.innerHTML = `
      <div class="form-check mb-2">
        <input type="checkbox" class="form-check-input" id="settingsVendorApi" ${enabled ? 'checked' : ''}
               onchange="setVendorApi(this.checked)">
        <label class="form-check-label" for="settingsVendorApi">Enable external vendor API lookup</label>
      </div>
      <small class="form-text text-muted">
        When enabled, MAC prefixes not found locally are sent to macvendors.com.
        Off by default to avoid leaking observed device addresses to a third party.
      </small>`;
}

async function setBandFilter(band) {
    try {
        await authFetch('/system/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ band_filter: band }),
        });
        document.querySelectorAll('#settingsBandGroup .btn').forEach(btn => {
            const matched = btn.textContent.trim() === { all:'All','2.4':'2.4 GHz','5':'5 GHz','6':'6 GHz' }[band];
            btn.className = btn.className.replace(/btn-primary|btn-outline-secondary/g,
                matched ? 'btn-primary' : 'btn-outline-secondary');
        });
    } catch (e) { console.error(e); }
}

let _dwellTimer = null;
function handleDwellChange(val) {
    const el = document.getElementById('settingsDwellVal');
    if (el) el.innerText = val;
    clearTimeout(_dwellTimer);
    _dwellTimer = setTimeout(() => authFetch('/system/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dwell_time: parseFloat(val) / 1000 }),
    }), 400);
}

async function setVendorApi(enabled) {
    try {
        await authFetch('/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ external_api_enabled: enabled }),
        });
        const badge = document.getElementById('externalApiBadge');
        if (badge) badge.classList.toggle('d-none', !enabled);
    } catch (e) { console.error(e); }
}

function handleSettingsThreshold(val) {
    const el = document.getElementById('settingsThresholdVal');
    if (el) el.innerText = parseFloat(val).toFixed(2);
    handleThresholdChange(val);
}

function handleSettingsPageLen(val) {
    const el = document.getElementById('settingsPageLenVal');
    if (el) el.innerText = val;
    _uiPageLength = parseInt(val, 10);
    try { localStorage.setItem('dw_pageLength', val); } catch (_) {}
}

function handleSettingsRefresh(val) {
    const el = document.getElementById('settingsRefreshVal');
    if (el) el.innerText = val;
    _uiRefreshInterval = parseInt(val, 10);
    try { localStorage.setItem('dw_refreshInterval', val); } catch (_) {}
    clearInterval(_dataRefreshTimer);
    _dataRefreshTimer = setInterval(fetchData, _uiRefreshInterval * 1000);
}

function onSettingsNightChange(checked) {
    if (checked !== document.body.classList.contains('night')) toggleNightMode();
}

async function runCleanup() {
    const hours = document.getElementById('cleanupHoursSlider')?.value || 24;
    if (!confirm(`Delete all devices not seen in the last ${hours} hour(s)?`)) return;
    try {
        const resp = await authFetch(`/device/cleanup?hours=${hours}`, { method: 'POST' });
        if (resp.ok) {
            rawDataStore = { aps: {}, clients: {}, bluetooths: {}, bles: {}, probe_requests: [] };
            lastFetchSince = null;
            fetchData();
        } else {
            alert(`Cleanup failed: ${resp.status}`);
        }
    } catch (e) { alert(`Cleanup failed: ${e.message}`); }
}

// ---------- Interface Status ----------

async function fetchInterfaceStatus() {
    const bar = document.getElementById('ifaceStatusBar');
    if (!bar) return;
    try {
        const res = await authFetch('/system/status');
        if (!res.ok) return;
        const d = await res.json();
        const ifaces = [
            { key: 'wifi', icon: 'fas fa-wifi',           label: d.wifi.interface || 'Wi-Fi' },
            { key: 'bt',   icon: 'fab fa-bluetooth-b',    label: d.bt.interface   || 'BT'    },
            { key: 'ble',  icon: 'fas fa-broadcast-tower', label: d.ble.interface  || 'BLE'   },
        ];
        bar.innerHTML = ifaces.map(({ key, icon, label }) => {
            const info    = d[key];
            const missing = !info.interface;
            const dotColor = missing ? '#6c757d' : info.active ? '#28a745' : info.error ? '#f59e0b' : '#dc3545';
            const title    = missing ? 'Not configured' : info.active ? 'Active' : info.error ? 'Error / retrying' : 'Inactive';
            return `<span class="mr-2 small" title="${escHtml(label)}: ${title}" style="white-space:nowrap;opacity:${missing ? '0.45' : '1'}">` +
                   `<i class="${icon}" style="font-size:.85em"></i> ` +
                   `<span style="font-size:.8em">${escHtml(label)}</span>` +
                   `<span style="color:${dotColor};margin-left:3px">●</span>` +
                   `</span>`;
        }).join('');
    } catch (e) { /* silent */ }
}

// ---------- Channel Hopping Controls ----------

async function fetchHoppingStatus() {
    try {
        const res = await authFetch('/system/channel_hopper');
        if (res.ok) {
            const data = await res.json();
            const ids = [['btnHoppingToggle','btnHoppingChannel'], ['settingsHoppingToggle','settingsHoppingChannel']];
            for (const [toggleId, channelId] of ids) {
                const t = document.getElementById(toggleId);
                const c = document.getElementById(channelId);
                if (!t) continue;
                if (data.hopping) {
                    t.innerHTML = '<i class="fas fa-satellite-dish mr-1"></i> Hopping: ON';
                    t.className = t.className.replace(/btn-\S+/, '') + ' btn-info';
                    if (c) c.innerHTML = 'CH: Auto';
                } else {
                    t.innerHTML = '<i class="fas fa-satellite-dish mr-1"></i> Hopping: PAUSED';
                    t.className = t.className.replace(/btn-\S+/, '') + ' btn-outline-warning';
                    if (c) c.innerHTML = `CH: ${data.current_channel || '?'}`;
                }
            }
        }
    } catch (e) {
        console.error("Failed to fetch hopping status", e);
    }
}

async function toggleChannelHopping() {
    const btn = document.getElementById('btnHoppingToggle');
    const isPaused = btn.innerHTML.includes('PAUSED');
    try {
        await authFetch('/system/channel_hopper', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: isPaused ? 'resume' : 'pause' })
        });
        fetchHoppingStatus();
    } catch (e) {
        console.error(e);
    }
}

async function promptSetChannel() {
    const ch = prompt("Enter channel to lock onto (1-165):");
    if (!ch) return;
    try {
        await authFetch('/system/channel_hopper', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'pause', channel: parseInt(ch, 10) })
        });
        fetchHoppingStatus();
    } catch (e) {
        console.error(e);
    }
}

// Check hopping status periodically
setInterval(fetchHoppingStatus, 5000);
setTimeout(fetchHoppingStatus, 500);

// ---------- live packet feed ----------

const _LIVEFEED_COLORS = {
    // Management – by subtype name
    'Beacon':        { fg: '#93c5fd', accent: '#3b82f6' },  // blue
    'Probe Req':     { fg: '#c4b5fd', accent: '#8b5cf6' },  // violet
    'Probe Resp':    { fg: '#c4b5fd', accent: '#8b5cf6' },
    'Auth':          { fg: '#fde68a', accent: '#f59e0b' },  // amber
    'Assoc Req':     { fg: '#fde68a', accent: '#f59e0b' },
    'Assoc Resp':    { fg: '#fde68a', accent: '#f59e0b' },
    'Reassoc Req':   { fg: '#fde68a', accent: '#f59e0b' },
    'Reassoc Resp':  { fg: '#fde68a', accent: '#f59e0b' },
    'Deauth':        { fg: '#fca5a5', accent: '#ef4444' },  // red
    'Disassoc':      { fg: '#fca5a5', accent: '#ef4444' },
    'Action':        { fg: '#f9a8d4', accent: '#ec4899' },  // pink
    // Data
    'Data':          { fg: '#6ee7b7', accent: '#10b981' },  // emerald
    'QoS Data':      { fg: '#6ee7b7', accent: '#10b981' },
    'Null':          { fg: '#4b5563', accent: '#374151' },  // dark
    'QoS Null':      { fg: '#4b5563', accent: '#374151' },
    // Control (catch-all)
    '__ctrl':        { fg: '#94a3b8', accent: '#64748b' },
    '__default':     { fg: '#d1d5db', accent: '#6b7280' },
};

function _pktColor(type) {
    if (_LIVEFEED_COLORS[type]) return _LIVEFEED_COLORS[type];
    if (/^Ctrl|^PS-Poll|^Block/.test(type)) return _LIVEFEED_COLORS['__ctrl'];
    if (/^Mgt|^Data/.test(type))            return _LIVEFEED_COLORS['Data'];
    return _LIVEFEED_COLORS['__default'];
}

function _signalColour(sig) {
    if (sig == null) return '#6b7280';
    if (sig >= -50)  return '#22c55e';
    if (sig >= -65)  return '#84cc16';
    if (sig >= -75)  return '#f59e0b';
    if (sig >= -85)  return '#f97316';
    return '#ef4444';
}

function startLiveFeed() {
    if (_liveFeedES && _liveFeedES.readyState !== EventSource.CLOSED) return; // already open
    const url = _authToken ? `/live/packets?token=${encodeURIComponent(_authToken)}` : '/live/packets';
    _liveFeedES = new EventSource(url);
    _liveFeedES.onopen = () => {
        const ph = document.getElementById('livefeed-placeholder');
        if (ph) ph.style.display = 'none';
    };
    _liveFeedES.onmessage = (ev) => {
        if (_liveFeedPaused) return;
        try {
            const pkt = JSON.parse(ev.data);
            appendLiveFeedRow(pkt);
        } catch (_) {}
    };
    _liveFeedES.onerror = () => {
        // Reconnect is handled automatically by the browser;
        // close manually only if the section is no longer visible.
        if (document.getElementById('section-livefeed').classList.contains('d-none')) {
            stopLiveFeed();
        }
    };
}

function stopLiveFeed() {
    if (_liveFeedES) {
        _liveFeedES.close();
        _liveFeedES = null;
    }
}

function _passesWfFilter(type, src, dst, signal, info) {
    const f = _wfFilter;
    if (f.hiddenTypes.size > 0 && f.hiddenTypes.has(type)) return false;
    if (f.hideRandom && isRandomMac(src)) return false;
    if (f.minSignal != null && signal != null && signal < f.minSignal) return false;
    if (f.macSearch) {
        const q = f.macSearch.toLowerCase();
        if (!src.toLowerCase().includes(q) && !(dst || '').toLowerCase().includes(q)) return false;
    }
    if (f.infoSearch) {
        if (!(info || '').toLowerCase().includes(f.infoSearch.toLowerCase())) return false;
    }
    return true;
}

function _applyWfFilter() {
    document.querySelectorAll('#livefeed-output .lf-row').forEach(row => {
        const show = _passesWfFilter(
            row.dataset.type  || '',
            row.dataset.src   || '',
            row.dataset.dst   || '',
            row.dataset.signal !== '' ? parseInt(row.dataset.signal, 10) : null,
            row.dataset.info  || ''
        );
        row.style.display = show ? 'flex' : 'none';
    });
}

function toggleWfType(type) {
    if (_wfFilter.hiddenTypes.has(type)) _wfFilter.hiddenTypes.delete(type);
    else _wfFilter.hiddenTypes.add(type);
    // Update badge appearance
    document.querySelectorAll('#wf-type-toggles .lf-type-badge').forEach(b => {
        if (b.dataset.type === type) {
            const hidden = _wfFilter.hiddenTypes.has(type);
            b.style.opacity = hidden ? '0.3' : '1';
            b.style.textDecoration = hidden ? 'line-through' : '';
        }
    });
    _applyWfFilter();
}

function onWfMacSearch()   { _wfFilter.macSearch  = (document.getElementById('wfMacSearch')?.value   || '').trim(); _applyWfFilter(); }
function onWfInfoSearch()  { _wfFilter.infoSearch = (document.getElementById('wfInfoSearch')?.value  || '').trim(); _applyWfFilter(); }
function onWfHideRandom()  { _wfFilter.hideRandom = document.getElementById('wfHideRandom')?.checked || false;      _applyWfFilter(); }
function onWfMinSignal()   {
    const v = parseInt(document.getElementById('wfMinSignal')?.value || '', 10);
    _wfFilter.minSignal = isNaN(v) ? null : v;
    _applyWfFilter();
}

function clearWfFilters() {
    _wfFilter.hiddenTypes.clear();
    _wfFilter.macSearch  = '';
    _wfFilter.infoSearch = '';
    _wfFilter.hideRandom = false;
    _wfFilter.minSignal  = null;
    const ms = document.getElementById('wfMacSearch');   if (ms) ms.value = '';
    const is = document.getElementById('wfInfoSearch');  if (is) is.value = '';
    const hr = document.getElementById('wfHideRandom');  if (hr) hr.checked = false;
    const sg = document.getElementById('wfMinSignal');   if (sg) sg.value  = '';
    document.querySelectorAll('#wf-type-toggles .lf-type-badge').forEach(b => {
        b.style.opacity = '1'; b.style.textDecoration = '';
    });
    _applyWfFilter();
}

function appendLiveFeedRow(pkt) {
    const out = document.getElementById('livefeed-output');
    if (!out) return;

    _liveFeedCount++;
    const badge = document.getElementById('livefeed-count-badge');
    if (badge) badge.textContent = _liveFeedCount.toLocaleString() + ' pkts';

    // Evict oldest rows to cap DOM size
    const rows = out.querySelectorAll('.lf-row');
    if (rows.length >= _LIVEFEED_MAX) {
        for (let i = 0; i < rows.length - _LIVEFEED_MAX + 1; i++) rows[i].remove();
    }

    const col   = _pktColor(pkt.type);
    const sigC  = _signalColour(pkt.signal);
    const sig   = pkt.signal != null ? pkt.signal + ' dBm' : '—';
    const dst   = pkt.dst  || '—';
    const info  = pkt.info || '';
    const ch    = pkt.channel != null ? pkt.channel : '—';

    const passes = _passesWfFilter(pkt.type, pkt.src || '', pkt.dst || '', pkt.signal, info);

    const row = document.createElement('div');
    row.className = 'lf-row';
    row.dataset.type   = pkt.type  || '';
    row.dataset.src    = pkt.src   || '';
    row.dataset.dst    = pkt.dst   || '';
    row.dataset.signal = pkt.signal != null ? pkt.signal : '';
    row.dataset.info   = info;
    row.style.cssText = [
        'display:' + (passes ? 'flex' : 'none'),
        'align-items:center',
        'padding:2px 12px',
        'border-left:3px solid ' + col.accent,
        'border-bottom:1px solid #161b22',
        'color:' + col.fg,
        'white-space:nowrap',
        'overflow:hidden',
        'animation:lf-fade-in 0.25s ease',
    ].join(';');

    row.innerHTML =
        `<span style="width:90px;color:#8b949e;flex-shrink:0">${escHtml(pkt.time)}</span>` +
        `<span style="width:130px;flex-shrink:0"><span style="background:${col.accent};color:#fff;border-radius:3px;padding:0 5px;font-size:0.72rem">${escHtml(pkt.type)}</span></span>` +
        `<span style="width:145px;flex-shrink:0;font-family:monospace;color:#e2e8f0">${escHtml(pkt.src)}</span>` +
        `<span style="width:145px;flex-shrink:0;font-family:monospace;color:#94a3b8">${escHtml(dst)}</span>` +
        `<span style="width:55px;flex-shrink:0;color:${sigC}">${sig}</span>` +
        `<span style="width:45px;flex-shrink:0;color:#64748b">${ch}</span>` +
        `<span style="overflow:hidden;text-overflow:ellipsis;color:#fbbf24">${escHtml(info)}</span>`;

    out.appendChild(row);

    // Auto-scroll if the user hasn't scrolled up themselves
    if (passes) {
        const atBottom = out.scrollHeight - out.scrollTop <= out.clientHeight + 60;
        if (atBottom) out.scrollTop = out.scrollHeight;
    }
}

function toggleLiveFeedPause() {
    _liveFeedPaused = !_liveFeedPaused;
    const btn = document.getElementById('livefeed-pause-btn');
    if (!btn) return;
    if (_liveFeedPaused) {
        btn.innerHTML = '<i class="fas fa-play mr-1"></i>Resume';
        btn.classList.replace('btn-warning', 'btn-success');
    } else {
        btn.innerHTML = '<i class="fas fa-pause mr-1"></i>Pause';
        btn.classList.replace('btn-success', 'btn-warning');
    }
}

function clearLiveFeed() {
    const out = document.getElementById('livefeed-output');
    if (!out) return;
    out.querySelectorAll('.lf-row').forEach(r => r.remove());
    _liveFeedCount = 0;
    const badge = document.getElementById('livefeed-count-badge');
    if (badge) badge.textContent = '0 pkts';
}

// ---------- BT/BLE live feed ----------

let _btFeedESBt    = null;   // EventSource for BT Classic
let _btFeedESBle   = null;   // EventSource for BLE
let _btFeedPaused  = false;
let _btFeedCount   = 0;
let _btFeedFilter  = 'all';  // 'all' | 'bt' | 'ble'
const _BT_FEED_MAX = 800;

const _BT_FEED_COLORS = {
    'Discovered':    { fg: '#c4b5fd', accent: '#8b5cf6' },  // violet  — BT Classic
    'Advertisement': { fg: '#a5f3fc', accent: '#06b6d4' },  // cyan    — BLE generic
    'iBeacon':       { fg: '#fde68a', accent: '#f59e0b' },  // amber
    'Eddystone-URL': { fg: '#6ee7b7', accent: '#10b981' },  // emerald
    'Eddystone-UID': { fg: '#6ee7b7', accent: '#10b981' },
    '__default':     { fg: '#d1d5db', accent: '#6b7280' },
};

function _btEvtColor(type) {
    return _BT_FEED_COLORS[type] || _BT_FEED_COLORS['__default'];
}

function startBtLiveFeed() {
    const token = _authToken ? `?token=${encodeURIComponent(_authToken)}` : '';

    if (!_btFeedESBt || _btFeedESBt.readyState === EventSource.CLOSED) {
        _btFeedESBt = new EventSource(`/live/bt${token}`);
        _btFeedESBt.onopen = () => {
            const ph = document.getElementById('btfeed-placeholder');
            if (ph) ph.style.display = 'none';
        };
        _btFeedESBt.onmessage = (ev) => {
            if (_btFeedPaused || (_btFeedFilter === 'ble')) return;
            try { appendBtFeedRow(JSON.parse(ev.data), 'bt'); } catch (_) {}
        };
        _btFeedESBt.onerror = () => {
            if (document.getElementById('section-btlivefeed').classList.contains('d-none'))
                stopBtLiveFeed();
        };
    }

    if (!_btFeedESBle || _btFeedESBle.readyState === EventSource.CLOSED) {
        _btFeedESBle = new EventSource(`/live/ble${token}`);
        _btFeedESBle.onopen = () => {
            const ph = document.getElementById('btfeed-placeholder');
            if (ph) ph.style.display = 'none';
        };
        _btFeedESBle.onmessage = (ev) => {
            if (_btFeedPaused || (_btFeedFilter === 'bt')) return;
            try { appendBtFeedRow(JSON.parse(ev.data), 'ble'); } catch (_) {}
        };
        _btFeedESBle.onerror = () => {
            if (document.getElementById('section-btlivefeed').classList.contains('d-none'))
                stopBtLiveFeed();
        };
    }
}

function stopBtLiveFeed() {
    if (_btFeedESBt)  { _btFeedESBt.close();  _btFeedESBt  = null; }
    if (_btFeedESBle) { _btFeedESBle.close(); _btFeedESBle = null; }
}

function _passesBtFilter(type, mac, name, vendor, rssi) {
    const f = _btEventFilter;
    if (f.hiddenTypes.size > 0 && f.hiddenTypes.has(type)) return false;
    if (f.hideRandom && isRandomMac(mac)) return false;
    if (f.minRssi != null && rssi != null && rssi < f.minRssi) return false;
    if (f.search) {
        const q = f.search.toLowerCase();
        const m = (mac    || '').toLowerCase();
        const n = (name   || '').toLowerCase();
        const v = (vendor || '').toLowerCase();
        if (!m.includes(q) && !n.includes(q) && !v.includes(q)) return false;
    }
    return true;
}

function _applyBtFilter() {
    document.querySelectorAll('#btfeed-output .lf-row').forEach(row => {
        const show = _passesBtFilter(
            row.dataset.type   || '',
            row.dataset.mac    || '',
            row.dataset.name   || '',
            row.dataset.vendor || '',
            row.dataset.rssi !== '' ? parseInt(row.dataset.rssi, 10) : null
        );
        row.style.display = show ? 'flex' : 'none';
    });
}

function toggleBtType(type) {
    if (_btEventFilter.hiddenTypes.has(type)) _btEventFilter.hiddenTypes.delete(type);
    else _btEventFilter.hiddenTypes.add(type);
    document.querySelectorAll('#bt-type-toggles .lf-type-badge').forEach(b => {
        if (b.dataset.type === type) {
            const hidden = _btEventFilter.hiddenTypes.has(type);
            b.style.opacity = hidden ? '0.3' : '1';
            b.style.textDecoration = hidden ? 'line-through' : '';
        }
    });
    _applyBtFilter();
}

function onBtSearch()     { _btEventFilter.search     = (document.getElementById('btSearch')?.value    || '').trim(); _applyBtFilter(); }
function onBtHideRandom() { _btEventFilter.hideRandom = document.getElementById('btHideRandom')?.checked || false;    _applyBtFilter(); }
function onBtMinRssi()    {
    const v = parseInt(document.getElementById('btMinRssi')?.value || '', 10);
    _btEventFilter.minRssi = isNaN(v) ? null : v;
    _applyBtFilter();
}

function clearBtFilters() {
    _btEventFilter.hiddenTypes.clear();
    _btEventFilter.search    = '';
    _btEventFilter.hideRandom = false;
    _btEventFilter.minRssi   = null;
    const s  = document.getElementById('btSearch');    if (s)  s.value   = '';
    const hr = document.getElementById('btHideRandom'); if (hr) hr.checked = false;
    const r  = document.getElementById('btMinRssi');   if (r)  r.value   = '';
    document.querySelectorAll('#bt-type-toggles .lf-type-badge').forEach(b => {
        b.style.opacity = '1'; b.style.textDecoration = '';
    });
    _applyBtFilter();
}

function appendBtFeedRow(evt, source) {
    const out = document.getElementById('btfeed-output');
    if (!out) return;

    _btFeedCount++;
    const badge = document.getElementById('btfeed-count-badge');
    if (badge) badge.textContent = _btFeedCount.toLocaleString() + ' evts';

    const rows = out.querySelectorAll('.lf-row');
    if (rows.length >= _BT_FEED_MAX) {
        for (let i = 0; i < rows.length - _BT_FEED_MAX + 1; i++) rows[i].remove();
    }

    const col  = _btEvtColor(evt.type);
    const rssi = evt.rssi != null ? evt.rssi + ' dBm' : '—';
    const rssiColor = evt.rssi != null ? _signalColour(evt.rssi) : '#6b7280';
    const infoText  = evt.info || evt.device_type || '';
    const name   = evt.name   || '';
    const vendor  = evt.vendor && evt.vendor !== 'Unknown' ? evt.vendor : '';

    const passes = _passesBtFilter(evt.type, evt.mac || '', name, vendor, evt.rssi);

    const row = document.createElement('div');
    row.className = 'lf-row';
    row.dataset.type   = evt.type   || '';
    row.dataset.source = source;
    row.dataset.mac    = evt.mac    || '';
    row.dataset.name   = name;
    row.dataset.vendor = vendor;
    row.dataset.rssi   = evt.rssi != null ? evt.rssi : '';
    row.style.cssText = [
        'display:' + (passes ? 'flex' : 'none'),
        'align-items:center',
        'padding:2px 12px',
        'border-left:3px solid ' + col.accent,
        'border-bottom:1px solid #161b22',
        'color:' + col.fg,
        'white-space:nowrap',
        'overflow:hidden',
        'animation:lf-fade-in 0.25s ease',
    ].join(';');

    const nameHtml   = name   ? escHtml(name)   : '<span style="color:#4b5563">—</span>';
    const vendorHtml = vendor ? `<span style="color:#94a3b8">${escHtml(vendor)}</span>` : '<span style="color:#4b5563">—</span>';

    row.innerHTML =
        `<span style="width:90px;color:#8b949e;flex-shrink:0">${escHtml(evt.time)}</span>` +
        `<span style="width:120px;flex-shrink:0"><span style="background:${col.accent};color:#fff;border-radius:3px;padding:0 5px;font-size:0.72rem">${escHtml(evt.type)}</span></span>` +
        `<span style="width:150px;flex-shrink:0;font-family:monospace;color:#e2e8f0">${escHtml(evt.mac)}</span>` +
        `<span style="width:150px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis">${nameHtml}</span>` +
        `<span style="width:130px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis">${vendorHtml}</span>` +
        `<span style="width:55px;flex-shrink:0;color:${rssiColor}">${rssi}</span>` +
        `<span style="overflow:hidden;text-overflow:ellipsis;color:#fbbf24">${escHtml(infoText)}</span>`;

    out.appendChild(row);

    if (passes) {
        const atBottom = out.scrollHeight - out.scrollTop <= out.clientHeight + 60;
        if (atBottom) out.scrollTop = out.scrollHeight;
    }
}

function toggleBtFeedPause() {
    _btFeedPaused = !_btFeedPaused;
    const btn = document.getElementById('btfeed-pause-btn');
    if (!btn) return;
    if (_btFeedPaused) {
        btn.innerHTML = '<i class="fas fa-play mr-1"></i>Resume';
        btn.classList.replace('btn-warning', 'btn-success');
    } else {
        btn.innerHTML = '<i class="fas fa-pause mr-1"></i>Pause';
        btn.classList.replace('btn-success', 'btn-warning');
    }
}

function clearBtFeed() {
    const out = document.getElementById('btfeed-output');
    if (!out) return;
    out.querySelectorAll('.lf-row').forEach(r => r.remove());
    _btFeedCount = 0;
    const badge = document.getElementById('btfeed-count-badge');
    if (badge) badge.textContent = '0 evts';
}

function setBtFeedFilter(f) {
    _btFeedFilter = f;
    document.querySelectorAll('#btfeed-filter-group .btn').forEach(btn => {
        const label = btn.textContent.trim().toLowerCase().replace(' classic', '');
        const active = (f === 'all' && label === 'all') ||
                       (f === 'bt'  && label === 'bt') ||
                       (f === 'ble' && label === 'ble');
        btn.className = active ? 'btn btn-primary' : 'btn btn-outline-secondary';
    });
}
