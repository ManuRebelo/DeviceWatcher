let networkWifi = null;
let networkBluetooth = null;
let activityChart = null;

function averageSignal(devices) {
    let sum = 0, count = 0, min = null, max = null;
    for (const d of Object.values(devices)) {
        if (d.signal_strength !== undefined && d.signal_strength !== null && d.signal_strength !== "") {
            let s = parseInt(d.signal_strength, 10);
            if (!isNaN(s)) {
                sum += s;
                count++;
                if (min === null || s < min) min = s;
                if (max === null || s > max) max = s;
            }
        }
    }
    return count ? { avg: (sum / count).toFixed(1), min: min, max: max } : { avg: "N/A", min: "N/A", max: "N/A" };
}

function apWithMostClients(aps, clients) {
    const apClientCount = {};
    for (const ap of Object.values(aps)) {
        const baseMac = ap.mac_address.split('_')[0];
        apClientCount[baseMac] = 0;
    }
    for (const client of Object.values(clients)) {
        if (client.associated_ap) {
            const apMac = client.associated_ap.split('_')[0];
            if (apClientCount[apMac] !== undefined) apClientCount[apMac]++;
        }
    }
    let max = 0, maxAp = null;
    for (const [apMac, count] of Object.entries(apClientCount)) {
        if (count > max) {
            max = count;
            maxAp = apMac;
        }
    }
    if (!maxAp) return { ap: null, count: 0 };
    return { ap: aps[maxAp] || { mac_address: maxAp }, count: max };
}

function mostCommonVendor(devices) {
    const vendorCount = {};
    const seenMacs = new Set();

    for (const d of Object.values(devices)) {
        if (d.mac && !seenMacs.has(d.mac) && d.vendor) {
            seenMacs.add(d.mac);
            vendorCount[d.vendor] = (vendorCount[d.vendor] || 0) + 1;
        }
    }

    let max = 0, maxVendor = null;
    for (const [vendor, count] of Object.entries(vendorCount)) {
        if (count > max) {
            max = count;
            maxVendor = vendor;
        }
    }
    return maxVendor ? `${maxVendor} (${max})` : "N/A";
}

function mergeAPs(aps) {
    const merged = {};
    for (const ap of Object.values(aps)) {
        const baseMac = ap.mac_address.split('_')[0];
        if (!merged[baseMac]) {
            merged[baseMac] = {
                mac_address: baseMac,
                ssids: new Set(),
                vendors: new Set(),
                signals: [],
                channels: [],
                securities: new Set(),
                freq_info: [],
                raw: []
            };
        }
        merged[baseMac].ssids.add(ap.ssid || 'Unknown');
        merged[baseMac].vendors.add(ap.vendor || '');
        if (ap.signal_strength !== undefined && ap.signal_strength !== null && ap.signal_strength !== "") {
            merged[baseMac].signals.push(ap.signal_strength);
        }
        if (ap.channel !== undefined && ap.channel !== null && ap.channel !== "") {
            merged[baseMac].channels.push(ap.channel);
        }
        merged[baseMac].securities.add(ap.security || 'Unknown');
        merged[baseMac].freq_info.push({
            channel: ap.channel,
            signal: ap.signal_strength,
            security: ap.security,
            ssid: ap.ssid || 'Unknown'
        });
        merged[baseMac].raw.push(ap);
    }
    for (const mac in merged) {
        merged[mac].ssids = Array.from(merged[mac].ssids);
        merged[mac].vendors = Array.from(merged[mac].vendors);
        merged[mac].securities = Array.from(merged[mac].securities);
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
                vendors: new Set(),
                signals: [],
                associated_aps: new Set(),
                counts: [],
                raw: []
            };
        }
        merged[baseMac].vendors.add(client.vendor || '');
        if (client.signal_strength !== undefined && client.signal_strength !== null && client.signal_strength !== "") {
            merged[baseMac].signals.push(client.signal_strength);
        }
        if (client.associated_ap) {
            merged[baseMac].associated_aps.add(client.associated_ap.split('_')[0]);
        }
        merged[baseMac].counts.push(client.count || 0);
        merged[baseMac].raw.push(client);
    }
    for (const mac in merged) {
        merged[mac].vendors = Array.from(merged[mac].vendors);
        merged[mac].associated_aps = Array.from(merged[mac].associated_aps);
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
                names: new Set(),
                vendors: new Set(),
                signals: [],
                raw: []
            };
        }
        merged[mac].names.add(bt.name || 'Unknown');
        merged[mac].vendors.add(bt.vendor || '');
        if (bt.signal_strength !== undefined && bt.signal_strength !== null && bt.signal_strength !== "") {
            merged[mac].signals.push(bt.signal_strength);
        }
        merged[mac].raw.push(bt);
    }
    for (const mac in merged) {
        merged[mac].names = Array.from(merged[mac].names);
        merged[mac].vendors = Array.from(merged[mac].vendors);
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
                vendors: new Set(),
                signals: [],
                raw: []
            };
        }
        merged[mac].vendors.add(ble.vendor || '');
        if (ble.signal_strength !== undefined && ble.signal_strength !== null && ble.signal_strength !== "") {
            merged[mac].signals.push(ble.signal_strength);
        }
        merged[mac].raw.push(ble);
    }
    for (const mac in merged) {
        merged[mac].vendors = Array.from(merged[mac].vendors);
    }
    return merged;
}

function countUniqueAPs(data) {
    return Object.keys(mergeAPs(data.aps)).length;
}
function countUniqueClients(data) {
    return Object.keys(mergeClients(data.clients)).length;
}
function countUniqueBluetooths(data) {
    return Object.keys(mergeBluetooths(data.bluetooths)).length;
}
function countUniqueBLEs(data) {
    return Object.keys(mergeBLEs(data.bles)).length;
}

function getMostActive(data) {
    let mostActive = { count: 0 };
    for (const key in data) {
        if (data[key].count > mostActive.count) {
            mostActive = data[key];
            mostActive.mac = key;
        }
    }
    return mostActive;
}

async function fetchData() {
    try {
        const response = await fetch('/data');
        const data = await response.json();

        displayGeneralInfo(data);
        displayMiniStats(data);
        displayAPs(data.aps);
        displayClients(data.aps, data.clients);
        displayBluetooth(data.bluetooths)
        displayBLE(data.bles)
        updateWifiGraph(data.aps, data.clients);
        updateBLEGraph(data.bluetooths, data.bles)
        updateActivityChart(data);
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}

function displayGeneralInfo(data) {
    const apCount = countUniqueAPs(data);
    const clientCount = countUniqueClients(data);
    const bluetoothCount = countUniqueBluetooths(data);
    const bleCount = countUniqueBLEs(data);
    const deviceCount = apCount + clientCount + bluetoothCount + bleCount;
    const mostActiveAP = getMostActive(data.aps);
    const mostActiveClient = getMostActive(data.clients);
    const mergedAPs = mergeAPs(data.aps);
    const mergedClients = mergeClients(data.clients);

    let apClientCount = {};
    for (const apMac in mergedAPs) apClientCount[apMac] = 0;
    for (const clientMac in mergedClients) {
        for (const ap of mergedClients[clientMac].associated_aps) {
            if (apClientCount[ap] !== undefined) apClientCount[ap]++;
        }
    }
    let maxClients = 0, maxApMac = null;
    for (const [apMac, count] of Object.entries(apClientCount)) {
        if (count > maxClients) {
            maxClients = count;
            maxApMac = apMac;
        }
    }
    let apMostClientsSSID = "N/A";
    if (maxApMac && mergedAPs[maxApMac]) {
        apMostClientsSSID = mergedAPs[maxApMac].ssids.join(", ") + ` <span style="color:var(--muted);font-size:0.95em;">(${maxClients} clients)</span>`;
    }

    document.getElementById('generalInfo').innerHTML = `
            <div class="summary-cards">
                <div class="summary-card">
                <h3>Total Devices</h3>
                <div class="value">${deviceCount}</div>
                <div class="desc">All detected</div>
                </div>
                <div class="summary-card">
                <h3>Wi-Fi APs</h3>
                <div class="value">${apCount}</div>
                <div class="desc">Access Points</div>
                </div>
                <div class="summary-card">
                <h3>Clients</h3>
                <div class="value">${clientCount}</div>
                <div class="desc">Wi-Fi Clients</div>
                </div>
                <div class="summary-card">
                <h3>Bluetooth</h3>
                <div class="value">${bluetoothCount}</div>
                <div class="desc">Classic BT</div>
                </div>
                <div class="summary-card">
                <h3>BLE</h3>
                <div class="value">${bleCount}</div>
                <div class="desc">Low Energy</div>
                </div>
            </div>
            <div style="margin: 0 auto; max-width: 700px;">
                <table>
                <tbody>
                    <tr>
                    <th>AP with Most Clients</th>
                    <td>
                        ${apMostClientsSSID}
                    </td>
                    </tr>
                    <tr>                                
                    <th>Most Active AP</th>
                    <td title="SSID: ${mostActiveAP.ssid || 'Unknown'}&#10;MAC: ${mostActiveAP.mac_address || ''}">
                        ${mostActiveAP.ssid || 'Unknown'} <span style="color:var(--muted);font-size:0.95em;">(${mostActiveAP.count || 0} packets)</span>
                    </td>
                    </tr>
                    <tr>
                    <th>Most Active Client</th>
                    <td title="MAC: ${mostActiveClient.mac_address || ''}">
                        ${mostActiveClient.mac_address || 'Unknown'} <span style="color:var(--muted);font-size:0.95em;">(${mostActiveClient.count || 0} packets)</span>
                    </td>
                    </tr>
                </tbody>
                </table>
            </div>
            `;
}

function displayMiniStats(data) {
    const apStats = averageSignal(data.aps);
    const clientStats = averageSignal(data.clients);
    const btStats = averageSignal(data.bluetooths);
    const bleStats = averageSignal(data.bles);
    const apVendors = mostCommonVendor(data.aps);
    const clientVendors = mostCommonVendor(data.clients);
    document.getElementById('miniStatsBar').innerHTML = `
            <div class="mini-stats-bar">
                <div class="mini-stat">AP Signal: avg <b>${apStats.avg} dBm</b>, min <b>${apStats.min} dBm</b>, max <b>${apStats.max} dBm</b></div>
                <div class="mini-stat">Client Signal: avg <b>${clientStats.avg} dBm</b>, min <b>${clientStats.min} dBm</b>, max <b>${clientStats.max} dBm</b></div>
                <div class="mini-stat">BT Signal: avg <b>${btStats.avg} dBm</b>, min <b>${btStats.min} dBm</b>, max <b>${btStats.max} dBm</b></div>
                <div class="mini-stat">BLE Signal: avg <b>${bleStats.avg} dBm</b>, min <b>${bleStats.min} dBm</b>, max <b>${bleStats.max} dBm</b></div>
                <div class="mini-stat">AP Top Vendor: <b>${apVendors}</b></div>
                <div class="mini-stat">Client Top Vendor: <b>${clientVendors}</b></div>
            </div>
        `;
}

function displayAPs(aps) {
    const apsTableBody = document.getElementById("apsTableBody");
    apsTableBody.innerHTML = '';
    const merged = mergeAPs(aps);
    for (const mac in merged) {
        const ap = merged[mac];
        const row = document.createElement('tr');
        row.innerHTML = `
                    <td title="BSSID: ${ap.mac_address}">
                        ${ap.mac_address}
                    </td>
                    <td>${ap.ssids.join(", ")}</td>
                    <td>${ap.vendors.join(", ")}</td>
                    <td>
                        ${ap.signals.length ? ap.signals.join(", ") : ""}
                    </td>
                    <td>
                        ${ap.channels.length ? ap.channels.join(", ") : ""}
                    </td>
                    <td>${ap.securities.join(", ")}</td>
                `;
        apsTableBody.appendChild(row);
    }
    addSortingFunctionality("apsTable");
}

function displayClients(aps, clients) {
    const clientsTableBody = document.getElementById("clientsTableBody");
    clientsTableBody.innerHTML = '';
    const mergedClients = mergeClients(clients);
    const mergedAPs = mergeAPs(aps);

    for (const mac in mergedClients) {
        const client = mergedClients[mac];
        const associatedAPsDisplay = client.associated_aps.map(apMac => {
            if (!apMac || apMac.toLowerCase() === "ff:ff:ff:ff:ff:ff") return "Unknown";
            if (mergedAPs[apMac]) {
                const ssids = mergedAPs[apMac].ssids.join(", ");
                return `${ssids} (${apMac})`;
            }
            return `Unknown (${apMac})`;
        }).join(", ");

        const row = document.createElement('tr');
        row.innerHTML = `
                    <td>${client.mac_address}</td>
                    <td>${client.vendors.join(", ")}</td>
                    <td>${client.signals.length ? client.signals.join(", ") : ""}</td>
                    <td>${associatedAPsDisplay || "Unknown"}</td>
                    <td>${client.counts.reduce((a, b) => a + b, 0)}</td>
                `;
        clientsTableBody.appendChild(row);
    }
    addSortingFunctionality("clientsTable");
}

function displayBluetooth(bluetooths) {
    const bluetoothTableBody = document.getElementById("bluetoothTableBody");
    bluetoothTableBody.innerHTML = '';
    const merged = mergeBluetooths(bluetooths);
    for (const mac in merged) {
        const bt = merged[mac];
        const row = document.createElement('tr');
        row.innerHTML = `
                    <td>
                        ${bt.names.join(", ")}
                    </td>
                    <td>${bt.mac_address}</td>
                    <td>${bt.signals.length ? bt.signals.join(", ") : ""}</td>
                    <td>${bt.vendors.join(", ")}</td>
                `;
        bluetoothTableBody.appendChild(row);
    }
    addSortingFunctionality("bluetoothTable");
}

function displayBLE(bles) {
    const bleTableBody = document.getElementById("bleTableBody");
    bleTableBody.innerHTML = '';
    const merged = mergeBLEs(bles);
    for (const mac in merged) {
        const ble = merged[mac];
        const row = document.createElement('tr');
        row.innerHTML = `
                    <td>
                        ${ble.mac_address}
                    </td>
                    <td>${ble.signals.length ? ble.signals.join(", ") : ""}</td>
                    <td>${ble.vendors.join(", ")}</td>
                `;
        bleTableBody.appendChild(row);
    }
    addSortingFunctionality("bleTable");
}

function addSortingFunctionality(tableId) {
    const table = document.getElementById(tableId);
    const headers = table.querySelectorAll("th");
    headers.forEach((header, index) => {
        header.onclick = function () {
            const rows = Array.from(table.querySelectorAll("tbody tr"));
            const isAscending = header.classList.contains("asc");
            const order = isAscending ? 1 : -1;
            rows.sort((rowA, rowB) => {
                const cellA = rowA.cells[index].innerText;
                const cellB = rowB.cells[index].innerText;
                const valueA = isNaN(cellA) ? cellA : parseFloat(cellA);
                const valueB = isNaN(cellB) ? cellB : parseFloat(cellB);
                if (valueA > valueB) return order;
                if (valueA < valueB) return -order;
                return 0;
            });
            rows.forEach(row => table.querySelector("tbody").appendChild(row));
            headers.forEach(h => h.classList.remove("asc", "desc"));
            header.classList.toggle("asc", !isAscending);
            header.classList.toggle("desc", isAscending);
        };
    });
}

function updateWifiGraph(aps, clients) {
    if (networkWifi !== null) networkWifi.destroy();

    const nodesSet = new vis.DataSet();
    const edgesSet = new vis.DataSet();
    const apMap = {};

    const ssidGroups = {};
    for (const ap of Object.values(aps)) {
        const baseMac = ap.mac_address.split('_')[0];
        if (baseMac === "ff:ff:ff:ff:ff:ff") continue;
        const ssid = ap.ssid || 'Unknown';
        if (!ssidGroups[ssid]) ssidGroups[ssid] = [];
        ssidGroups[ssid].push(ap);
    }

    // Add AP nodes, color by SSID group
    const ssidColors = {};
    let colorIdx = 0;
    const palette = [
        "#2563eb", // Blue
        "#10b981", // Green
        "#ef4444", // Red
        "#f59e42", // Orange
        "#a21caf", // Purple
        "#0ea5e9", // Light Blue
        "#6d4c41", // Brown
        "#c026d3", // Magenta
        "#6366f1", // Indigo
        "#14b8a6", // Teal
        "#facc15", // Yellow
        "#e11d48", // Crimson
        "#84cc16", // Lime
        "#9333ea", // Deep Purple
        "#3b82f6", // Sky Blue
        "#f97316", // Deep Orange
        "#475569", // Slate Gray
        "#22c55e", // Emerald
        "#fb7185", // Rose
        "#8b5cf6"  // Violet
    ];


    for (const [ssid, group] of Object.entries(ssidGroups)) {
        const color = palette[colorIdx % palette.length];
        ssidColors[ssid] = color;
        colorIdx++;
        for (const ap of group) {
            const baseMac = ap.mac_address.split('_')[0];
            if (nodesSet.get(baseMac)) continue;
            let signalStrength = parseInt(ap.signal_strength, 10);
            if (isNaN(signalStrength)) signalStrength = -70;
            const nodeSize = Math.max(38, Math.min(70, (signalStrength + 200) / 2));
            nodesSet.add({
                id: baseMac,
                label: `${ap.ssid || 'Unknown'}\n${baseMac}`,
                shape: 'hexagon',
                size: nodeSize,
                color: { background: color, border: '#222' },
                font: { color: "#fff", size: 15, face: "Roboto" },
                title: `SSID: ${ap.ssid || 'Unknown'}<br>BSSID: ${baseMac}<br>Vendor: ${ap.vendor || 'Unknown'}<br>Signal: ${signalStrength} dBm<br>Security: ${ap.security || 'Unknown'}`
            });
            apMap[baseMac] = true;
        }
    }

    for (const client of Object.values(clients)) {
        const clientMac = client.mac_address.split('_')[0];
        const apId = client.associated_ap ? client.associated_ap.split('_')[0] : '';
        if (clientMac === "ff:ff:ff:ff:ff:ff") continue;
        if (!nodesSet.get(clientMac)) {
            nodesSet.add({
                id: clientMac,
                label: `${clientMac}`,
                shape: 'dot',
                size: 18,
                color: { background: '#fff', border: '#2563eb' },
                font: { color: "#2563eb", size: 13, face: "Roboto" },
                title: `Client MAC: ${client.mac_address}<br>Vendor: ${client.vendor || 'Unknown'}<br>Signal: ${client.signal_strength || 'N/A'} dBm`
            });
        }
        if (apMap[apId]) {
            edgesSet.add({
                from: clientMac,
                to: apId,
                arrows: { to: true },
                color: { color: '#a5b4fc', highlight: '#2563eb' },
                width: 2,
                title: `Client ${clientMac} → AP ${apId}`
            });
        }
    }

    let legendHTML = '<div style="margin-bottom:8px;font-size:1em;"><b>AP SSID Colors:</b> ';
    for (const [ssid, color] of Object.entries(ssidColors)) {
        legendHTML += `<span style="display:inline-block;width:14px;height:14px;background:${color};border-radius:3px;margin-right:4px;vertical-align:middle;"></span> <span style="margin-right:10px;">${ssid}</span>`;
    }
    legendHTML += '</div>';

    document.getElementById('wifi-legend').innerHTML = legendHTML;

    const container = document.getElementById('networkGraph');
    const dataGraph = { nodes: nodesSet, edges: edgesSet };
    const options = {
        interaction: { hover: true, tooltipDelay: 120 },
        physics: {
            enabled: true,
            stabilization: true,
            barnesHut: { gravitationalConstant: -32000, centralGravity: 0.25, springLength: 100, springConstant: 0.04 },
        },
        layout: {
            improvedLayout: true,
            randomSeed: 2,
        },
        nodes: {
            borderWidth: 2,
            shadow: true
        },
        edges: {
            smooth: { type: 'dynamic' },
            shadow: true
        }
    };
    networkWifi = new vis.Network(container, dataGraph, options);
}

function updateBLEGraph(bluetooths, bles) {
    if (networkBluetooth !== null) networkBluetooth.destroy();

    const nodesSet = new vis.DataSet();
    const edgesSet = new vis.DataSet();

    for (const ble of Object.values(bles)) {
        const baseMac = ble.mac_address;
        let signalStrength = parseInt(ble.signal_strength, 10);
        if (isNaN(signalStrength)) signalStrength = -70;
        const strengthNorm = Math.min(1, Math.max(0, (signalStrength + 100) / 70));
        const color = `rgb(${80 + Math.floor(120 * (1 - strengthNorm))},${180 + Math.floor(60 * strengthNorm)},120)`;
        const nodeSize = 18 + strengthNorm * 22;
        nodesSet.add({
            id: baseMac,
            label: `${baseMac}\n${signalStrength} dBm`,
            shape: 'dot',
            size: nodeSize,
            color: { background: color, border: '#10b981' },
            font: { color: "#222", size: 12, face: "Roboto" },
            title: `BLE MAC: ${baseMac}<br>Signal: ${signalStrength} dBm`
        });
    }

    for (const bluetooth of Object.values(bluetooths)) {
        const baseMac = bluetooth.mac_address;
        let signalStrength = parseInt(bluetooth.signal_strength, 10);
        if (isNaN(signalStrength)) signalStrength = -70;
        const strengthNorm = Math.min(1, Math.max(0, (signalStrength + 100) / 70));

        const color = `rgb(${80 + Math.floor(120 * (1 - strengthNorm))},${180 + Math.floor(60 * strengthNorm)},120)`;
        const nodeSize = 18 + strengthNorm * 22;
        nodesSet.add({
            id: baseMac,
            label: `${bluetooth.name || 'BT'}\n${baseMac}\n${signalStrength} dBm`,
            shape: 'square',
            size: nodeSize,
            color: { background: color, border: '#39ff14' },
            font: { color: "#222", size: 12, face: "Roboto" },
            title: `Bluetooth Name: ${bluetooth.name || 'Unknown'}<br>MAC: ${baseMac}<br>Signal: ${signalStrength} dBm`
        });
    }

    document.getElementById('ble-legend').innerHTML = `
            <span style="display:inline-block;width:14px;height:14px;background:#39ff14;border-radius:3px;margin-right:6px;vertical-align:middle;"></span>
            <span style="margin-right:16px;">BLE</span>
            
            <span style="display:inline-block;width:14px;height:14px;background:#1e90ff;border-radius:3px;margin-right:6px;vertical-align:middle;"></span>
            <span>Bluetooth</span>
            `;


    const container = document.getElementById('BLEGraph');
    const dataGraph = { nodes: nodesSet, edges: edgesSet };
    const options = {
        interaction: { hover: true, tooltipDelay: 120 },
        physics: {
            enabled: true,
            stabilization: true,
            barnesHut: {
                gravitationalConstant: -32000,
                centralGravity: 0.3,
                springLength: 90,
                springConstant: 0.03,
                damping: 0.4,
                avoidOverlap: 1,
            },
        },
        layout: {
            improvedLayout: true,
            randomSeed: 42
        },
        nodes: {
            borderWidth: 2,
            shadow: true
        },
        edges: {
            smooth: { type: 'dynamic' },
            shadow: true
        }
    };
    networkBluetooth = new vis.Network(container, dataGraph, options);
}



function updateActivityChart(data) {
    const mergedAPs = mergeAPs(data.aps);
    const mergedClients = mergeClients(data.clients);
    const devices = [];

    for (const ap of Object.values(mergedAPs)) {
        const totalPackets = ap.raw.reduce((sum, d) => sum + (d.count || 0), 0);
        if (totalPackets > 0) devices.push({ name: ap.ssids.join(", ") || ap.mac_address, packets: totalPackets });
    }
    for (const client of Object.values(mergedClients)) {
        const totalPackets = client.counts.reduce((a, b) => a + b, 0);
        if (totalPackets > 0) devices.push({ name: client.mac_address, packets: totalPackets });
    }

    devices.sort((a, b) => b.packets - a.packets);
    const topDevices = devices.slice(0, 10); // top 10
    const labels = topDevices.map(d => d.name);
    const packets = topDevices.map(d => d.packets);

    const ctx = document.getElementById('activityChart').getContext('2d');
    if (activityChart) activityChart.destroy();

    activityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Number of Packets',
                data: packets,
                backgroundColor: 'rgba(37, 99, 235, 0.6)',
                borderColor: 'rgba(37, 99, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                tooltip: { mode: 'index', intersect: false }
            },
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Packets' } },
                x: { title: { display: true, text: 'Device' } }
            }
        }
    });
}

function zoomInWifi() {
    if (!networkWifi) return;
    const currentScale = networkWifi.getScale();
    networkWifi.moveTo({ scale: currentScale * 1.2 });
}
function zoomOutWifi() {
    if (!networkWifi) return;
    const currentScale = networkWifi.getScale();
    networkWifi.moveTo({ scale: currentScale / 1.2 });
}
function zoomInBluetooth() {
    if (!networkBluetooth) return;
    const currentScale = networkBluetooth.getScale();
    networkBluetooth.moveTo({ scale: currentScale * 1.2 });
}
function zoomOutBluetooth() {
    if (!networkBluetooth) return;
    const currentScale = networkBluetooth.getScale();
    networkBluetooth.moveTo({ scale: currentScale / 1.2 });
}

function switchTab(tabName) {
    const allTabs = document.querySelectorAll('.tab-content');
    const allButtons = document.querySelectorAll('.tab-button');
    allTabs.forEach(tab => tab.classList.remove('active'));
    allButtons.forEach(button => button.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

function toggleRetroStyle() {
    document.body.classList.toggle("retro");
    const btn = document.getElementById("retroToggleBtn");
    if (document.body.classList.contains("retro")) {
        btn.textContent = "Switch to Normal";
    } else {
        btn.textContent = "Switch to Retro";
    }
}

window.onload = function () {
    fetchData();
};
