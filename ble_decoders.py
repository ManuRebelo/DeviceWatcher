"""
@file ble_decoders.py
@brief BLE manufacturer-specific advertisement data decoders for common vendor formats.
@license MIT — see LICENSE for details.
"""

import logging

logger = logging.getLogger(__name__)


def decode_manufacturer_data(hex_data: str) -> dict:
    """Decode common BLE manufacturer-specific advertisement payloads.

    Recognises Apple (iBeacon / Nearby / AirPods), Xiaomi MiBeacon
    (temperature/humidity), and Microsoft Swift Pair frames.

    @param hex_data  Raw manufacturer data as a hex string beginning with the
                     little-endian 2-byte company ID (e.g. ``'4c000215...'``).
                     Colon separators are stripped automatically.
    @return          Mapping of decoded field names to their values.  Returns
                     an empty dict when the payload is empty, too short, or the
                     company ID is not recognised.
    """
    if not hex_data:
        return {}

    metrics: dict = {}
    try:
        data = bytes.fromhex(hex_data.replace(':', ''))
        if len(data) < 2:
            return metrics

        company_id = data[0] + (data[1] << 8)
        payload = data[2:]

        if company_id == 0x004C:                    # Apple
            metrics['brand'] = 'Apple'
            if payload:
                type_id = payload[0]
                if type_id == 0x02 and len(payload) >= 21:
                    metrics['beacon_type'] = 'iBeacon'
                elif type_id == 0x10:
                    metrics['service'] = 'Nearby/Continuity'
                elif type_id == 0x07:
                    metrics['service'] = 'AirPods/Proximity Pair'

        elif company_id == 0x015D:                  # Xiaomi MiBeacon
            metrics['brand'] = 'Xiaomi'
            if len(payload) > 11:
                event_id = payload[9] + (payload[10] << 8)
                if event_id == 0x1004 and len(payload) >= 13:
                    temp_raw = payload[11] + (payload[12] << 8)
                    metrics['temperature_c'] = round(temp_raw / 10.0, 1)
                elif event_id == 0x1006 and len(payload) >= 13:
                    hum_raw = payload[11] + (payload[12] << 8)
                    metrics['humidity_pct'] = round(hum_raw / 10.0, 1)

        elif company_id == 0x0006:                  # Microsoft
            metrics['brand'] = 'Microsoft'
            if payload and payload[0] == 0x03:
                metrics['service'] = 'Swift Pair'

    except Exception as exc:
        logger.debug("decode_manufacturer_data failed for %r: %s", hex_data, exc)

    return metrics
