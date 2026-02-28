"""BLE device detection helpers for the Govee H601E integration.

This module provides utilities for identifying Govee H601E (and related H604x)
lamps in BLE advertisement data.  It is deliberately kept free of direct Home
Assistant imports so that the detection logic can be unit-tested standalone.

The coordinator and config-flow code depend on this module to decide whether a
discovered BLE device is a candidate for this integration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

_LOGGER = logging.getLogger(__name__)

# ── Known advertisement identifiers ───────────────────────────────────────────

GOVEE_LOCAL_NAME_PREFIXES: tuple[str, ...] = (
    "GVH",       # Most Govee BLE models
    "Govee",     # Some newer firmware versions
    "govee",     # Lower-case variant seen on some units
    "ihoment",   # OEM name used on some Govee-manufactured devices
)
"""BLE advertisement local-name prefixes that identify a Govee lamp."""

GOVEE_SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
"""Primary GATT service UUID advertised by the H601E and related H604x models."""

# Model sub-strings that confirm H601E / H604x family when found in the name.
H601E_MODEL_HINTS: tuple[str, ...] = ("H601", "H604")
"""Sub-strings in the local name that indicate the H601E / H604x family."""


# ── Data structure returned by is_govee_h601e ─────────────────────────────────

@dataclass
class DeviceInfo:
    """Summary information about a discovered Govee BLE lamp.

    Attributes:
        address:        BLE address (MAC on Linux/Windows, CoreBluetooth UUID on macOS).
        local_name:     Advertisement local name, or an empty string if absent.
        is_h601e_family: ``True`` if the name hints at the H601E / H604x family.
        rssi:           Received signal strength in dBm (0 if unknown).
    """

    address: str
    local_name: str
    is_h601e_family: bool
    rssi: int = 0


def is_govee_device(local_name: str | None, service_uuids: list[str] | None) -> bool:
    """Return ``True`` if the advertisement data belongs to a Govee lamp.

    The check uses *either* the local name prefix *or* the presence of the
    Govee service UUID in the advertisement's service-UUID list.

    Args:
        local_name:    BLE advertisement local name (may be ``None``).
        service_uuids: List of 128-bit UUIDs advertised in the packet
                       (may be ``None`` or empty).

    Returns:
        ``True`` if the device is likely a Govee lamp.
    """
    if local_name:
        lname = local_name.strip()
        for prefix in GOVEE_LOCAL_NAME_PREFIXES:
            if lname.startswith(prefix):
                return True

    if service_uuids:
        normalised = {u.lower() for u in service_uuids}
        if GOVEE_SERVICE_UUID.lower() in normalised:
            return True

    return False


def is_h601e_family(local_name: str | None) -> bool:
    """Return ``True`` if the name suggests an H601E or H604x lamp.

    Args:
        local_name: BLE advertisement local name (may be ``None``).

    Returns:
        ``True`` when a model-hint substring is found in the name.
    """
    if not local_name:
        return False
    for hint in H601E_MODEL_HINTS:
        if hint in local_name:
            return True
    return False


def device_info_from_advertisement(
    address: str,
    local_name: str | None,
    service_uuids: list[str] | None,
    rssi: int = 0,
) -> DeviceInfo | None:
    """Build a :class:`DeviceInfo` from raw advertisement fields.

    Returns ``None`` if the advertisement does not match a Govee lamp.

    Args:
        address:       BLE MAC address or CoreBluetooth UUID.
        local_name:    Advertisement local name.
        service_uuids: Advertised 128-bit service UUIDs.
        rssi:          Received signal strength in dBm.

    Returns:
        :class:`DeviceInfo` instance, or ``None`` if not a Govee device.
    """
    if not is_govee_device(local_name, service_uuids):
        return None

    return DeviceInfo(
        address=address,
        local_name=local_name or "",
        is_h601e_family=is_h601e_family(local_name),
        rssi=rssi,
    )


def friendly_name_from_advertisement(local_name: str | None, address: str) -> str:
    """Derive a human-readable display name from advertisement data.

    Falls back to a shortened address if no local name is available.

    Args:
        local_name: BLE advertisement local name.
        address:    BLE address string.

    Returns:
        A non-empty display name string.
    """
    if local_name and local_name.strip():
        return local_name.strip()
    # Use the last 6 characters of the address for a compact fallback.
    short_addr = address.replace(":", "").replace("-", "")[-6:].upper()
    return f"Govee H601E {short_addr}"
