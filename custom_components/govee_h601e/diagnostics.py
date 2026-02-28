"""Diagnostics support for the Govee H601E integration.

Users can download a redacted JSON snapshot from
Settings → Devices & Services → Govee H601E → three-dot menu → Download diagnostics.

The MAC address is redacted from the output to avoid sharing device identifiers
in public bug reports.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_MAC, DOMAIN
from .coordinator import GoveeCoordinator

_TO_REDACT: set[str] = {CONF_MAC}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a Govee H601E config entry.

    Args:
        hass:  Home Assistant instance.
        entry: Config entry to collect diagnostics for.

    Returns:
        Redacted dictionary suitable for inclusion in a bug report.
    """
    coordinator: GoveeCoordinator = hass.data[DOMAIN][entry.entry_id]
    state = coordinator.state

    return async_redact_data(
        {
            "entry_data": dict(entry.data),
            "entry_options": dict(entry.options),
            "connection": {
                "mode": coordinator.connection_mode,
                "available": coordinator.available,
                "is_connected": bool(
                    coordinator._client and coordinator._client.is_connected
                ),
                "has_session_key": coordinator._session_key is not None,
                "reconnect_attempt": coordinator._reconnect_attempt,
            },
            "state": {
                "is_on": state.is_on,
                "brightness_pct": state.brightness_pct,
                "center": {
                    "is_on": state.center.is_on,
                    "brightness_pct": state.center.brightness_pct,
                    "color_mode": state.center.color_mode.value,
                    "color_temp_kelvin": state.center.color_temp_kelvin,
                    "rgb": state.center.rgb,
                },
                "ring": {
                    "is_on": state.ring.is_on,
                    "brightness_pct": state.ring.brightness_pct,
                    "color_mode": state.ring.color_mode.value,
                    "rgb": state.ring.rgb,
                },
            },
        },
        _TO_REDACT,
    )
