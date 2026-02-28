"""Govee H601E BLE Ceiling Light – Home Assistant integration.

This integration provides local-push BLE control for the Govee H601E (and
compatible H604x) ceiling lamp directly within Home Assistant, with no cloud
dependency.

Architecture overview
---------------------
``govee/device.py``
    Pure-Python protocol layer: crypto (AES-ECB + RC4), frame builders and
    notification parser.  Has zero Home Assistant dependencies.

``govee/scanner.py``
    BLE advertisement helpers for detecting H601E devices.

``coordinator.py``
    :class:`~coordinator.GoveeCoordinator` manages the BLE connection
    lifecycle (persistent or on-demand), performs the handshake, sends
    commands and distributes state changes to entities.

``light.py``
    Three :class:`homeassistant.components.light.LightEntity` subclasses:
    main (on/off), centre panel (brightness + CT + RGB) and outer ring (RGB).

``switch.py``
    :class:`homeassistant.components.switch.SwitchEntity` that toggles the
    connection mode at runtime.

``config_flow.py``
    Guided setup via BLE discovery or manual MAC entry; includes connection
    mode selection.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_CONNECTION_MODE,
    CONF_MAC,
    CONNECTION_MODE_DEFAULT,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import GoveeCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a Govee H601E lamp from a config entry.

    Creates a :class:`~coordinator.GoveeCoordinator` for the lamp, starts it
    (establishing the BLE connection in persistent mode), stores it in
    ``hass.data`` and forwards setup to the registered platforms.

    Args:
        hass:  Home Assistant instance.
        entry: Config entry created by the config flow.

    Returns:
        ``True`` on success.
    """
    address: str = entry.data[CONF_MAC]
    # entry.options takes precedence over entry.data so that the Options Flow
    # and the connection-mode switch both write to the same source of truth.
    connection_mode: str = entry.options.get(
        CONF_CONNECTION_MODE,
        entry.data.get(CONF_CONNECTION_MODE, CONNECTION_MODE_DEFAULT),
    )

    _LOGGER.debug(
        "Setting up Govee H601E: address=%s, mode=%s", address, connection_mode
    )

    coordinator = GoveeCoordinator(
        hass=hass,
        address=address,
        connection_mode=connection_mode,
    )

    # Store coordinator in hass.data so platforms can retrieve it
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    # Start connection (non-blocking; failure is logged, not raised)
    await coordinator.async_start()

    # Forward platform setup (light, switch)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Apply options changes (from the Options Flow) live without a full reload.
    # The switch entity writes to entry.options too, but its direct coordinator
    # call sets the mode first, so the listener is effectively a no-op for it.
    entry.async_on_unload(
        entry.add_update_listener(_async_update_listener)
    )

    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Apply options changes to the running coordinator without a full reload.

    Called whenever ``entry.options`` is updated (by the Options Flow or by the
    connection-mode switch entity).  Applies the new connection mode live if it
    differs from the coordinator's current mode.
    """
    coordinator: GoveeCoordinator = hass.data[DOMAIN].get(entry.entry_id)
    if coordinator is None:
        return
    new_mode = entry.options.get(CONF_CONNECTION_MODE)
    if new_mode and new_mode != coordinator.connection_mode:
        _LOGGER.debug(
            "Options update: applying connection mode %s → %s",
            coordinator.connection_mode, new_mode,
        )
        await coordinator.async_set_connection_mode(new_mode)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and disconnect from the lamp.

    Args:
        hass:  Home Assistant instance.
        entry: Config entry being removed.

    Returns:
        ``True`` if all platforms were unloaded successfully.
    """
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        coordinator: GoveeCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_stop()
        _LOGGER.debug("Govee H601E entry unloaded: %s", entry.data[CONF_MAC])

    return unload_ok
