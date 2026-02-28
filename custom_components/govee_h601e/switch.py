"""Switch platform for the Govee H601E integration.

Provides a single :class:`GoveeConnectionModeSwitch` entity per lamp that lets
the user toggle between *persistent* and *on-demand* BLE connection modes from
the Home Assistant UI without having to reconfigure the integration.

+------------------+----------------------------------+
| Switch state     | Connection mode                  |
+==================+==================================+
| **ON**  (default)| ``persistent`` – one permanent   |
|                  | BLE connection with heartbeat    |
+------------------+----------------------------------+
| **OFF**          | ``on_demand`` – transient BLE    |
|                  | connection per command           |
+------------------+----------------------------------+

When the switch is toggled the coordinator tears down the existing connection
and re-establishes it in the new mode.  The new mode is also persisted back to
the config entry so that it survives a Home Assistant restart.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_CONNECTION_MODE,
    CONF_MAC,
    CONNECTION_MODE_ON_DEMAND,
    CONNECTION_MODE_PERSISTENT,
    DOMAIN,
    MANUFACTURER,
    MODEL,
    SUFFIX_PERSIST,
)
from .coordinator import GoveeCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the connection-mode switch for a config entry.

    Args:
        hass:               Home Assistant instance.
        entry:              Config entry for this lamp.
        async_add_entities: Callback to register the new entities.
    """
    coordinator: GoveeCoordinator = hass.data[DOMAIN][entry.entry_id]
    name: str = entry.data.get("name", "Govee H601E")
    async_add_entities([GoveeConnectionModeSwitch(coordinator, entry, name)])


class GoveeConnectionModeSwitch(SwitchEntity):
    """Switch that toggles the BLE connection mode for a Govee H601E lamp.

    ON  = persistent (one permanent BLE session, heartbeat running)
    OFF = on-demand  (transient connection per command)
    """

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_icon = "mdi:bluetooth-connect"

    def __init__(
        self,
        coordinator: GoveeCoordinator,
        entry: ConfigEntry,
        lamp_name: str,
    ) -> None:
        """Initialise the switch entity.

        Args:
            coordinator: Coordinator managing the BLE connection.
            entry:       Config entry.
            lamp_name:   User-assigned display name of the lamp.
        """
        self._coordinator = coordinator
        self._entry = entry
        self._lamp_name = lamp_name
        self._attr_unique_id = f"{entry.data[CONF_MAC]}{SUFFIX_PERSIST}"
        self._attr_name = "Persistent connection"
        self._remove_callback: Callable[[], None] | None = None

    # ── Device info ────────────────────────────────────────────────────────────

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry info (same device as the light entities)."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.data[CONF_MAC])},
            name=self._lamp_name,
            manufacturer=MANUFACTURER,
            model=MODEL,
        )

    # ── State ──────────────────────────────────────────────────────────────────

    @property
    def is_on(self) -> bool:
        """Return ``True`` when the coordinator is in persistent mode."""
        return self._coordinator.connection_mode == CONNECTION_MODE_PERSISTENT

    # ── HA lifecycle ───────────────────────────────────────────────────────────

    async def async_added_to_hass(self) -> None:
        """Subscribe to coordinator updates."""
        self._remove_callback = self._coordinator.register_update_callback(
            self.async_write_ha_state
        )

    async def async_will_remove_from_hass(self) -> None:
        """Unsubscribe from coordinator updates."""
        if self._remove_callback is not None:
            self._remove_callback()
            self._remove_callback = None

    # ── Commands ───────────────────────────────────────────────────────────────

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Switch to persistent connection mode.

        Updates the coordinator, persists the change to the config entry and
        calls ``async_write_ha_state`` to reflect the new state immediately.
        """
        await self._set_mode(CONNECTION_MODE_PERSISTENT)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Switch to on-demand connection mode.

        Updates the coordinator, persists the change to the config entry and
        calls ``async_write_ha_state`` to reflect the new state immediately.
        """
        await self._set_mode(CONNECTION_MODE_ON_DEMAND)

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _set_mode(self, mode: str) -> None:
        """Apply a new connection mode.

        Instructs the coordinator to switch modes and persists the choice to
        the config entry data so that it survives a restart.

        Args:
            mode: ``CONNECTION_MODE_PERSISTENT`` or ``CONNECTION_MODE_ON_DEMAND``.
        """
        _LOGGER.debug(
            "[%s] Connection mode change requested: %s → %s",
            self._coordinator.address,
            self._coordinator.connection_mode,
            mode,
        )

        # Update coordinator (handles reconnect/disconnect internally)
        await self._coordinator.async_set_connection_mode(mode)

        # Persist the new mode to entry.options (the authoritative source read
        # by both the Options Flow and __init__.async_setup_entry on restart).
        new_options = {**self._entry.options, CONF_CONNECTION_MODE: mode}
        self.hass.config_entries.async_update_entry(
            self._entry, options=new_options
        )

        self.async_write_ha_state()
