"""Config flow for the Govee H601E integration.

Supports two discovery paths:

1. **Automatic BLE discovery** – Home Assistant's Bluetooth component detects
   an H601E advertisement and triggers ``async_step_bluetooth``.  The user
   only needs to confirm the device and optionally rename it.

2. **Manual entry** – The user selects "Add integration → Govee H601E" from
   the HA integrations menu and enters the BLE address by hand.  This is the
   fallback for devices whose advertisements don't match the manifest filters.

Both paths share the same final step where the user assigns a display name and
chooses the initial connection mode.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.const import CONF_NAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_CONNECTION_MODE,
    CONF_MAC,
    CONNECTION_MODE_ON_DEMAND,
    CONNECTION_MODE_PERSISTENT,
    DOMAIN,
)
from .govee.scanner import (
    friendly_name_from_advertisement,
    is_govee_device,
)

_LOGGER = logging.getLogger(__name__)

# ── Validation helpers ─────────────────────────────────────────────────────────

# Accepts standard MAC (AA:BB:CC:DD:EE:FF) and CoreBluetooth UUIDs
_RE_MAC = re.compile(
    r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    r"|^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$"
)


def _validate_address(value: str) -> str:
    """Validate a BLE address string.

    Args:
        value: User-supplied address string.

    Returns:
        Normalised address.

    Raises:
        vol.Invalid: If the address format is not recognised.
    """
    stripped = value.strip()
    if not _RE_MAC.match(stripped):
        raise vol.Invalid(
            "Invalid BLE address.  "
            "Expected AA:BB:CC:DD:EE:FF or a CoreBluetooth UUID."
        )
    return stripped


# ── Config flow ────────────────────────────────────────────────────────────────

class GoveeH601EConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the Govee H601E config-entry creation flow.

    Steps
    -----
    bluetooth         Called by HA when an advertisement matches the manifest.
    bluetooth_confirm User confirms the auto-discovered device.
    user              Manual address entry (fallback path).
    finish            Common final step: name + connection-mode selection.
    """

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> GoveeH601EOptionsFlow:
        """Return the options flow handler for this config entry."""
        return GoveeH601EOptionsFlow(config_entry)

    def __init__(self) -> None:
        """Initialise flow instance variables."""
        self._discovered_address: str | None = None
        self._discovered_name: str | None = None

    # ── Auto-discovery path ────────────────────────────────────────────────────

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        """Handle a BLE advertisement match triggered by HA's Bluetooth component.

        HA calls this step when an advertisement matches one of the patterns
        declared in ``manifest.json`` (service UUID or local-name prefix).

        Args:
            discovery_info: Advertisement metadata provided by HA.

        Returns:
            Flow result proceeding to the confirmation step.
        """
        _LOGGER.debug(
            "Bluetooth discovery: address=%s name=%s",
            discovery_info.address, discovery_info.name,
        )

        # Deduplicate: abort if this address is already configured
        await self.async_set_unique_id(discovery_info.address.upper())
        self._abort_if_unique_id_configured()

        # Quick sanity check (manifest filters already did the heavy lifting)
        service_uuids = list(discovery_info.service_uuids or [])
        if not is_govee_device(discovery_info.name, service_uuids):
            return self.async_abort(reason="not_govee_device")

        self._discovered_address = discovery_info.address
        self._discovered_name = friendly_name_from_advertisement(
            discovery_info.name, discovery_info.address
        )

        self.context["title_placeholders"] = {"name": self._discovered_name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask the user to confirm the auto-discovered device.

        Args:
            user_input: Form data (submitted name and connection mode), or
                        ``None`` on the first display of the form.

        Returns:
            Flow result: show form again on errors, or create entry on success.
        """
        if self._discovered_address is None:
            # Should never happen: _discovered_address is set in async_step_bluetooth
            # before this step is called.  Guard against potential state corruption.
            return self.async_abort(reason="device_address_unavailable")

        if user_input is not None:
            return self.async_create_entry(
                title=user_input[CONF_NAME],
                data={
                    CONF_MAC: self._discovered_address,
                    CONF_NAME: user_input[CONF_NAME],
                    CONF_CONNECTION_MODE: user_input[CONF_CONNECTION_MODE],
                },
            )

        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=_build_finish_schema(self._discovered_name or "Govee H601E"),
            description_placeholders={
                "address": self._discovered_address,
                "name": self._discovered_name or self._discovered_address,
            },
        )

    # ── Manual entry path ──────────────────────────────────────────────────────

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial manual-entry step shown in the integrations menu.

        If previously discovered H601E devices exist in the Bluetooth cache,
        they are offered as a list.  Otherwise a free-text address field is
        shown.

        Args:
            user_input: Submitted form data, or ``None`` on first display.

        Returns:
            Flow result.
        """
        errors: dict[str, str] = {}

        # Collect already-discovered Govee devices from the HA BT cache
        discovered: list[BluetoothServiceInfoBleak] = [
            info
            for info in async_discovered_service_info(self.hass, connectable=True)
            if is_govee_device(info.name, list(info.service_uuids or []))
        ]

        if user_input is not None:
            address = user_input.get(CONF_MAC, "").strip()
            try:
                address = _validate_address(address)
            except vol.Invalid:
                errors[CONF_MAC] = "invalid_address"
            else:
                # Deduplicate
                normalised_id = address.upper()
                await self.async_set_unique_id(normalised_id)
                self._abort_if_unique_id_configured()

                self._discovered_address = address
                self._discovered_name = user_input.get(CONF_NAME) or f"Govee H601E {address[-5:]}"
                return self.async_create_entry(
                    title=self._discovered_name,
                    data={
                        CONF_MAC: address,
                        CONF_NAME: self._discovered_name,
                        CONF_CONNECTION_MODE: user_input[CONF_CONNECTION_MODE],
                    },
                )

        # Build schema: if discovered devices exist, offer a select list;
        # otherwise show a plain text field for the address.
        if discovered:
            address_field: vol.Schema = vol.In(
                {
                    info.address: f"{info.name or info.address}  ({info.address})"
                    for info in discovered
                }
            )
        else:
            address_field = str

        schema = vol.Schema(
            {
                vol.Required(CONF_MAC): address_field,
                vol.Optional(CONF_NAME, default="Govee H601E"): str,
                vol.Required(
                    CONF_CONNECTION_MODE, default=CONNECTION_MODE_PERSISTENT
                ): vol.In(
                    {
                        CONNECTION_MODE_PERSISTENT: "Persistent (recommended)",
                        CONNECTION_MODE_ON_DEMAND: "On-demand (lower radio usage)",
                    }
                ),
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )


# ── Schema helpers ─────────────────────────────────────────────────────────────

def _build_finish_schema(default_name: str) -> vol.Schema:
    """Return the confirmation / finish step schema.

    Args:
        default_name: Pre-filled display name for the lamp.

    Returns:
        Voluptuous schema for the form.
    """
    return vol.Schema(
        {
            vol.Required(CONF_NAME, default=default_name): str,
            vol.Required(
                CONF_CONNECTION_MODE, default=CONNECTION_MODE_PERSISTENT
            ): vol.In(
                {
                    CONNECTION_MODE_PERSISTENT: "Persistent (recommended)",
                    CONNECTION_MODE_ON_DEMAND: "On-demand (lower radio usage)",
                }
            ),
        }
    )


# ── Options flow ───────────────────────────────────────────────────────────────

class GoveeH601EOptionsFlow(OptionsFlow):
    """Options flow for changing the BLE connection mode after initial setup.

    Accessible via Settings → Devices & Services → Govee H601E → Configure.
    Changes are applied live to the running coordinator without a full reload.
    """

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialise with the current config entry."""
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Show the options form.

        Args:
            user_input: Submitted form data, or ``None`` on first display.

        Returns:
            Flow result.
        """
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        # Read current mode: entry.options takes precedence over entry.data
        current_mode = self._config_entry.options.get(
            CONF_CONNECTION_MODE,
            self._config_entry.data.get(CONF_CONNECTION_MODE, CONNECTION_MODE_PERSISTENT),
        )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_CONNECTION_MODE, default=current_mode): vol.In(
                        {
                            CONNECTION_MODE_PERSISTENT: "Persistent (recommended)",
                            CONNECTION_MODE_ON_DEMAND: "On-demand (lower radio usage)",
                        }
                    ),
                }
            ),
        )
