# Govee H601E – Home Assistant Custom Integration

Local-push Bluetooth LE control for the **Govee H601E** (and compatible
**H604x** family) ceiling lamp, with no cloud dependency.  All communication
happens directly over BLE using a cryptographic protocol reverse-engineered
from the official Govee Android APK.

---

## Features

| Entity | Description |
|--------|-------------|
| `light.<name>` | Master on/off for the entire lamp |
| `light.<name>_center` | Centre panel – brightness, colour temperature (2 200–6 500 K), RGB |
| `light.<name>_ring` | Outer RGB ring – brightness, RGB, animated effects (Solid / Breathe / Strobe / Chase / Gradient) |
| `switch.<name>_persistent_connection` | Toggle between persistent and on-demand BLE mode |

### Ring light effects

The outer ring exposes five effects via HA's standard effect picker:

| Effect | Description |
|--------|-------------|
| **Solid** | Static colour (default) |
| **Breathe** | Slow pulse / fade in–out |
| **Strobe** | Fast flash |
| **Chase** | Streamer running around the ring |
| **Gradient** | Smooth two-colour gradient (complementary hue auto-computed) |

### Connection modes

| Mode | Description |
|------|-------------|
| **Persistent** *(default)* | One permanent BLE session per lamp. Notifications and heartbeats are processed in real time. Recommended for fast response. |
| **On-demand** | BLE connects only to send a command, then disconnects. Lower radio usage; slightly higher latency per command. |

---

## Requirements

- Home Assistant **2023.3** or later
- The **Bluetooth** integration enabled (built-in, no extra hardware needed on
  most hosts running HA OS or Supervised)
- The H601E lamp within Bluetooth range of the HA host
- Python package **pycryptodome** ≥ 3.19 (installed automatically via
  `requirements` in `manifest.json`)
- Python package **bleak-retry-connector** ≥ 3.6 (installed automatically)

---

## Installation

### Via HACS (recommended)

1. Open HACS → **Integrations** → three-dot menu → **Custom repositories**.
2. Add `https://github.com/YOUR_USERNAME/govee-h601e-ha` as an
   **Integration** repository.
3. Search for **Govee H601E** and install.
4. Restart Home Assistant.
5. Go to **Settings → Devices & Services → Add Integration** and search for
   **Govee H601E**.

### Manual

1. Copy the `custom_components/govee_h601e` folder into
   `<config>/custom_components/govee_h601e/`.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for
   **Govee H601E**.

---

## Configuration

The integration is fully configured through the UI config flow.

### Auto-discovery

If your lamp is advertising nearby, HA will show a notification in
**Settings → Devices & Services** offering to set it up automatically.
Click **Configure**, confirm the device name and select the desired connection
mode.

### Manual setup

1. **Settings → Devices & Services → Add Integration → Govee H601E**.
2. Select a discovered device from the list *or* enter the BLE address
   manually (`AA:BB:CC:DD:EE:FF` on Linux/Windows,
   `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` CoreBluetooth UUID on macOS).
3. Assign a display name and choose a connection mode.

### Multiple lamps

Repeat the setup process for each physical lamp.  Each lamp gets its own
device with three light entities and one switch.

---

## Cryptographic protocol

The H601E uses a hybrid encryption scheme (reverse-engineered from
`com.govee.encryp.ble`):

1. **Static communication key** (`commKey = b"MakingLifeSmarte"`) – embedded
   in the APK, decrypted from `strings.xml` using `AESUtils.decode`.
2. **Handshake** – two-step exchange (HS1 / HS2) using AES-ECB + commKey to
   negotiate a per-session 16-byte key.
3. **Commands** – every command frame is encrypted with the session key using
   the same AES-ECB + RC4 hybrid (`safe_encrypt` from `Safe.Companion`).

All protocol logic lives in `govee/device.py` with no Home Assistant
dependencies, so it can be tested and reused independently.

---

## Known limitations

- **State readback** – Power-on/off state for each zone is synchronised from
  the device's heartbeat echo immediately after (re)connect.  Brightness,
  colour and ring-effect state are still tracked *optimistically* – the
  protocol offers no non-destructive query for those values.  Hardware-button
  presses are not yet reflected in HA because the unsolicited state-push
  notification format is not yet fully documented.
- **Ring colour temperature** – The outer ring only supports RGB colour via
  the DIY protocol (`cmdType = 0x50`).  Colour temperature on the ring is
  not available.
- **Brightness granularity** – Govee uses 0–100 %; HA uses 0–255.  Rounding
  means not all 256 HA values map to unique Govee values.
- **macOS / CoreBluetooth** – On macOS the BLE address is a UUID assigned by
  CoreBluetooth rather than the hardware MAC.  This UUID is stable per host
  but differs from the MAC shown on the device label.

---

## Roadmap

### Unsolicited state-push parsing

The H601E may push state notifications when the lamp is toggled via the
hardware button or the Govee app (independent of command echoes).  The
integration currently decrypts all incoming frames and applies the parsed
state delta, but does not yet handle *unsolicited* pushes because their
exact trigger and payload format have not been captured from live BLE traces.

Once characterised, the coordinator's `_on_notification` handler already
routes `STATE_UPDATE` frames through `_apply_state_update`, so wiring in
unsolicited pushes requires only extending `_parse_heartbeat` / adding new
parser helpers in `govee/device.py`.

---

## Development

### Project structure

```
custom_components/govee_h601e/
├── __init__.py          – Integration setup / teardown
├── manifest.json        – HA metadata + Bluetooth advertisement filters
├── config_flow.py       – UI config flow (discovery + manual) + options flow
├── const.py             – All shared constants
├── coordinator.py       – BLE connection manager + command dispatcher
├── diagnostics.py       – Diagnostics download support
├── light.py             – Three LightEntity subclasses
├── switch.py            – Connection-mode SwitchEntity
├── strings.json         – UI strings (config flow, options, repair issues)
├── translations/
│   └── en.json          – English translations (mirrors strings.json)
└── govee/
    ├── __init__.py      – Package marker
    ├── device.py        – Protocol layer (crypto, frames, state model, notification parsing)
    └── scanner.py       – BLE advertisement detection helpers
```

### Running tests (example)

```bash
# Install dev dependencies
pip install pycryptodome pytest

# Run protocol tests (no HA required)
pytest tests/
```

### Adding support for new commands

1. Add a `cmd_*` builder function in `govee/device.py`.
2. Add the corresponding `async_set_*` method on `GoveeCoordinator`.
3. Wire it up in the appropriate light / switch entity.

---

## Acknowledgements

Protocol analysis based on reverse engineering of the Govee Home Android APK
(v7.3.15).  Relevant APK classes:

- `com.govee.encryp.ble.Safe` – AES-ECB + RC4 hybrid
- `com.govee.encryp.ble.Controller4Aes` – Handshake frame builders
- `com.govee.encryp.ble.EncryptionManager` – V1 session protocol
- `com.govee.shared.protocol.h601e.KmpH601EFDiyParse` – Ring DIY protocol
- `com.govee.shared.protocol.h601e.subEffect.KmpSubEffect*` – Ring effect builders (Breathe, Strobe, Chase, Gradient)
- `com.govee.h604a.ble.controller.ComposeLightHeartController` – Heartbeat response format (per-zone power states)
- `com.govee.base2home.Constant.Y1` – Kelvin→RGB lookup table

---

## License

MIT – see `LICENSE` for details.
