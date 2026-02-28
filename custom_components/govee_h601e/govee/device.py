"""Govee H601E protocol layer.

This module contains **all** protocol logic for the Govee H601E BLE ceiling
lamp.  It has **no** dependency on Home Assistant; every function and class
here can be tested with plain Python + pycryptodome.

Cryptography (reverse-engineered from com.govee.encryp.ble.Safe):
  * AES/ECB/NoPadding for the first 16 bytes of every frame.
  * RC4 (PRGA) for any bytes beyond the first 16 (bytes 16–19 of a 20-byte
    frame).
  * ``safe_encrypt`` / ``safe_decrypt`` implement this hybrid scheme exactly as
    the APK does.

Handshake (com.govee.encryp.ble.EncryptionManager V1):
  1. Client sends HS1 (safe_encrypt with commKey → session-key request).
  2. Device replies with HS1 response (safe_decrypt → extract 16-byte SK).
  3. Client sends HS2 (safe_encrypt with commKey → session confirmation).
  4. Device echoes HS2.

All subsequent commands are ``safe_encrypt``-ed with the negotiated session key.

Frame layout (BleUtils.generate20Bytes):
  ``[proType, cmdType, payload(0-17 bytes, zero-padded), xor_checksum]``
  Total: 20 bytes.
"""

from __future__ import annotations

import colorsys
import logging
import os
from dataclasses import dataclass, field
from enum import Enum

from Crypto.Cipher import AES as _AES  # type: ignore[import-untyped]

_LOGGER = logging.getLogger(__name__)

# ── BLE UUIDs (defined here so govee/device.py is self-contained) ─────────────

WRITE_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
"""GATT characteristic UUID for writing commands (write-without-response)."""

NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
"""GATT characteristic UUID for receiving device notifications."""

SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
"""Primary GATT service UUID advertised by the H601E."""

# ── Static communication key ───────────────────────────────────────────────────
# Derived from APK: AESUtils.decode(app_communication, app_session)
#   app_communication → AES-256-ECB-encrypted hex string (strings.xml)
#   app_session       → "chiygnveeihhmme_govee_sessioniyz" (decrypt password)
# Result: parseHexStr2Byte("4D616B696E674C696665536D61727465")
#       = b"MakingLifeSmarte"  (16 bytes, ASCII)

COMM_KEY: bytes = bytes.fromhex("4d616b696e674c696665536d61727465")
"""Static 16-byte AES key shared by all Govee BLE devices in this family."""

# ── Kelvin colour temperature range ───────────────────────────────────────────

KELVIN_MIN: int = 2200
KELVIN_MAX: int = 6500

# ── Kelvin → RGB approximation table ──────────────────────────────────────────
# Source: com.govee.base2home.Constant.Y1 (LinkedHashMap, H604a range 2200–6500 K).
# Used in SubModeColor.makeSubModeColor4Kelvin() to build the colour-temp frame.
# Each entry: kelvin → (R, G, B) white-point approximation.

KELVIN_RGB: dict[int, tuple[int, int, int]] = {
    2200: (0xFF, 0x98, 0x29), 2300: (0xFF, 0x9D, 0x33), 2400: (0xFF, 0xA2, 0x3C),
    2500: (0xFF, 0xA6, 0x45), 2600: (0xFF, 0xAA, 0x4D), 2700: (0xFF, 0xAE, 0x54),
    2800: (0xFF, 0xB2, 0x5B), 2900: (0xFF, 0xB6, 0x62), 3000: (0xFF, 0xB9, 0x69),
    3100: (0xFF, 0xBD, 0x6F), 3200: (0xFF, 0xC0, 0x76), 3300: (0xFF, 0xC3, 0x7C),
    3400: (0xFF, 0xC6, 0x82), 3500: (0xFF, 0xC9, 0x87), 3600: (0xFF, 0xCB, 0x8D),
    3700: (0xFF, 0xCE, 0x92), 3800: (0xFF, 0xD0, 0x97), 3900: (0xFF, 0xD3, 0x9C),
    4000: (0xFF, 0xD5, 0xA1), 4100: (0xFF, 0xD7, 0xA6), 4200: (0xFF, 0xD9, 0xAB),
    4300: (0xFF, 0xDB, 0xAF), 4400: (0xFF, 0xDD, 0xB4), 4500: (0xFF, 0xDF, 0xB8),
    4600: (0xFF, 0xE1, 0xBC), 4700: (0xFF, 0xE2, 0xC0), 4800: (0xFF, 0xE4, 0xC4),
    4900: (0xFF, 0xE5, 0xC8), 5000: (0xFF, 0xE7, 0xCC), 5100: (0xFF, 0xE8, 0xD0),
    5200: (0xFF, 0xEA, 0xD3), 5300: (0xFF, 0xEB, 0xD7), 5400: (0xFF, 0xED, 0xDA),
    5500: (0xFF, 0xEE, 0xDE), 5600: (0xFF, 0xEF, 0xE1), 5700: (0xFF, 0xF0, 0xE4),
    5800: (0xFF, 0xF1, 0xE7), 5900: (0xFF, 0xF3, 0xEA), 6000: (0xFF, 0xF4, 0xED),
    6100: (0xFF, 0xF5, 0xF0), 6200: (0xFF, 0xF6, 0xF3), 6300: (0xFF, 0xF7, 0xF7),
    6400: (0xFF, 0xF8, 0xF8), 6500: (0xFF, 0xF9, 0xFB),
}

# ── Segment bitmasks (SubModeColor.getWriteBytes, ColorModeH604x.java) ────────
# bArr[10]: segments  0- 7  (LSB = segment 0)
# bArr[11]: segments  8-15
# bArr[12]: segments 16-23
# Panel = segments 0-13 (centre diffuser)
# Ring  = segments 14-23 (outer RGB ring) – NOT controlled via this bitmask;
#         the ring uses a separate DIY protocol (cmdType=0x50, see cmd_ring_diy).

_BITMASK_ALL: tuple[int, int, int] = (0xFF, 0xFF, 0xFF)
"""All 24 segments (centre + ring area), but ring colour actually needs 0x50."""

_BITMASK_PANEL: tuple[int, int, int] = (0xFF, 0x3F, 0x00)
"""Only the 14 centre-panel segments (0–13)."""


# ═════════════════════════════════════════════════════════════════════════════
# State model
# ═════════════════════════════════════════════════════════════════════════════

class LightColorMode(str, Enum):
    """Active colour mode of a light zone."""
    RGB = "rgb"
    COLOR_TEMP = "color_temp"
    UNKNOWN = "unknown"


@dataclass
class ZoneState:
    """State of one independently controllable light zone (centre or ring)."""

    is_on: bool = False
    """Whether this zone is powered on."""

    brightness_pct: int = 100
    """Brightness as a percentage (0–100).  Note: brightness is physically
    shared between zones on the H601E; both zones read from the same value."""

    color_mode: LightColorMode = LightColorMode.COLOR_TEMP

    color_temp_kelvin: int = 4000
    """Active colour temperature in Kelvin (2 200–6 500 K)."""

    rgb: tuple[int, int, int] = (255, 255, 255)
    """Active RGB colour (each component 0–255)."""

    effect: str | None = None
    """Active ring effect name (e.g. 'Breathe'), or ``None`` for solid colour."""


@dataclass
class GoveeDeviceState:
    """Complete state snapshot of a single Govee H601E lamp.

    Home-Assistant entities read from and write to this object via the
    coordinator.  Fields are updated both optimistically (on command send) and
    from device notification echoes parsed by :func:`parse_notification`.
    """

    is_on: bool = False
    """Master power state (affects both centre and ring)."""

    # Brightness is global on the H601E – one value controls both zones.
    brightness_pct: int = 100
    """Global brightness as a percentage (0–100)."""

    center: ZoneState = field(default_factory=ZoneState)
    """State of the centre panel (supports RGB and colour temperature)."""

    ring: ZoneState = field(default_factory=lambda: ZoneState(
        color_mode=LightColorMode.RGB,
        rgb=(255, 255, 255),
    ))
    """State of the outer RGB ring (RGB only; no colour-temperature support)."""


@dataclass
class StateUpdate:
    """Partial state delta extracted from a device notification echo.

    Fields default to ``None`` meaning "not carried by this notification".
    The coordinator merges only the non-``None`` fields into
    :class:`GoveeDeviceState`.

    The ``ring_present`` sentinel is needed because ``ring_effect`` may
    legitimately be ``None`` (solid colour, no active effect), which would
    otherwise be indistinguishable from "ring state not present in this frame".
    """

    # ── Power ─────────────────────────────────────────────────────────────────
    is_on: bool | None = None
    center_is_on: bool | None = None
    ring_is_on: bool | None = None

    # ── Brightness ────────────────────────────────────────────────────────────
    brightness_pct: int | None = None

    # ── Centre colour ─────────────────────────────────────────────────────────
    center_color_mode: LightColorMode | None = None
    center_color_temp_kelvin: int | None = None
    center_rgb: tuple[int, int, int] | None = None

    # ── Ring ──────────────────────────────────────────────────────────────────
    ring_present: bool = False
    """``True`` when this notification carries ring state (0x33/0x50 echo)."""

    ring_rgb: tuple[int, int, int] | None = None
    ring_effect: str | None = None
    """Named ring effect (e.g. ``"Breathe"``), or ``None`` for solid colour."""


# ═════════════════════════════════════════════════════════════════════════════
# Crypto primitives  (Safe.Companion from com.govee.encryp.ble.Safe)
# ═════════════════════════════════════════════════════════════════════════════

def _rc4_init(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm (KSA).

    Directly mirrors ``Safe.Companion.f()`` from the APK.

    Args:
        key: AES key (16 bytes) reused as the RC4 key.

    Returns:
        Initialised 256-element permutation table S.
    """
    s: list[int] = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm (PRGA) – encrypt or decrypt.

    RC4 is symmetric, so this function is used for both directions.
    Mirrors ``Safe.Companion.g()`` from the APK.

    Args:
        data: Plaintext or ciphertext bytes to process.
        key:  16-byte RC4 key (same as AES key).

    Returns:
        XOR-transformed bytes of the same length as *data*.
    """
    s = _rc4_init(key)
    result = bytearray(len(data))
    i = j = 0
    for idx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        result[idx] = s[(s[i] + s[j]) & 0xFF] ^ data[idx]
    return bytes(result)


def safe_encrypt(data: bytes, key: bytes) -> bytes:
    """Govee hybrid encryption: AES/ECB for 16-byte blocks + RC4 for the tail.

    Implements ``Safe.Companion.d()`` from the APK.  For a 20-byte frame:
      * Bytes  0–15 → AES-128/ECB/NoPadding encrypt.
      * Bytes 16–19 → RC4(key) XOR plaintext[16:20].

    Args:
        data: Plaintext frame to encrypt (typically 20 bytes).
        key:  16-byte AES/RC4 key (commKey or session key).

    Returns:
        Encrypted frame of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    n_blocks, remainder = divmod(len(data), 16)
    result = bytearray()
    for i in range(n_blocks):
        cipher = _AES.new(key, _AES.MODE_ECB)
        result.extend(cipher.encrypt(data[i * 16 : (i + 1) * 16]))
    if remainder:
        result.extend(_rc4_crypt(data[n_blocks * 16 :], key))
    return bytes(result)


def safe_decrypt(data: bytes, key: bytes) -> bytes:
    """Govee hybrid decryption: AES/ECB decrypt + RC4 for the tail.

    Implements ``Safe.Companion.b()`` from the APK.  Inverse of
    :func:`safe_encrypt`.

    Args:
        data: Encrypted frame to decrypt.
        key:  16-byte AES/RC4 key.

    Returns:
        Decrypted frame of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    n_blocks, remainder = divmod(len(data), 16)
    result = bytearray()
    for i in range(n_blocks):
        cipher = _AES.new(key, _AES.MODE_ECB)
        result.extend(cipher.decrypt(data[i * 16 : (i + 1) * 16]))
    if remainder:
        result.extend(_rc4_crypt(data[n_blocks * 16 :], key))
    return bytes(result)


# ═════════════════════════════════════════════════════════════════════════════
# Frame helpers  (BleUtils / Controller4Aes from APK)
# ═════════════════════════════════════════════════════════════════════════════

def _xor_checksum(data: bytes) -> int:
    """XOR of all bytes – ``Controller4Aes.Companion.c()`` from APK.

    Args:
        data: Bytes to checksum (normally the first 19 bytes of a frame).

    Returns:
        Single-byte XOR result (0–255).
    """
    result = 0
    for b in data:
        result ^= b
    return result


def _make_govee_frame(proto_type: int, cmd_type: int, payload: bytes = b"") -> bytes:
    """Build a 20-byte Govee BLE frame (plaintext, before encryption).

    Implements ``BleUtils.generate20Bytes(proType, cmdType, payload)`` from APK.

    Frame layout::

        [0]     proto_type
        [1]     cmd_type
        [2..18] payload (zero-padded to 17 bytes)
        [19]    XOR checksum of bytes [0..18]

    Args:
        proto_type: Protocol type byte (e.g. 0x33 for commands, 0xAA for keepalive).
        cmd_type:   Command type byte (e.g. 0x01 for power, 0x04 for brightness).
        payload:    Command-specific payload bytes (at most 17 bytes; longer
                    payloads are silently truncated to fit).

    Returns:
        20-byte plaintext frame ready to be encrypted and sent.
    """
    frame = bytearray(20)
    frame[0] = proto_type & 0xFF
    frame[1] = cmd_type & 0xFF
    for i, b in enumerate(payload[:17]):
        frame[2 + i] = b
    frame[19] = _xor_checksum(bytes(frame[:19]))
    return bytes(frame)


# ═════════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═════════════════════════════════════════════════════════════════════════════

def snap_kelvin(kelvin: int) -> int:
    """Clamp and round a Kelvin value to the nearest 100 K step in [2200, 6500].

    The H601E firmware only supports steps of 100 K.

    Args:
        kelvin: Desired colour temperature in Kelvin.

    Returns:
        Nearest valid Kelvin value.
    """
    k = max(KELVIN_MIN, min(KELVIN_MAX, kelvin))
    return max(KELVIN_MIN, min(KELVIN_MAX, round(k / 100) * 100))


def brightness_pct_to_ha(pct: int) -> int:
    """Convert Govee brightness percentage (0–100) to HA scale (0–255).

    Args:
        pct: Govee brightness 0–100.

    Returns:
        Home Assistant brightness 0–255.
    """
    return round(max(0, min(100, pct)) / 100 * 255)


def brightness_ha_to_pct(ha_value: int) -> int:
    """Convert HA brightness scale (0–255) to Govee percentage (0–100).

    Args:
        ha_value: Home Assistant brightness 0–255.

    Returns:
        Govee brightness 0–100.
    """
    return round(max(0, min(255, ha_value)) / 255 * 100)


# ═════════════════════════════════════════════════════════════════════════════
# Command frame builders
# ═════════════════════════════════════════════════════════════════════════════

def cmd_keepalive() -> bytes:
    """Build a keep-alive / heartbeat response frame.

    Source: ``ComposeLightHeartController`` (proType=0xAA, cmdType=0x36).
    Plaintext: ``[0xAA, 0x36, 0x00×17, 0x9C]``.

    Returns:
        20-byte plaintext frame.
    """
    return _make_govee_frame(0xAA, 0x36)


def cmd_power(on: bool) -> bytes:
    """Build a power on/off frame.

    Source: ``ControllerSwitch`` (proType=0x33, cmdType=0x01).

    Args:
        on: ``True`` to switch on, ``False`` to switch off.

    Returns:
        20-byte plaintext frame.
    """
    return _make_govee_frame(0x33, 0x01, bytes([0x01 if on else 0x00]))


def cmd_brightness(value: int) -> bytes:
    """Build a global brightness frame.

    Brightness is physically shared between the centre panel and the outer ring.

    Source: ``ControllerBrightness`` (proType=0x33, cmdType=0x04).

    Args:
        value: Brightness as a Govee percentage (0–100).  Values outside this
               range are clamped automatically.

    Returns:
        20-byte plaintext frame.
    """
    v = max(0, min(100, value))
    return _make_govee_frame(0x33, 0x04, bytes([v]))


def cmd_color_rgb(r: int, g: int, b: int) -> bytes:
    """Build an RGB colour frame targeting all 24 segments (panel + ring area).

    Uses the ``SubModeColor`` bitmask ``FF FF FF``.  Note that the outer ring
    requires a separate command (:func:`cmd_ring_diy`); sending only this frame
    does not change the ring colour on the H601E.

    Args:
        r: Red component   (0–255).
        g: Green component (0–255).
        b: Blue component  (0–255).

    Returns:
        20-byte plaintext frame.
    """
    return _make_color_frame(r, g, b, _BITMASK_ALL)


def cmd_color_rgb_panel(r: int, g: int, b: int) -> bytes:
    """Build an RGB colour frame targeting only the centre panel (segments 0–13).

    Uses the ``SubModeColor`` bitmask ``FF 3F 00``.

    Args:
        r: Red component   (0–255).
        g: Green component (0–255).
        b: Blue component  (0–255).

    Returns:
        20-byte plaintext frame.
    """
    return _make_color_frame(r, g, b, _BITMASK_PANEL)


def cmd_color_temp(kelvin: int) -> bytes:
    """Build a colour-temperature frame for the centre panel.

    Source: ``SubModeColor.makeSubModeColor4Kelvin(kelvin)`` + bitmask FF FF FF.

    Payload layout (17 bytes after cmdType=0x05)::

        [0x15, 0x01,
         0xFF, 0xFF, 0xFF,   ← white RGB (ColorUtils.toWhite())
         KH, KL,             ← Kelvin big-endian
         KR, KG, KB,         ← Kelvin RGB approximation (from KELVIN_RGB table)
         0xFF, 0xFF, 0xFF,   ← segment bitmask – all 24 active
         0x00, 0x00, 0x00, 0x00]

    Args:
        kelvin: Desired colour temperature in Kelvin (2 200–6 500).  Will be
                clamped and snapped to the nearest 100 K step.

    Returns:
        20-byte plaintext frame.
    """
    k = snap_kelvin(kelvin)
    kr, kg, kb = KELVIN_RGB[k]
    kh = (k >> 8) & 0xFF
    kl = k & 0xFF
    payload = bytes([
        0x15, 0x01,
        0xFF, 0xFF, 0xFF,       # white (ColorUtils.toWhite())
        kh, kl,                 # Kelvin big-endian
        kr, kg, kb,             # Kelvin RGB approximation
        0xFF, 0xFF, 0xFF,       # all-segments bitmask
        0x00, 0x00, 0x00, 0x00, # padding
    ])
    return _make_govee_frame(0x33, 0x05, payload)


def _cmd_ring_diy_raw(sub_effect_type: int, effect_a_output: bytes) -> bytes:
    """Build a cmdType=0x50 DIY frame from the ``a()`` output of a sub-effect.

    The frame payload layout (bytes after cmdType=0x50):

    ``total_len(LE2) | 01 00 | 00 | sub_len(LE2) | 01 | subEffectType | a()``

    Where ``a() = q() + e()`` per ``KmpAbsSubH60ax``:
      - ``q()``  adds effect-specific parameters (speed, then class fields)
      - ``e()``  adds  ``[colorCount, R, G, B, ...]``

    Args:
        sub_effect_type: The subEffectType byte (e.g. 0x01 for solid colour).
        effect_a_output: Raw bytes from the sub-effect's ``a()`` method.

    Returns:
        20-byte plaintext frame.
    """
    sub_content = bytes([0x01, sub_effect_type]) + effect_a_output
    sub_len = len(sub_content)
    # total_len counts: main_len(2) + main_data(1) + sub_len(2) + sub_content
    total_len = 5 + sub_len
    payload = (
        total_len.to_bytes(2, "little")
        + bytes([0x01, 0x00, 0x00])       # main_len=1 (LE), main_data=[0x00] (None)
        + sub_len.to_bytes(2, "little")
        + sub_content
    )
    return _make_govee_frame(0x33, 0x50, payload)


def _complement_rgb(r: int, g: int, b: int) -> tuple[int, int, int]:
    """Return the complementary colour (hue + 180°) for use in gradient effects.

    Enforces a minimum saturation and value so the complement is always
    visible even if the primary colour is near-white or near-black.
    """
    h, s, v = colorsys.rgb_to_hsv(r / 255.0, g / 255.0, b / 255.0)
    r2, g2, b2 = colorsys.hsv_to_rgb(
        (h + 0.5) % 1.0,
        max(s, 0.8),
        max(v, 0.8),
    )
    return int(r2 * 255), int(g2 * 255), int(b2 * 255)


def cmd_ring_diy(r: int, g: int, b: int) -> bytes:
    """Build an outer-ring solid-colour frame (KmpSubEffectCommon, type=0x01).

    This is the verified-working baseline effect.  The outer ring is NOT
    controlled by the ``SubModeColor`` bitmask; it uses the DIY protocol
    (cmdType=0x50) reverse-engineered from ``KmpH601EFDiyParse`` and
    ``KmpSubEffectCommon``.

    Sub-section payload (a() output for 1 colour):
    ``[speed=0x32, f142885d=0x01, colorCount=0x01, R, G, B]``  → sub_len = 8

    Args:
        r, g, b: RGB colour components (0–255).

    Returns:
        20-byte plaintext frame.
    """
    r, g, b = r & 0xFF, g & 0xFF, b & 0xFF
    # q() = [h()=speed=0x32, f142885d=0x01]  |  e() = [colorCount=1, R, G, B]
    return _cmd_ring_diy_raw(0x01, bytes([0x32, 0x01, 0x01, r, g, b]))


def cmd_ring_breathe(r: int, g: int, b: int, speed: int = 0x32) -> bytes:
    """Build an outer-ring breathing/pulse frame (KmpSubEffectBreathe, type=0x0B).

    Sub-section payload (a() output):
    ``[speed, f142879d=0x04, f142880e=0x01, colorCount=0x01, R, G, B]``

    The ``f142879d`` field controls pulse intensity (0x04 = direction 0 default;
    0xFF = other directions).  ``f142880e`` is the sub-type marker (always 0x01
    for the default constructor).

    Args:
        r, g, b: Base colour (0–255).
        speed:   Animation speed (0–255, default 50).

    Returns:
        20-byte plaintext frame.
    """
    r, g, b = r & 0xFF, g & 0xFF, b & 0xFF
    return _cmd_ring_diy_raw(0x0B, bytes([speed & 0xFF, 0x04, 0x01, 0x01, r, g, b]))


def cmd_ring_strobe(r: int, g: int, b: int, speed: int = 0x32) -> bytes:
    """Build an outer-ring strobe/flash frame (KmpSubEffectDuiJi, type=0x0A).

    Sub-section payload (a() output):
    ``[speed, f142887d=0x01(direction), f142888e=0x01(type), colorCount=0x01, R, G, B]``

    Args:
        r, g, b: Strobe colour (0–255).
        speed:   Flash speed (0–255, default 50).

    Returns:
        20-byte plaintext frame.
    """
    r, g, b = r & 0xFF, g & 0xFF, b & 0xFF
    return _cmd_ring_diy_raw(0x0A, bytes([speed & 0xFF, 0x01, 0x01, 0x01, r, g, b]))


def cmd_ring_chase(r: int, g: int, b: int, speed: int = 0x32) -> bytes:
    """Build an outer-ring streamer/chase frame (KmpSubEffectStreamer, type=0x07).

    Sub-section payload (a() output):
    ``[speed, f142896e=0x01(mode), f142895d=0x03(direction), colorCount=0x01, R, G, B]``

    Args:
        r, g, b: Streak colour (0–255).
        speed:   Chase speed (0–255, default 50).

    Returns:
        20-byte plaintext frame.
    """
    r, g, b = r & 0xFF, g & 0xFF, b & 0xFF
    return _cmd_ring_diy_raw(0x07, bytes([speed & 0xFF, 0x01, 0x03, 0x01, r, g, b]))


def cmd_ring_gradient(r: int, g: int, b: int, speed: int = 0x32) -> bytes:
    """Build a 2-colour ring gradient frame (KmpSubEffectSpeedColor, type=0x06).

    The second colour is automatically chosen as the complementary hue
    (+ 180°) of the primary colour, creating a smooth opposing gradient.
    Two colours is the maximum that fits within a 20-byte BLE frame.

    Sub-section payload (a() output):
    ``[speed, colorCount=0x02, R₁, G₁, B₁, R₂, G₂, B₂]``  → sub_len = 10

    Args:
        r, g, b: Primary gradient colour (0–255).
        speed:   Animation speed (0–255, default 50).

    Returns:
        20-byte plaintext frame.
    """
    r, g, b = r & 0xFF, g & 0xFF, b & 0xFF
    r2, g2, b2 = _complement_rgb(r, g, b)
    # q() = [h()=speed]  |  e() = [colorCount=2, R₁,G₁,B₁, R₂,G₂,B₂]
    return _cmd_ring_diy_raw(0x06, bytes([speed & 0xFF, 0x02, r, g, b, r2, g2, b2]))


def _make_color_frame(r: int, g: int, b: int, bitmask: tuple[int, int, int]) -> bytes:
    """Internal helper: build a SubModeColor RGB frame with the given segment bitmask.

    Args:
        r, g, b:  RGB colour components (0–255).
        bitmask:  Three-byte segment bitmask (e.g. ``_BITMASK_ALL`` or
                  ``_BITMASK_PANEL``).

    Returns:
        20-byte plaintext frame.
    """
    m0, m1, m2 = bitmask
    payload = bytes([
        0x15, 0x01,
        r & 0xFF, g & 0xFF, b & 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00,  # no colour-temp (f113427f == 0)
        m0, m1, m2,                     # segment bitmask
        0x00, 0x00, 0x00, 0x00,         # padding
    ])
    return _make_govee_frame(0x33, 0x05, payload)


# ═════════════════════════════════════════════════════════════════════════════
# Handshake frame builders  (Controller4Aes from com.govee.encryp.ble)
# ═════════════════════════════════════════════════════════════════════════════

def make_hs1_frame() -> bytes:
    """Build the HS1 (session-key request) frame.

    Implements ``Controller4Aes.e()`` from the APK.

    Plaintext: ``[0xE7, 0x01, <17 random bytes>, xor_checksum]``
    Returned:  ``safe_encrypt(plaintext, COMM_KEY)``

    Returns:
        20-byte encrypted HS1 frame.
    """
    plain = bytearray(20)
    plain[0] = 0xE7
    plain[1] = 0x01
    plain[2:19] = os.urandom(17)
    plain[19] = _xor_checksum(bytes(plain[:19]))
    _LOGGER.debug("HS1 plaintext: %s", bytes(plain).hex())
    encrypted = safe_encrypt(bytes(plain), COMM_KEY)
    _LOGGER.debug("HS1 encrypted: %s", encrypted.hex())
    return encrypted


def parse_hs1_response(data: bytes) -> bytes | None:
    """Parse the device's HS1 response and extract the 16-byte session key.

    Implements ``Controller4Aes.g()`` from the APK.

    Expected decrypted layout: ``[0xE7, 0x01, SK[0..15], xor_checksum]``

    Args:
        data: Raw 20-byte notification received from the device.

    Returns:
        16-byte session key, or ``None`` on parsing failure.
    """
    if len(data) < 20:
        _LOGGER.error("HS1 response too short: %d bytes (expected 20)", len(data))
        return None

    decrypted = safe_decrypt(data[:20], COMM_KEY)
    _LOGGER.debug("HS1 response decrypted: %s", decrypted.hex())

    if decrypted[0] != 0xE7 or decrypted[1] != 0x01:
        _LOGGER.warning(
            "Unexpected HS1 header: 0x%02x 0x%02x (expected 0xe7 0x01)",
            decrypted[0], decrypted[1],
        )
        return None

    expected_xor = _xor_checksum(decrypted[:19])
    if decrypted[19] != expected_xor:
        _LOGGER.warning(
            "HS1 checksum mismatch (got 0x%02x, expected 0x%02x) – continuing anyway",
            decrypted[19], expected_xor,
        )

    session_key = bytes(decrypted[2:18])
    _LOGGER.debug("Session key extracted (16 bytes)")
    return session_key


def make_hs2_frame() -> bytes:
    """Build the HS2 (session confirmation) frame.

    Implements ``Controller4Aes.f()`` from the APK.

    Plaintext: ``[0xE7, 0x02, <17 random bytes>, xor_checksum]``
    Returned:  ``safe_encrypt(plaintext, COMM_KEY)``

    Returns:
        20-byte encrypted HS2 frame.
    """
    plain = bytearray(20)
    plain[0] = 0xE7
    plain[1] = 0x02
    plain[2:19] = os.urandom(17)
    plain[19] = _xor_checksum(bytes(plain[:19]))
    _LOGGER.debug("HS2 plaintext: %s", bytes(plain).hex())
    return safe_encrypt(bytes(plain), COMM_KEY)


def encrypt_command(session_key: bytes, plain_frame: bytes) -> bytes:
    """Encrypt a plaintext command frame with the active session key.

    Implements ``AESEncryptionStrategy.encrypt()`` (= ``Safe.d(plain, sk)``).

    Args:
        session_key: 16-byte session key obtained during handshake.
        plain_frame: 20-byte plaintext frame built by one of the ``cmd_*``
                     functions.

    Returns:
        20-byte encrypted frame ready to be written to the GATT characteristic.

    Raises:
        ValueError: If *plain_frame* is not exactly 20 bytes.
    """
    if len(plain_frame) != 20:
        raise ValueError(f"Frame must be 20 bytes, got {len(plain_frame)}")
    return safe_encrypt(plain_frame, session_key)


# ═════════════════════════════════════════════════════════════════════════════
# Notification parser
# ═════════════════════════════════════════════════════════════════════════════

class NotificationType(str, Enum):
    """Category of an inbound BLE notification from the device."""
    HS1_RESPONSE = "hs1_response"
    HS2_ECHO = "hs2_echo"
    HEARTBEAT = "heartbeat"
    STATE_UPDATE = "state_update"
    UNKNOWN = "unknown"


@dataclass
class ParsedNotification:
    """Decoded BLE notification.

    Attributes:
        type:         Category of the notification.
        raw:          The original raw bytes.
        plain:        Decrypted plaintext (if a session key was available).
        session_key:  Extracted session key (only set for HS1_RESPONSE).
        state_update: Parsed state delta (set for HEARTBEAT and STATE_UPDATE).
    """
    type: NotificationType
    raw: bytes
    plain: bytes | None = None
    session_key: bytes | None = None
    state_update: StateUpdate | None = None


# ── Ring sub-effect type → effect name mapping ────────────────────────────────
# Values must match the RING_EFFECT_* constants in const.py.

_RING_SUBEFFECT_NAMES: dict[int, str] = {
    0x01: "Solid",
    0x06: "Gradient",
    0x07: "Chase",
    0x0A: "Strobe",
    0x0B: "Breathe",
}


# ── Notification payload parsers ──────────────────────────────────────────────

def _parse_heartbeat(plain: bytes) -> StateUpdate:
    """Parse a decrypted 0xAA/0x36 keepalive echo.

    The H601E sends proactive keepalive notifications every few seconds with
    ``plain[2]=0, plain[3]=0`` regardless of physical power state.  Unlike the
    H604a (where those bytes encode ``center_on`` / ``ring_on`` per
    ``ComposeLightHeartController.parseValidBytes()``), the H601E always zeroes
    them out, so extracting power state here would reset HA state to "off"
    every 2–3 seconds.

    Power state is therefore tracked exclusively via optimistic updates (set at
    command send time) and ``RestoreEntity`` persistence across restarts.

    Args:
        plain: 20-byte decrypted heartbeat frame.

    Returns:
        Empty :class:`StateUpdate` (no fields set).
    """
    return StateUpdate()


def _parse_0x33_0x01(plain: bytes) -> StateUpdate:
    """Parse a 0x33/0x01 power-command echo.

    Power state is intentionally NOT extracted here.  Some devices echo the
    state *before* processing the command (i.e. the lamp echoes "off" in
    response to an ON command), which would override the optimistic update set
    at send time and produce a spurious "on → off" logbook entry.

    Power state is tracked via:
    * Optimistic updates in ``async_turn_on`` / ``async_turn_off``.
    * The keepalive echo (0xAA/0x36) which is authoritative after the 2-second
      command-suppression window expires.
    """
    return StateUpdate()


def _parse_0x33_0x04(plain: bytes) -> StateUpdate:
    """Extract brightness from a 0x33/0x04 echo.

    ``plain[2]``: Govee brightness 0–100.
    """
    if len(plain) < 3:
        return StateUpdate()
    return StateUpdate(brightness_pct=max(0, min(100, plain[2])))


def _parse_0x33_0x05(plain: bytes) -> StateUpdate:
    """Extract colour mode from a 0x33/0x05 echo.

    Payload layout (bytes[2..] of ``plain``):
      ``[0x15, 0x01, R, G, B, KH, KL, KR, KG, KB, M0, M1, M2, 0, 0, 0, 0]``

    Colour-temperature mode: ``KH != 0 or KL != 0``
    RGB mode: ``KH == 0 and KL == 0``
    """
    if len(plain) < 12:
        return StateUpdate()
    r, g, b = plain[4], plain[5], plain[6]
    kh, kl  = plain[7], plain[8]
    if kh != 0 or kl != 0:
        return StateUpdate(
            center_color_mode=LightColorMode.COLOR_TEMP,
            center_color_temp_kelvin=snap_kelvin((kh << 8) | kl),
        )
    return StateUpdate(
        center_color_mode=LightColorMode.RGB,
        center_rgb=(r, g, b),
    )


def _parse_0x33_0x50(plain: bytes) -> StateUpdate:
    """Extract ring state from a 0x33/0x50 DIY ring echo.

    Frame layout after ``plain[1]=0x50``:
      ``plain[9]``  = has_flag (0x01)
      ``plain[10]`` = subEffectType
      ``plain[11..]`` = ``a()`` output (speed + params + colorCount + RGB)

    Primary colour byte offset within ``plain`` depends on sub-effect type:
      - 0x01 Solid:    ``a()`` = ``[speed, flag, colorCount, R, G, B]``  → R at 14
      - 0x06 Gradient: ``a()`` = ``[speed, colorCount, R, G, B, …]``    → R at 13
      - 0x07/0x0A/0x0B:``a()`` = ``[speed, p1, p2, colorCount, R, G, B]``→ R at 15
    """
    if len(plain) < 11:
        return StateUpdate(ring_present=True)

    sub_effect_type = plain[10]
    effect_name = _RING_SUBEFFECT_NAMES.get(sub_effect_type)

    # Determine RGB byte offset and extract primary colour
    if sub_effect_type == 0x01:
        r_idx = 14
    elif sub_effect_type == 0x06:
        r_idx = 13
    else:
        r_idx = 15

    ring_rgb: tuple[int, int, int] | None = None
    if len(plain) >= r_idx + 3:
        ring_rgb = (plain[r_idx], plain[r_idx + 1], plain[r_idx + 2])

    # ring_effect=None means "solid / no effect active" in GoveeDeviceState
    ring_effect = None if (effect_name is None or effect_name == "Solid") else effect_name

    return StateUpdate(
        ring_present=True,
        ring_rgb=ring_rgb,
        ring_effect=ring_effect,
    )


def parse_notification(
    data: bytes,
    session_key: bytes | None = None,
) -> ParsedNotification:
    """Parse an inbound BLE notification.

    Determines the notification type by inspecting the decrypted content.
    During the handshake no session key exists yet; post-handshake the
    session key is used to decrypt state-update frames.

    Args:
        data:        Raw notification bytes (20 bytes expected).
        session_key: Active session key, or ``None`` during handshake.

    Returns:
        :class:`ParsedNotification` with type and decrypted content.
    """
    if len(data) < 20:
        _LOGGER.debug("Notification too short (%d bytes), skipping", len(data))
        return ParsedNotification(type=NotificationType.UNKNOWN, raw=data)

    # Try to decrypt with commKey first (handshake messages are always
    # encrypted with commKey, not the session key).
    # pycryptodome raises ValueError on AES failures; our safe_decrypt also
    # raises ValueError for bad key length.  Any other exception is unexpected.
    try:
        plain_comm = safe_decrypt(data[:20], COMM_KEY)
    except ValueError:
        plain_comm = None

    if plain_comm and plain_comm[0] == 0xE7 and plain_comm[1] == 0x01:
        sk = parse_hs1_response(data)
        return ParsedNotification(
            type=NotificationType.HS1_RESPONSE,
            raw=data,
            plain=plain_comm,
            session_key=sk,
        )

    if plain_comm and plain_comm[0] == 0xE7 and plain_comm[1] == 0x02:
        return ParsedNotification(
            type=NotificationType.HS2_ECHO,
            raw=data,
            plain=plain_comm,
        )

    # Post-handshake: try session key decryption
    if session_key is not None:
        try:
            plain_sk = safe_decrypt(data[:20], session_key)
        except ValueError:
            plain_sk = None

        if plain_sk:
            if plain_sk[0] == 0xAA and plain_sk[1] == 0x36:
                return ParsedNotification(
                    type=NotificationType.HEARTBEAT,
                    raw=data,
                    plain=plain_sk,
                    state_update=_parse_heartbeat(plain_sk),
                )

            if plain_sk[0] == 0x33:
                cmd = plain_sk[1]
                if cmd == 0x01:
                    su: StateUpdate | None = _parse_0x33_0x01(plain_sk)
                elif cmd == 0x04:
                    su = _parse_0x33_0x04(plain_sk)
                elif cmd == 0x05:
                    su = _parse_0x33_0x05(plain_sk)
                elif cmd == 0x50:
                    su = _parse_0x33_0x50(plain_sk)
                else:
                    su = None
                return ParsedNotification(
                    type=NotificationType.STATE_UPDATE,
                    raw=data,
                    plain=plain_sk,
                    state_update=su,
                )

            return ParsedNotification(
                type=NotificationType.STATE_UPDATE,
                raw=data,
                plain=plain_sk,
            )

    _LOGGER.debug("Unknown notification (no key matched): %s", data.hex())
    return ParsedNotification(type=NotificationType.UNKNOWN, raw=data)
