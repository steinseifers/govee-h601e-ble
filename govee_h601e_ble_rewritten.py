#!/usr/bin/env python3
"""
Govee H601E BLE Controller (macOS / bleak)

Ziele dieser Fassung:
- nur die bekannte Notify-Characteristic 2b10 abonnieren
- Handshake als write-with-response senden
- saubere, deterministische Logs
- mehrere Handshake-Formate testbar machen, ohne den BLE-Ablauf zu vermischen
- rohe und entschlüsselte Antworten vollständig loggen

Bekannte Daten:
  Root-Key  : MakingLifeSmarte
  Write UUID: 00010203-0405-0607-0809-0a0b0c0d2b11
  Notify UUID:00010203-0405-0607-0809-0a0b0c0d2b10

Installation:
  pip install bleak pycryptodome

Beispiele:
  python3 govee_h601e_ble_rewritten.py --scan
  python3 govee_h601e_ble_rewritten.py --mac 55F072C6-D041-9EC0-84A3-A7EB3F190676 --handshake-only --debug
  python3 govee_h601e_ble_rewritten.py --mac 55F072C6-D041-9EC0-84A3-A7EB3F190676 --on --debug
  python3 govee_h601e_ble_rewritten.py --mac 55F072C6-D041-9EC0-84A3-A7EB3F190676 --hs1-hex 001122... --handshake-only
"""

from __future__ import annotations

import argparse
import asyncio
import binascii
import logging
import os
import sys
from dataclasses import dataclass
from typing import Callable, Optional

AES_BACKEND = None

try:
    from Crypto.Cipher import AES as _AES
    AES_BACKEND = "pycryptodome"
except ImportError:
    try:
        from Cryptodome.Cipher import AES as _AES
        AES_BACKEND = "pycryptodomex"
    except ImportError:
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            AES_BACKEND = "cryptography"
        except ImportError:
            print("Fehler: Keine AES-Bibliothek gefunden. Bitte eines davon installieren:")
            print("  python3 -m pip install pycryptodome")
            print("oder")
            print("  python3 -m pip install pycryptodomex")
            print("oder")
            print("  python3 -m pip install cryptography")
            sys.exit(1)

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.characteristic import BleakGATTCharacteristic
except ImportError:
    print("Fehler: bleak nicht installiert. Bitte ausführen:")
    print("  python3 -m pip install bleak")
    sys.exit(1)


DEFAULT_ADDRESS = "55F072C6-D041-9EC0-84A3-A7EB3F190676"
WRITE_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
ROOT_KEY = b"MakingLifeSmarte"
KNOWN_HS1 = bytes.fromhex("34a4d533a9ed45e30872c7c9d2adfdfd96a45026")
KNOWN_HS1_RESP = bytes.fromhex("99a81daa3318dba0af8842a8a422a4e59ecd50a9")
KNOWN_HS2 = bytes.fromhex("77467ab8792c62f947abb9572fb3a057b5006967")
KNOWN_HS2_RESP = bytes.fromhex("77467ab8792c62f947abb9572fb3a057b5006967")

CMD_POWER = 0x01
CMD_BRIGHTNESS = 0x04
CMD_COLOR = 0x05

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("govee_h601e")


def xor_checksum(data: bytes) -> int:
    value = 0
    for b in data:
        value ^= b
    return value


def chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError(f"AES ECB requires multiples of 16 bytes, got {len(data)}")
    if AES_BACKEND in ("pycryptodome", "pycryptodomex"):
        return _AES.new(key, _AES.MODE_ECB).encrypt(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError(f"AES ECB requires multiples of 16 bytes, got {len(data)}")
    if AES_BACKEND in ("pycryptodome", "pycryptodomex"):
        return _AES.new(key, _AES.MODE_ECB).decrypt(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def hex_bytes(data: bytes) -> str:
    return data.hex()


@dataclass
class HandshakeResult:
    raw_response: bytes
    decrypted_response: bytes
    session_key: Optional[bytes]
    explanation: str


class ProtocolError(RuntimeError):
    pass


class GoveeProtocol:
    """Best-effort-Protokoll-Implementierung mit klaren Debug-Pfaden.

    Da das exakte Handshake-Format der H601E hier noch nicht vollständig bewiesen ist,
    unterstützen wir zwei saubere Kandidaten:

    - hs1_v1_16:  1 AES-Block = [E7 01 + 13 random + XOR]
    - hs1_v2_32:  2 AES-Blöcke = [E7 01 + 17 random + XOR], mit Nullpadding auf 32 Byte

    Der BLE-Ablauf bleibt dabei identisch. Nur das Handshake-Format wechselt.
    """

    def __init__(self, root_key: bytes):
        if len(root_key) != 16:
            raise ValueError("Root key must be 16 bytes")
        self.root_key = root_key

    def make_hs1_v1_16(self) -> bytes:
        random_part = os.urandom(13)
        plain = bytes([0xE7, 0x01]) + random_part
        plain += bytes([xor_checksum(plain)])
        if len(plain) != 16:
            raise AssertionError(f"HS1 v1 must be 16 bytes, got {len(plain)}")
        log.debug("HS1 v1 plaintext : %s", hex_bytes(plain))
        encrypted = aes_ecb_encrypt(self.root_key, plain)
        log.debug("HS1 v1 encrypted : %s", hex_bytes(encrypted))
        return encrypted

    def make_hs2_v1_16(self) -> bytes:
        random_part = os.urandom(13)
        plain = bytes([0xE7, 0x02]) + random_part
        plain += bytes([xor_checksum(plain)])
        if len(plain) != 16:
            raise AssertionError(f"HS2 v1 must be 16 bytes, got {len(plain)}")
        log.debug("HS2 v1 plaintext : %s", hex_bytes(plain))
        encrypted = aes_ecb_encrypt(self.root_key, plain)
        log.debug("HS2 v1 encrypted : %s", hex_bytes(encrypted))
        return encrypted

    def make_hs1_v2_32(self) -> bytes:
        plain = bytes([0xE7, 0x01]) + os.urandom(17)
        plain += bytes([xor_checksum(plain)])
        padded = plain.ljust(32, b"\x00")
        log.debug("HS1 v2 plaintext : %s", hex_bytes(padded))
        encrypted = aes_ecb_encrypt(self.root_key, padded)
        log.debug("HS1 v2 encrypted : %s", hex_bytes(encrypted))
        return encrypted

    def make_hs2_v2_32(self) -> bytes:
        plain = bytes([0xE7, 0x02]) + os.urandom(17)
        plain += bytes([xor_checksum(plain)])
        padded = plain.ljust(32, b"\x00")
        log.debug("HS2 v2 plaintext : %s", hex_bytes(padded))
        encrypted = aes_ecb_encrypt(self.root_key, padded)
        log.debug("HS2 v2 encrypted : %s", hex_bytes(encrypted))
        return encrypted

    def make_command_packet(self, session_key: bytes, payload: bytes) -> bytes:
        if len(session_key) != 16:
            raise ProtocolError(f"Session key must be 16 bytes, got {len(session_key)}")

        if len(payload) > 15:
            raise ProtocolError(f"Command payload too long for 1 block: {len(payload)}")

        plain = payload.ljust(15, b"\x00")
        plain += bytes([xor_checksum(plain)])
        log.debug("CMD plaintext    : %s", hex_bytes(plain))
        encrypted = aes_ecb_encrypt(session_key, plain)
        log.debug("CMD encrypted    : %s", hex_bytes(encrypted))
        return encrypted

    def inspect_response(self, raw: bytes) -> HandshakeResult:
        if len(raw) % 16 != 0:
            return HandshakeResult(
                raw_response=raw,
                decrypted_response=b"",
                session_key=None,
                explanation=f"Antwortlänge {len(raw)} ist kein AES-Block-Vielfaches",
            )

        decrypted = aes_ecb_decrypt(self.root_key, raw)
        log.debug("HS response raw  : %s", hex_bytes(raw))
        log.debug("HS response dec  : %s", hex_bytes(decrypted))

        blocks = chunks(decrypted, 16)

        # Heuristik A: erster Block beginnt mit E7 01 / E7 02, Rest enthält 14 Bytes Session-Material.
        # Das ist noch kein echter AES-Key -> nur diagnostisch protokollieren.
        if blocks and len(blocks[0]) == 16 and blocks[0][:2] in (b"\xE7\x01", b"\xE7\x02"):
            trailing = blocks[0][2:]
            if len(blocks) >= 2:
                candidate = (trailing + blocks[1])[:16]
                return HandshakeResult(
                    raw_response=raw,
                    decrypted_response=decrypted,
                    session_key=candidate,
                    explanation="Session-Key heuristisch aus Block0[2:] + Block1 zusammengesetzt",
                )
            return HandshakeResult(
                raw_response=raw,
                decrypted_response=decrypted,
                session_key=None,
                explanation="Antwort beginnt korrekt mit E7 xx, enthält aber nur 1 Block -> Session-Key unklar",
            )

        # Heuristik B: erster entschlüsselter Block ist direkt ein 16-Byte-Key ohne Header.
        if len(decrypted) == 16:
            return HandshakeResult(
                raw_response=raw,
                decrypted_response=decrypted,
                session_key=decrypted,
                explanation="Session-Key heuristisch als kompletter 16-Byte-Block interpretiert",
            )

        return HandshakeResult(
            raw_response=raw,
            decrypted_response=decrypted,
            session_key=None,
            explanation="Antwort entschlüsselt, aber keine bekannte Session-Key-Struktur erkannt",
        )


class GoveeH601E:
    def __init__(self, address: str, handshake_variant: str, hs1_override: Optional[bytes] = None):
        self.address = address
        self.protocol = GoveeProtocol(ROOT_KEY)
        self.handshake_variant = handshake_variant
        self.hs1_override = hs1_override
        self.session_key: Optional[bytes] = None
        self._notify_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def _on_notify(self, characteristic: BleakGATTCharacteristic, data: bytearray) -> None:
        packet = bytes(data)
        log.debug("Notify from %s: %s", characteristic.uuid, hex_bytes(packet))
        self._notify_queue.put_nowait(packet)

    async def _drain_queue(self) -> None:
        while not self._notify_queue.empty():
            self._notify_queue.get_nowait()

    async def _wait_for_notification(self, timeout: float) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._notify_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def _build_hs1(self) -> tuple[bytes, bool]:
        if self.hs1_override is not None:
            log.info("Verwende manuell vorgegebenes HS1")
            return self.hs1_override, False
        if self.handshake_variant == "known":
            return KNOWN_HS1, False
        if self.handshake_variant == "v1":
            return self.protocol.make_hs1_v1_16(), True
        if self.handshake_variant == "v2":
            return self.protocol.make_hs1_v2_32(), True
        raise ValueError(f"Unknown handshake variant: {self.handshake_variant}")

    def _build_hs2(self) -> tuple[bytes, bool]:
        if self.handshake_variant == "known":
            return KNOWN_HS2, False
        if self.handshake_variant == "v1":
            return self.protocol.make_hs2_v1_16(), True
        if self.handshake_variant == "v2":
            return self.protocol.make_hs2_v2_32(), True
        raise ValueError(f"Unknown handshake variant: {self.handshake_variant}")

    async def connect_and_handshake(self, client: BleakClient) -> bool:
        log.info("Abonniere Notify-Characteristic %s", NOTIFY_UUID)
        await client.start_notify(NOTIFY_UUID, self._on_notify)
        await asyncio.sleep(0.5)
        await self._drain_queue()

        hs1, hs1_with_response = self._build_hs1()
        log.info("Sende HS1 (%d Byte) mit write-%s", len(hs1), "with-response" if hs1_with_response else "without-response")
        log.debug("HS1 payload      : %s", hex_bytes(hs1))
        if len(hs1) >= 16:
            try:
                log.debug("HS1 dec(first16) : %s", hex_bytes(aes_ecb_decrypt(ROOT_KEY, hs1[:16])))
            except Exception:
                pass
        await client.write_gatt_char(WRITE_UUID, hs1, response=hs1_with_response)

        response = await self._wait_for_notification(timeout=5.0)
        if response is None:
            log.error("Keine Notification auf HS1 erhalten")
            return False

        log.info("HS1-Notification : %s", hex_bytes(response))
        if self.handshake_variant == "known":
            log.info("Erwartete HS1-Antwort: %s", KNOWN_HS1_RESP.hex())
            if response != KNOWN_HS1_RESP:
                log.warning("HS1-Antwort weicht vom Logger ab")
            hs2, hs2_with_response = self._build_hs2()
            log.info("Sende HS2 (%d Byte) mit write-%s", len(hs2), "with-response" if hs2_with_response else "without-response")
            log.debug("HS2 payload      : %s", hex_bytes(hs2))
            await self._drain_queue()
            await client.write_gatt_char(WRITE_UUID, hs2, response=hs2_with_response)
            echo = await self._wait_for_notification(timeout=2.0)
            if echo is not None:
                log.info("HS2-Notification : %s", hex_bytes(echo))
                log.info("Erwartete HS2-Antwort: %s", KNOWN_HS2_RESP.hex())
            self.session_key = None
            return True

        result = self.protocol.inspect_response(response)
        log.info("Handshake-Antwort: %s", result.explanation)
        if result.decrypted_response:
            log.info("Entschlüsselte Antwort: %s", hex_bytes(result.decrypted_response))

        if result.session_key is None:
            log.error("Kein belastbarer Session-Key ableitbar")
            return False

        self.session_key = result.session_key
        log.info("Session-Key (heuristisch): %s", hex_bytes(self.session_key))

        hs2, hs2_with_response = self._build_hs2()
        log.info("Sende HS2 (%d Byte) mit write-%s", len(hs2), "with-response" if hs2_with_response else "without-response")
        await client.write_gatt_char(WRITE_UUID, hs2, response=hs2_with_response)
        await asyncio.sleep(0.4)
        return True

    async def send_encrypted_payload(self, client: BleakClient, payload: bytes) -> Optional[bytes]:
        if self.session_key is None:
            raise ProtocolError("Kein Session-Key vorhanden")
        packet = self.protocol.make_command_packet(self.session_key, payload)
        await self._drain_queue()
        await client.write_gatt_char(WRITE_UUID, packet, response=False)
        await asyncio.sleep(0.15)
        return await self._wait_for_notification(timeout=1.0)

    async def power(self, client: BleakClient, on: bool) -> None:
        payload = bytes([0x33, CMD_POWER, 0x01 if on else 0x00])
        response = await self.send_encrypted_payload(client, payload)
        log.info("Power %s gesendet%s", "ON" if on else "OFF", f", Antwort: {hex_bytes(response)}" if response else "")

    async def brightness(self, client: BleakClient, value: int) -> None:
        value = max(0, min(100, value))
        payload = bytes([0x33, CMD_BRIGHTNESS, value])
        response = await self.send_encrypted_payload(client, payload)
        log.info("Brightness %d%% gesendet%s", value, f", Antwort: {hex_bytes(response)}" if response else "")

    async def color(self, client: BleakClient, r: int, g: int, b: int) -> None:
        r = max(0, min(255, r))
        g = max(0, min(255, g))
        b = max(0, min(255, b))
        payload = bytes([0x33, CMD_COLOR, 0x02, r, g, b, 0x00, 0x00, 0x00, 0xFF, 0xFF])
        response = await self.send_encrypted_payload(client, payload)
        log.info("Color %d,%d,%d gesendet%s", r, g, b, f", Antwort: {hex_bytes(response)}" if response else "")

    async def raw_command(self, client: BleakClient, packet: bytes, label: str = "raw") -> None:
        await self._drain_queue()
        log.info("Sende %s (%d Byte) als Raw-Write", label, len(packet))
        log.debug("%s payload      : %s", label, hex_bytes(packet))
        if len(packet) >= 16:
            try:
                log.debug("%s dec(first16) : %s", label, hex_bytes(aes_ecb_decrypt(ROOT_KEY, packet[:16])))
            except Exception:
                pass
        await client.write_gatt_char(WRITE_UUID, packet, response=False)
        response = await self._wait_for_notification(timeout=1.5)
        log.info("%s-Notification : %s", label, hex_bytes(response) if response else "<keine>")
        if response and len(response) >= 16:
            try:
                log.info("%s dec(first16) : %s", label, hex_bytes(aes_ecb_decrypt(ROOT_KEY, response[:16])))
            except Exception:
                pass

    async def run(self, actions: list[Callable[[BleakClient], asyncio.Future]], handshake_only: bool) -> int:
        client = BleakClient(self.address, timeout=20.0, use_cached_services=False)
        try:
            log.info("Verbinde zu %s", self.address)
            await client.connect()
            if not client.is_connected:
                log.error("Verbindung fehlgeschlagen")
                return 2

            services = getattr(client, "services", None)
            if services is None:
                log.error("Bleak hat keine aufgelösten Services bereitgestellt")
                return 3
            notify_char = services.get_characteristic(NOTIFY_UUID)
            write_char = services.get_characteristic(WRITE_UUID)
            if notify_char is None or write_char is None:
                log.error("Erwartete Characteristics nicht gefunden")
                return 3

            log.info("Write-Char gefunden : %s (props=%s)", write_char.uuid, ",".join(write_char.properties))
            log.info("Notify-Char gefunden: %s (props=%s)", notify_char.uuid, ",".join(notify_char.properties))

            ok = await self.connect_and_handshake(client)
            if not ok:
                return 4

            if handshake_only:
                log.info("Nur Handshake ausgeführt")
                return 0

            for action in actions:
                await action(client)
                await asyncio.sleep(0.3)
            return 0
        except Exception as exc:
            log.exception("Fehler während BLE-Session: %s", exc)
            return 1
        finally:
            try:
                if client.is_connected:
                    await client.disconnect()
            finally:
                log.info("Verbindung getrennt")


async def scan_devices() -> None:
    log.info("Scanne 10 Sekunden nach BLE-Geräten ...")
    devices = await BleakScanner.discover(timeout=10.0)
    for d in devices:
        name = d.name or "(kein Name)"
        print(f"{d.address}  {name}")


def parse_hex_argument(value: str) -> bytes:
    cleaned = value.replace(" ", "").replace(":", "")
    try:
        data = binascii.unhexlify(cleaned)
    except binascii.Error as exc:
        raise argparse.ArgumentTypeError(f"Ungültiger Hex-String: {exc}") from exc
    if not data:
        raise argparse.ArgumentTypeError("Hex-String darf nicht leer sein")
    return data


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Govee H601E BLE Controller")
    parser.add_argument("--mac", default=DEFAULT_ADDRESS, help="CoreBluetooth UUID / MAC der Lampe")
    parser.add_argument("--scan", action="store_true", help="BLE-Geräte scannen")
    parser.add_argument("--debug", action="store_true", help="Debug-Logs aktivieren")
    parser.add_argument("--handshake-variant", choices=["known", "v1", "v2"], default="known", help="Zu testendes Handshake-Format")
    parser.add_argument("--hs1-hex", type=parse_hex_argument, help="Verschlüsseltes HS1 manuell vorgeben")
    parser.add_argument("--handshake-only", action="store_true", help="Nur verbinden und Handshake testen")
    parser.add_argument("--on", action="store_true", help="Lampe einschalten")
    parser.add_argument("--off", action="store_true", help="Lampe ausschalten")
    parser.add_argument("--brightness", type=int, help="Helligkeit 0-100")
    parser.add_argument("--color", type=int, nargs=3, metavar=("R", "G", "B"), help="RGB-Farbe setzen")
    parser.add_argument("--raw-cmd-hex", action="append", type=parse_hex_argument, help="Rohes verschlüsseltes Kommando nach Handshake senden (mehrfach möglich)")
    return parser


def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("bleak").setLevel(logging.DEBUG)
    else:
        logging.getLogger("bleak").setLevel(logging.WARNING)

    if args.scan:
        asyncio.run(scan_devices())
        return 0

    controller = GoveeH601E(
        address=args.mac,
        handshake_variant=args.handshake_variant,
        hs1_override=args.hs1_hex,
    )

    actions: list[Callable[[BleakClient], asyncio.Future]] = []
    if args.on:
        actions.append(lambda client: controller.power(client, True))
    if args.off:
        actions.append(lambda client: controller.power(client, False))
    if args.brightness is not None:
        actions.append(lambda client, value=args.brightness: controller.brightness(client, value))
    if args.color is not None:
        r, g, b = args.color
        actions.append(lambda client, r=r, g=g, b=b: controller.color(client, r, g, b))
    if args.raw_cmd_hex:
        for idx, packet in enumerate(args.raw_cmd_hex, start=1):
            actions.append(lambda client, packet=packet, idx=idx: controller.raw_command(client, packet, f"raw-cmd-{idx}"))

    if not actions and not args.handshake_only:
        parser.error("Mindestens eine Aktion oder --handshake-only angeben")

    return asyncio.run(controller.run(actions, handshake_only=args.handshake_only))


if __name__ == "__main__":
    raise SystemExit(main())
