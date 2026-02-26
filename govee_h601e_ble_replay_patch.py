#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Optional

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
KNOWN_HS2 = bytes.fromhex("77467ab8792c62f947abb9572fb3a057b5006967")
KEEPALIVE = bytes.fromhex("3d217ced7fb6d7869e9bfdd01f498c27e7bb58d7")
CMD_ON = bytes.fromhex("fdbf089649b5812c8d94fcb92b9ad2d3e7bb584e")
CMD_COLDWHITE = bytes.fromhex("60ac94b7f6b77aaf8c0b8fe2593fa22de7bb58a0")
CMD_OFF = bytes.fromhex("227d19c9e212cdfe6b8a1893132a503ae7bb584f")

INIT_BURST = [
    bytes.fromhex("f21eae8067c38e28d38691d014eef648e7bb58c3"),
    bytes.fromhex("9aaa7bbacf47700ceed5e3d2624d5bcae7bb58f7"),
    bytes.fromhex("051ec1b1a8bf67bcb4bd8320d7f4bb01e7bb58f6"),
    bytes.fromhex("8e99d75367cf37f9a61edd0799245749e7bb5874"),
    bytes.fromhex("77832d308c1b6d76ee0fa01d5769cec1e7bb58d3"),
    bytes.fromhex("53956c1336ce2ab8b077262c4ab6eb12e7bb58d1"),
    bytes.fromhex("44b483b49f595f2a273d6f92656b4b97e7bb58f1"),
    bytes.fromhex("33cf8c3a2576519e7e31aa53bea13811e7bb586a"),
    bytes.fromhex("518f6c02ef741c96235dc54dd61fa4a3e7bb58d2"),
    bytes.fromhex("6aa5420e99c7f39434cb6d3ac2fb0d8be7bb58d5"),
    bytes.fromhex("345aa583a860d68cfccc7acfd0d3ded7e7bb58d2"),
    bytes.fromhex("bc6553dfb0059555cf88047c5dfb62dae7bb5873"),
    bytes.fromhex("ce5dcc4c9b40609f735cff5b9e5d63afe7bb5870"),
    bytes.fromhex("1742fecaefb9b1d27e2119ebe30aa70be7bb5874"),
]

log = logging.getLogger("govee_h601e")


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("AES ECB requires multiples of 16 bytes")
    if AES_BACKEND in ("pycryptodome", "pycryptodomex"):
        return _AES.new(key, _AES.MODE_ECB).encrypt(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.encryptor().update(data) + cipher.encryptor().finalize()


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("AES ECB requires multiples of 16 bytes")
    if AES_BACKEND in ("pycryptodome", "pycryptodomex"):
        return _AES.new(key, _AES.MODE_ECB).decrypt(data)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    return cipher.decryptor().update(data) + cipher.decryptor().finalize()


def hex_bytes(data: Optional[bytes]) -> str:
    return data.hex() if data is not None else "<none>"


class GoveeH601E:
    def __init__(self) -> None:
        self._notify_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._seen_packets: set[bytes] = set()
        self._keepalive_task: Optional[asyncio.Task] = None

    def _on_notify(self, characteristic: BleakGATTCharacteristic, data: bytearray) -> None:
        pkt = bytes(data)
        log.debug("Notify from %s: %s", characteristic.uuid, hex_bytes(pkt))
        self._notify_queue.put_nowait(pkt)

    async def _drain_queue(self) -> None:
        while not self._notify_queue.empty():
            self._notify_queue.get_nowait()

    async def _wait_for_notification(self, timeout: float) -> Optional[bytes]:
        try:
            return await asyncio.wait_for(self._notify_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def _wait_for_new_notification(self, timeout: float, ignore: set[bytes] | None = None) -> Optional[bytes]:
        ignore = ignore or set()
        end = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = end - asyncio.get_running_loop().time()
            if remaining <= 0:
                return None
            pkt = await self._wait_for_notification(remaining)
            if pkt is None:
                return None
            if pkt in ignore:
                log.debug("Ignoriere bereits gesehenes Notify: %s", hex_bytes(pkt))
                continue
            return pkt

    async def connect_and_handshake(self, client: BleakClient) -> bool:
        log.info("Abonniere Notify-Characteristic %s", NOTIFY_UUID)
        await client.start_notify(NOTIFY_UUID, self._on_notify)
        await asyncio.sleep(0.5)
        await self._drain_queue()

        log.info("Sende HS1")
        log.debug("HS1 payload      : %s", hex_bytes(KNOWN_HS1))
        log.debug("HS1 dec(first16) : %s", hex_bytes(aes_ecb_decrypt(ROOT_KEY, KNOWN_HS1[:16])))
        await client.write_gatt_char(WRITE_UUID, KNOWN_HS1, response=False)

        hs1_resp = await self._wait_for_new_notification(timeout=5.0)
        if hs1_resp is None:
            log.error("Keine Notification auf HS1 erhalten")
            return False
        self._seen_packets.add(hs1_resp)
        log.info("HS1-Notification : %s", hex_bytes(hs1_resp))

        await self._drain_queue()
        log.info("Sende HS2")
        log.debug("HS2 payload      : %s", hex_bytes(KNOWN_HS2))
        log.debug("HS2 dec(first16) : %s", hex_bytes(aes_ecb_decrypt(ROOT_KEY, KNOWN_HS2[:16])))
        await client.write_gatt_char(WRITE_UUID, KNOWN_HS2, response=False)
        hs2_resp = await self._wait_for_new_notification(timeout=3.0, ignore=self._seen_packets)
        if hs2_resp is None:
            log.error("Keine neue Notification auf HS2 erhalten")
            return False
        self._seen_packets.add(hs2_resp)
        log.info("HS2-Notification : %s", hex_bytes(hs2_resp))
        return True

    async def send_raw(self, client: BleakClient, packet: bytes, label: str, wait_reply: float = 1.0) -> list[bytes]:
        await self._drain_queue()
        log.info("Sende %s (%d Byte)", label, len(packet))
        log.debug("%s payload      : %s", label, hex_bytes(packet))
        if len(packet) >= 16:
            try:
                log.debug("%s dec(first16) : %s", label, hex_bytes(aes_ecb_decrypt(ROOT_KEY, packet[:16])))
            except Exception:
                pass
        await client.write_gatt_char(WRITE_UUID, packet, response=False)

        replies: list[bytes] = []
        end = asyncio.get_running_loop().time() + wait_reply
        while True:
            remaining = end - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            resp = await self._wait_for_new_notification(timeout=remaining, ignore=self._seen_packets)
            if resp is None:
                break
            self._seen_packets.add(resp)
            replies.append(resp)
            log.info("%s-Notification : %s", label, hex_bytes(resp))
            if len(resp) >= 16:
                try:
                    log.info("%s resp dec(first16): %s", label, hex_bytes(aes_ecb_decrypt(ROOT_KEY, resp[:16])))
                except Exception:
                    pass
        if not replies:
            log.info("Keine neue Notification auf %s", label)
        return replies

    async def replay_init_burst(self, client: BleakClient, gap: float, wait_reply: float) -> None:
        log.info("Replaying Init-Burst mit %d Frames", len(INIT_BURST))
        for idx, pkt in enumerate(INIT_BURST, start=1):
            await self.send_raw(client, pkt, f"INIT-{idx:02d}", wait_reply=wait_reply)
            if gap > 0:
                await asyncio.sleep(gap)

    async def keepalive_loop(self, client: BleakClient, interval: float = 3.0) -> None:
        try:
            while True:
                await asyncio.sleep(interval)
                await self.send_raw(client, KEEPALIVE, "KEEPALIVE", wait_reply=0.8)
        except asyncio.CancelledError:
            return

    async def start_keepalive(self, client: BleakClient) -> None:
        if self._keepalive_task and not self._keepalive_task.done():
            return
        log.info("Starte Keepalive alle 3.0 Sekunden")
        self._keepalive_task = asyncio.create_task(self.keepalive_loop(client, 3.0))

    async def stop_keepalive(self) -> None:
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None


async def scan_devices(timeout: float = 5.0) -> None:
    log.info("Scanne %.1f Sekunden nach BLE-Geräten ...", timeout)
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for _, (device, adv) in devices.items():
        name = device.name or adv.local_name or "<kein Name>"
        print(f"{device.address:40s} RSSI={device.rssi:4d}  Name={name}")


async def run(args: argparse.Namespace) -> int:
    if args.scan:
        await scan_devices(args.scan_timeout)
        return 0

    ctl = GoveeH601E()
    log.info("Verbinde zu %s", args.mac)

    async with BleakClient(args.mac, timeout=15.0) as client:
        if not client.is_connected:
            log.error("Verbindung fehlgeschlagen")
            return 2

        services = getattr(client, "services", None)
        if services is None:
            log.error("Bleak hat keine aufgelösten Services bereitgestellt")
            return 3

        write_char = services.get_characteristic(WRITE_UUID)
        notify_char = services.get_characteristic(NOTIFY_UUID)
        if write_char is None or notify_char is None:
            log.error("Erforderliche Characteristics nicht gefunden")
            return 4

        log.info("Write-Char gefunden : %s (props=%s)", write_char.uuid, ",".join(write_char.properties))
        log.info("Notify-Char gefunden: %s (props=%s)", notify_char.uuid, ",".join(notify_char.properties))

        ok = await ctl.connect_and_handshake(client)
        if not ok:
            return 5

        if args.replay_init_burst:
            await ctl.replay_init_burst(client, gap=args.burst_gap, wait_reply=args.burst_wait_reply)

        if args.handshake_only:
            log.info("Nur Handshake ausgeführt")
            return 0

        await ctl.start_keepalive(client)
        await asyncio.sleep(args.action_delay)

        did_anything = False
        test_map = {
            "on": (CMD_ON, "TEST-ON"),
            "coldwhite": (CMD_COLDWHITE, "TEST-COLDWHITE"),
            "off": (CMD_OFF, "TEST-OFF"),
        }

        if args.test:
            packet, label = test_map[args.test]
            await ctl.send_raw(client, packet, label, wait_reply=args.action_wait_reply)
            did_anything = True

        for idx, raw_hex in enumerate(args.raw_cmd_hex or [], start=1):
            pkt = bytes.fromhex(raw_hex)
            await ctl.send_raw(client, pkt, f"RAW-CMD-{idx}", wait_reply=args.action_wait_reply)
            did_anything = True

        if not did_anything:
            log.info("Kein Testkommando gewählt; Keepalive läuft %.1f Sekunden zur Beobachtung", args.idle_after)

        await asyncio.sleep(args.idle_after)
        await ctl.stop_keepalive()
        return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Govee H601E BLE replay test")
    p.add_argument("--scan", action="store_true", help="BLE-Geräte scannen")
    p.add_argument("--scan-timeout", type=float, default=5.0)
    p.add_argument("--mac", default=DEFAULT_ADDRESS)
    p.add_argument("--debug", action="store_true")
    p.add_argument("--handshake-only", action="store_true")
    p.add_argument("--replay-init-burst", action="store_true", help="Replay der 14 Init-Frames aus dem Logger")
    p.add_argument("--burst-gap", type=float, default=0.02, help="Pause zwischen Init-Frames in Sekunden")
    p.add_argument("--burst-wait-reply", type=float, default=0.15, help="Wie lange nach jedem Init-Frame auf Notifications gesammelt wird")
    p.add_argument("--test", choices=["on", "coldwhite", "off"])
    p.add_argument("--raw-cmd-hex", action="append", default=[], help="Rohes 20-Byte-Command in Hex; mehrfach nutzbar")
    p.add_argument("--action-delay", type=float, default=1.0, help="Sekunden nach Start des Keepalive bis zum Testkommando")
    p.add_argument("--action-wait-reply", type=float, default=0.35, help="Wie lange nach dem Testkommando auf Notifications gesammelt wird")
    p.add_argument("--idle-after", type=float, default=4.0, help="Sekunden nach dem letzten Testkommando offen bleiben")
    return p


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    try:
        rc = asyncio.run(run(args))
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
