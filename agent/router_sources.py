"""What the router knows about the devices of the network, through the ways that do not need its password (agent
2.0.0).

Detecting the router is not administering it. The official list of clients, blocking a device or changing the Wi-Fi
password need to log in to the router with its administrator password, and every maker (and every provider) does it
differently. WiFiSense does not have an official integration with any model yet, so those operations do not exist here
and the page explains how to do them on the router itself. This abstraction leaves the place ready to add them without
touching the rest of the agent:

  * ``RouterSource`` (Strategy): what a source can do. Today only ``names``.
  * ``GatewayDnsSource`` (Adapter of the DNS protocol): many home routers (dnsmasq: TP-Link, ASUS, OpenWrt and several
    from providers) keep the name each device gave when asking for an address (DHCP) and answer it when asked for the
    reversed IP (PTR). It is read only, uses no password, and the router is asked directly: the DNS configured on the
    computer may be the provider's, which does not know the devices of the home.
  * ``source_for`` (Factory): chooses the source by the maker and model of the router. A future integration (with the
    owner's authorization and through an official mechanism of the maker) would be another class here.

The password of the router is never stored nor sent: today it is not even asked.
"""
from __future__ import annotations

import random
import socket
import struct
import time
from typing import Iterable, Optional, Protocol

try:  # the agent as a package (tests) or as loose scripts (PyInstaller, python wifisense_agent.py)
    from agent.dns_wire import read_name
except ImportError:  # pragma: no cover
    from dns_wire import read_name

DNS_PORT = 53
TYPE_PTR, CLASS_IN = 12, 1
MAX_QUERIES = 1024


class NotSupported(Exception):
    """The operation does not exist for this router: there is no official integration."""


class RouterSource(Protocol):
    code: str

    def names(self, ips: Iterable[str]) -> dict[str, str]:
        """IP -> name the router knows. Whatever it does not know does not appear."""

    def clients(self) -> list[dict]:
        """The official list of clients of the router (active and past)."""

    def block(self, device: str) -> None:
        """Removes a device from the network on the router."""


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError("etiqueta DNS inválida")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def ptr_query(ip: str, query_id: int) -> bytes:
    """Standard PTR question with recursion desired (the router answers from its own table)."""
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encode_name(reverse_name(ip)) + struct.pack(
        "!HH", TYPE_PTR, CLASS_IN)


def parse_ptr_answer(data: bytes) -> tuple[int, Optional[str]]:
    """(question id, name) of a PTR answer; name None when the router does not know it or the answer is odd."""
    if len(data) < 12:
        raise ValueError("respuesta corta")
    query_id, flags, questions, answers = struct.unpack("!HHHH", data[:8])
    if not flags & 0x8000 or flags & 0x000F:  # not an answer, or it carries an error (for example NXDOMAIN)
        return query_id, None
    offset = 12
    for _ in range(questions):
        _name, offset = read_name(data, offset)
        offset += 4
    for _ in range(answers):
        _name, offset = read_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("respuesta cortada")
        record_type, _cls, _ttl, length = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if record_type == TYPE_PTR:
            name, _ = read_name(data, offset)
            return query_id, name or None
        offset += length
    return query_id, None


class GatewayDnsSource:
    """Asks the DNS of the router the name of each IP, all at once through the same socket (fast even for hundreds),
    and waits at most ``timeout`` seconds in total."""
    code = "GATEWAY_DNS"

    def __init__(self, gateway: str, timeout: float = 1.5, port: int = DNS_PORT,
                 clock=time.monotonic, sock_factory=None):
        self.gateway, self.timeout, self.port, self.clock = gateway, timeout, port, clock
        self.sock_factory = sock_factory or (lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

    def names(self, ips: Iterable[str]) -> dict[str, str]:
        pending: dict[int, str] = {}
        found: dict[str, str] = {}
        with self.sock_factory() as sock:
            sock.settimeout(0.2)
            used = set()
            for ip in list(ips)[:MAX_QUERIES]:
                query_id = random.randrange(1, 0xFFFF)
                while query_id in used:
                    query_id = random.randrange(1, 0xFFFF)
                used.add(query_id)
                try:
                    sock.sendto(ptr_query(ip, query_id), (self.gateway, self.port))
                    pending[query_id] = ip
                except (OSError, ValueError):
                    continue
            end = self.clock() + self.timeout
            while pending and self.clock() < end:
                try:
                    data, sender = sock.recvfrom(1500)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if sender[0] != self.gateway:  # only what the router itself answers counts
                    continue
                try:
                    query_id, name = parse_ptr_answer(data)
                except (ValueError, struct.error):
                    continue
                ip = pending.pop(query_id, None)
                if ip and name:
                    found[ip] = name
        return found

    def clients(self) -> list[dict]:
        raise NotSupported("La lista oficial de clientes necesita una integración con el router.")

    def block(self, device: str) -> None:
        raise NotSupported("Bloquear un equipo se hace en el router: WiFiSense no tiene integración con este modelo.")


def source_for(gateway: Optional[str], vendor: Optional[str] = None, model: Optional[str] = None
               ) -> Optional[RouterSource]:
    """The source for this router. Today, for any maker, only reading names through its DNS; when an official
    integration of a model exists, it would be chosen here by ``vendor`` and ``model``."""
    if not gateway:
        return None
    return GatewayDnsSource(gateway)


SUPPORTED_OPERATIONS = {
    "READ_NAMES": True,       # through the DNS of the router, without a password
    "LIST_CLIENTS": False,    # needs an official integration
    "BLOCK_DEVICE": False,    # needs an official integration
    "CHANGE_PASSWORD": False,  # never from WiFiSense: it is done on the router
}
