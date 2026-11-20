"""The DNS wire format the agent speaks: writing a name in a question and reading a name (with compression pointers)
from an answer. The mDNS discovery of devices (device_discovery.py, wifisense_agent.py) and the DNS of the router
(router_sources.py) read packets the same way, so this lives once.

Standard library only.
"""
from __future__ import annotations

MAX_POINTERS = 10


def dns_name(name: str) -> bytes:
    """A name in DNS format: each label preceded by its length, and a zero at the end."""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".") if part) + b"\0"


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """(name, offset after it) of the name at ``offset``, following compression pointers.

    A malformed packet (cut short, or with pointers that loop) raises ValueError instead of reading past its end.
    """
    if depth > MAX_POINTERS:
        raise ValueError("too many pointers")
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("name cut short")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("pointer cut short")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = read_name(data, pointer, depth + 1)
            labels.append(name)
            return ".".join(label for label in labels if label), offset + 2
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
