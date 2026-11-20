"""Reading of pcap and pcapng capture files (the ones Windows pktmon writes when it converts its .etl).

Only the headers of the blocks and the first bytes of each packet are read (the agent asks the tool to keep at most
128 bytes per packet). A damaged or truncated file does not break the agent: the reading stops and the rest is counted
as damaged. None of this leaves the computer: packet_parser and capture_stats turn it into counts and the file is
deleted (capture_files).

Formats (https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-03.html and draft-ietf-opsawg-pcapng):
  * pcap: a 24-byte header (magic number, version, maximum size, link type) and each packet with a 16-byte header
    (seconds, micro or nanoseconds, stored bytes, original bytes).
  * pcapng: blocks (type, length, body, length). SHB opens a section (and tells the byte order), IDB describes an
    interface (link type and time resolution), EPB and SPB carry packets, ISB carries statistics of the interface
    (packets the tool dropped).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER = 0x1A2B3C4D
BLOCK_IDB, BLOCK_SPB, BLOCK_ISB, BLOCK_EPB, BLOCK_OPB = 1, 3, 5, 6, 2
OPTION_END, OPTION_IF_TSRESOL, OPTION_ISB_IFDROP = 0, 9, 5
MAX_BLOCK = 1 << 20  # a block of more than 1 MB is not from a capture of headers: the file is damaged


class CaptureFileError(Exception):
    """The file is neither pcap nor pcapng."""


@dataclass(frozen=True)
class Frame:
    """A packet read from the file: moment (seconds), link type, stored bytes and original length."""
    timestamp: float
    link_type: int
    data: bytes
    original_length: int


@dataclass
class FileSummary:
    """What the file says about itself besides the packets."""
    dropped_by_tool: Optional[int] = None  # sum of isb_ifdrop of pcapng; None if the tool did not say
    damaged: bool = False                  # the reading stopped at a damaged or truncated block


def read_frames(stream: BinaryIO, summary: Optional[FileSummary] = None) -> Iterator[Frame]:
    """The packets of a pcap or pcapng file, in order."""
    summary = summary if summary is not None else FileSummary()
    head = stream.read(4)
    if len(head) < 4:
        raise CaptureFileError("El archivo de captura está vacío.")
    if struct.unpack("<I", head)[0] == PCAPNG_SHB:
        yield from _pcapng(stream, head, summary)
        return
    for order in ("<", ">"):
        magic = struct.unpack(order + "I", head)[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            yield from _pcap(stream, order, magic == PCAP_MAGIC_NS, summary)
            return
    raise CaptureFileError("El archivo no es una captura pcap ni pcapng.")


def _pcap(stream: BinaryIO, order: str, nanoseconds: bool, summary: FileSummary) -> Iterator[Frame]:
    header = stream.read(20)
    if len(header) < 20:
        summary.damaged = True
        return
    link_type = struct.unpack(order + "HHiIII", header)[5] & 0x0FFFFFFF
    divisor = 1e9 if nanoseconds else 1e6
    while True:
        record = stream.read(16)
        if not record:
            return
        if len(record) < 16:
            summary.damaged = True
            return
        seconds, fraction, saved, original = struct.unpack(order + "IIII", record)
        if saved > MAX_BLOCK:
            summary.damaged = True
            return
        data = stream.read(saved)
        if len(data) < saved:
            summary.damaged = True
            return
        yield Frame(seconds + fraction / divisor, link_type, data, original)


def _pcapng(stream: BinaryIO, head: bytes, summary: FileSummary) -> Iterator[Frame]:
    order = "<"
    interfaces: list[tuple[int, float]] = []  # (link type, seconds per time unit)
    block_type_raw = head
    while True:
        if not block_type_raw:
            return  # clean end of the file
        length_raw = stream.read(4)
        if len(block_type_raw) < 4 or len(length_raw) < 4:
            summary.damaged = True
            return
        block_type = struct.unpack(order + "I", block_type_raw)[0]
        if block_type == PCAPNG_SHB:
            # the byte order of the section is in the body, before the length can be read correctly
            body_start = stream.read(4)
            if len(body_start) < 4:
                summary.damaged = True
                return
            order = "<" if struct.unpack("<I", body_start)[0] == PCAPNG_BYTE_ORDER else ">"
            length = struct.unpack(order + "I", length_raw)[0]
            if length < 28 or length > MAX_BLOCK or length % 4:
                summary.damaged = True
                return
            body = body_start + stream.read(length - 12 - 4)
            interfaces = []  # each section numbers its interfaces from zero
        else:
            length = struct.unpack(order + "I", length_raw)[0]
            if length < 12 or length > MAX_BLOCK or length % 4:
                summary.damaged = True
                return
            body = stream.read(length - 12)
        trailer = stream.read(4)
        if len(body) < length - 12 or len(trailer) < 4:
            summary.damaged = True
            return
        if block_type == BLOCK_IDB and len(body) >= 8:
            link_type = struct.unpack(order + "H", body[:2])[0]
            interfaces.append((link_type, _resolution(_options(body[8:], order).get(OPTION_IF_TSRESOL))))
        elif block_type in (BLOCK_EPB, BLOCK_OPB) and len(body) >= 20:
            if block_type == BLOCK_EPB:
                interface, high, low, saved, original = struct.unpack(order + "IIIII", body[:20])
            else:  # obsolete block: the interface number takes 2 bytes and there are 2 of flags
                interface, _drops, high, low, saved, original = struct.unpack(order + "HHIIII", body[:20])
            if interface < len(interfaces) and saved <= len(body) - 20:
                link_type, unit = interfaces[interface]
                yield Frame(((high << 32) | low) * unit, link_type, body[20:20 + saved], original)
            else:
                summary.damaged = True
        elif block_type == BLOCK_SPB and len(body) >= 4 and interfaces:
            original = struct.unpack(order + "I", body[:4])[0]
            link_type, _unit = interfaces[0]
            yield Frame(0.0, link_type, body[4:4 + min(original, len(body) - 4)], original)
        elif block_type == BLOCK_ISB and len(body) >= 12:
            drop = _options(body[12:], order).get(OPTION_ISB_IFDROP)
            if drop is not None and len(drop) >= 8:
                summary.dropped_by_tool = (summary.dropped_by_tool or 0) + struct.unpack(order + "Q", drop[:8])[0]
        block_type_raw = stream.read(4)


def _options(raw: bytes, order: str) -> dict[int, bytes]:
    """Options of a pcapng block: (code, length, value padded to 4 bytes)."""
    found, offset = {}, 0
    while offset + 4 <= len(raw):
        code, length = struct.unpack(order + "HH", raw[offset:offset + 4])
        if code == OPTION_END:
            break
        found.setdefault(code, raw[offset + 4:offset + 4 + length])
        offset += 4 + length + (-length % 4)
    return found


def _resolution(raw: Optional[bytes]) -> float:
    """if_tsresol: power of 10 (high bit 0) or of 2 (high bit 1) of the unit; microseconds by default."""
    if not raw:
        return 1e-6
    value = raw[0]
    exponent = value & 0x7F
    return 2.0 ** -exponent if value & 0x80 else 10.0 ** -exponent
