"""Statistics of a capture: the only thing that leaves the computer.

Counts packets and bytes, incoming and outgoing, broadcast and multicast, packets per protocol, the most used services
(by well-known port) and packets per second. The devices are counted (how many of the local network and how many from
outside), but their addresses stay in memory and are forgotten at the end: the result has no field for an IP, a MAC or
the content of a packet (see AgentCaptureResult in the backend, which also rejects whatever does not add up).

The limits (seconds, packets, bytes) are decided by whoever asked for the capture and are enforced here: when one is
reached, the capture stops and the result says which one (stopReason).
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional

try:  # the agent as a package (tests) or as loose scripts (PyInstaller)
    from agent.packet_parser import PROTOCOLS, PacketInfo
except ImportError:  # pragma: no cover
    from packet_parser import PROTOCOLS, PacketInfo

MAX_SECONDS_KEPT = 360  # the server accepts 0 to 360 seconds
MAX_PORTS = 20
SERVER_MAX_PACKETS = 100_000
SERVER_MAX_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """What the server asked for: never more than what it accepts itself."""
    seconds: int
    packets: int
    bytes: int

    @staticmethod
    def of(task: dict) -> "Limits":
        def number(name: str, default: int, top: int) -> int:
            value = task.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                return default
            return min(value, top)
        return Limits(number("maxSeconds", 30, 300), number("maxPackets", 5000, SERVER_MAX_PACKETS),
                      number("maxBytes", 20 * 1024 * 1024, SERVER_MAX_BYTES))


@dataclass
class CaptureStats:
    """Accumulates packet by packet. ``local_networks`` are the networks of this computer (to tell what is local and
    what is incoming or outgoing); ``own_addresses`` are its own IPs."""
    limits: Limits
    own_addresses: frozenset = frozenset()
    local_networks: tuple = ()
    packets: int = 0
    bytes: int = 0
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    broadcast: int = 0
    multicast: int = 0
    malformed: int = 0
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    stop_reason: Optional[str] = None
    protocols: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    port_bytes: Counter = field(default_factory=Counter)
    seconds: Counter = field(default_factory=Counter)
    second_bytes: Counter = field(default_factory=Counter)
    _local_hosts: set = field(default_factory=set, repr=False)
    _remote_hosts: set = field(default_factory=set, repr=False)

    def full(self) -> bool:
        """True once a limit has been reached: whoever captures must stop."""
        return self.stop_reason is not None

    def add(self, info: PacketInfo, timestamp: Optional[float] = None) -> bool:
        """Counts a packet. Returns False (and does not count it) if a limit was already reached."""
        if self.full():
            return False
        if self.packets + 1 > self.limits.packets:
            self.stop_reason = "PACKET_LIMIT"
            return False
        if self.bytes + info.length > self.limits.bytes:
            self.stop_reason = "BYTE_LIMIT"
            return False
        if timestamp is not None and timestamp > 0:
            if self.first_timestamp is None:
                self.first_timestamp = timestamp
            if timestamp - self.first_timestamp >= self.limits.seconds:
                self.stop_reason = "DURATION"
                return False
            self.last_timestamp = timestamp
        self.packets += 1
        self.bytes += info.length
        self.protocols[info.protocol] += 1
        self.protocol_bytes[info.protocol] += info.length
        if info.malformed:
            self.malformed += 1
        if info.broadcast or self._directed_broadcast(info.destination):
            self.broadcast += 1
        elif info.multicast:
            self.multicast += 1
        if info.transport and info.service_port is not None:
            key = (info.transport, info.service_port)
            self.ports[key] += 1
            self.port_bytes[key] += info.length
        if self.first_timestamp is not None and timestamp is not None and timestamp > 0:
            second = int(timestamp - self.first_timestamp)
            if second <= MAX_SECONDS_KEPT:
                self.seconds[second] += 1
                self.second_bytes[second] += info.length
        self._direction(info)
        return True

    def _direction(self, info: PacketInfo) -> None:
        # each packet counts once: outgoing if this computer sent it, incoming if it received it
        if info.source and info.source in self.own_addresses:
            self.outbound_bytes += info.length
        elif info.destination and info.destination in self.own_addresses:
            self.inbound_bytes += info.length
        for address in (info.source, info.destination):
            if not address or address in self.own_addresses:
                continue
            kind = self._kind(address)
            if kind == "local":
                self._local_hosts.add(address)
            elif kind == "remote":
                self._remote_hosts.add(address)

    def _kind(self, address: str) -> Optional[str]:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback or str(ip) == "255.255.255.255":
            return None
        if any(ip.version == network.version and ip in network for network in self.local_networks):
            return "local"
        if ip.is_link_local or ip.is_private:
            return "local"
        return "remote"

    def _directed_broadcast(self, address: Optional[str]) -> bool:
        if not address:
            return False
        return any(network.version == 4 and network.prefixlen < 31 and address == str(network.broadcast_address)
                   for network in self.local_networks)

    def result(self, capture_id: int, tool: str, interface_name: Optional[str], agent_version: str,
               duration_ms: int, dropped_by_tool: Optional[int]) -> dict:
        """The body of POST /api/agent/captures. Counts only: neither addresses nor content."""
        protocols = [{"protocol": name if name in PROTOCOLS else "OTHER", "packets": count,
                      "bytes": self.protocol_bytes[name]}
                     for name, count in self.protocols.most_common()]
        ports = [{"transport": transport, "port": port, "packets": count, "bytes": self.port_bytes[(transport, port)]}
                 for (transport, port), count in self.ports.most_common(MAX_PORTS)]
        intervals = [{"second": second, "packets": self.seconds[second], "bytes": self.second_bytes[second]}
                     for second in sorted(self.seconds)]
        result = {
            "captureId": capture_id,
            "status": "COMPLETED",
            "stopReason": self.stop_reason or "DURATION",
            "captureTool": tool,
            "interfaceName": (interface_name or "")[:64] or None,
            "agentVersion": agent_version,
            "durationMs": max(0, min(int(duration_ms), 400_000)),
            "packetCount": self.packets,
            "byteCount": self.bytes,
            "droppedByTool": None if dropped_by_tool is None else max(0, min(int(dropped_by_tool), 100_000_000)),
            "malformedPackets": self.malformed,
            "inboundBytes": self.inbound_bytes,
            "outboundBytes": self.outbound_bytes,
            "broadcastPackets": self.broadcast,
            "multicastPackets": self.multicast,
            "distinctLocalHosts": min(len(self._local_hosts), 32_767),
            "distinctRemoteHosts": min(len(self._remote_hosts), 100_000),
            "protocols": _merge(protocols),
            "ports": ports,
            "intervals": intervals,
        }
        return {key: value for key, value in result.items() if value is not None}

    def forget_addresses(self) -> None:
        """At the end: the addresses seen are forgotten (only the counts remain)."""
        self._local_hosts.clear()
        self._remote_hosts.clear()


def _merge(protocols: list[dict]) -> list[dict]:
    """If something odd turned into OTHER, it is added in a single row (the server does not accept repeated protocols)."""
    merged: dict[str, dict] = {}
    for row in protocols:
        found = merged.get(row["protocol"])
        if found:
            found["packets"] += row["packets"]
            found["bytes"] += row["bytes"]
        else:
            merged[row["protocol"]] = dict(row)
    return list(merged.values())


def local_networks(prefixes: Iterable[str]) -> tuple:
    """'192.168.1.23/24' -> the network 192.168.1.0/24. Whatever cannot be understood is ignored."""
    networks = []
    for prefix in prefixes:
        try:
            networks.append(ipaddress.ip_interface(prefix).network)
        except ValueError:
            continue
    return tuple(networks)


def failure(capture_id: int, reason: str, agent_version: str, tool: Optional[str] = None,
            interface_name: Optional[str] = None) -> dict:
    """The body of a capture that could not be done, with its reason (one the server knows)."""
    result = {"captureId": capture_id, "status": "FAILED", "failureReason": reason, "agentVersion": agent_version}
    if tool:
        result["captureTool"] = tool
    if interface_name:
        result["interfaceName"] = interface_name[:64]
    return result
