"""Headers of a captured packet -> which protocol it is, from where to where and through which port.

Minimal capture: only the link, IP and TCP/UDP headers are read (the first bytes of the packet). The content is never
read: not the names asked to DNS, nor pages, passwords or cookies. The application protocol is deduced only from the
port number (53 is DNS, 443 is HTTPS...), without opening the packet.

The IP and MAC addresses only exist here, in memory, to count incoming and outgoing traffic and how many different
devices there were; capture_stats does not send them to the server.

Link types (LINKTYPE of tcpdump.org): 1 Ethernet (what Npcap and pktmon deliver on a normal Wi-Fi card), 101/228/229
IP without link (raw sockets), 113 and 276 Linux «cooked» (packet socket on the "any" interface).
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional

LINK_ETHERNET, LINK_RAW, LINK_IPV4, LINK_IPV6, LINK_LINUX_SLL, LINK_LINUX_SLL2 = 1, 101, 228, 229, 113, 276
ETHERTYPE_IPV4, ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_VLAN, ETHERTYPE_QINQ = 0x0800, 0x0806, 0x86DD, 0x8100, 0x88A8
IPPROTO_ICMP, IPPROTO_IGMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6 = 1, 2, 6, 17, 58
IPV6_EXTENSIONS = (0, 43, 44, 60)  # hop by hop, routing, fragment, destination options

# Port -> application protocol (only by the number, without opening the packet).
UDP_SERVICES = {53: "DNS", 5353: "MDNS", 67: "DHCP", 68: "DHCP", 546: "DHCP", 547: "DHCP", 1900: "SSDP",
                137: "NETBIOS", 138: "NETBIOS", 5355: "LLMNR", 443: "QUIC", 123: "NTP"}
TCP_SERVICES = {53: "DNS", 139: "NETBIOS", 80: "HTTP", 8080: "HTTP", 443: "HTTPS", 5355: "LLMNR"}
EPHEMERAL_FROM = 49152  # ports from here on are chosen at random by the system: they do not tell which service it is

# What the server accepts (AgentCaptureResult.Protocol): anything else would be rejected.
PROTOCOLS = ("TCP", "UDP", "ICMP", "ICMPV6", "ARP", "IGMP", "DNS", "MDNS", "DHCP", "SSDP", "NETBIOS", "LLMNR",
             "HTTP", "HTTPS", "QUIC", "NTP", "IPV6_OTHER", "IPV4_OTHER", "OTHER")


@dataclass(frozen=True)
class PacketInfo:
    """What is known about a packet from its headers."""
    length: int                         # original bytes of the packet (not only the stored ones)
    protocol: str                       # one of PROTOCOLS
    transport: Optional[str] = None     # "TCP" or "UDP"
    service_port: Optional[int] = None  # the well-known port of the conversation (443, 53...), not the ephemeral one
    source: Optional[str] = None        # source IP (in memory only)
    destination: Optional[str] = None   # destination IP (in memory only)
    broadcast: bool = False             # for every device of the network (MAC ff:ff:ff:ff:ff:ff or broadcast IP)
    multicast: bool = False             # for a group (mDNS, SSDP, IPv6...)
    malformed: bool = False             # headers cut short or impossible: counted, not interpreted


def parse(data: bytes, link_type: int, original_length: Optional[int] = None) -> PacketInfo:
    """Interprets the headers of a packet. It never raises: whatever cannot be read comes out as malformed."""
    length = original_length if original_length is not None else len(data)
    try:
        return _parse(data, link_type, length)
    except (struct.error, IndexError, ValueError):
        return PacketInfo(length, "OTHER", malformed=True)


def _parse(data: bytes, link_type: int, length: int) -> PacketInfo:
    broadcast = multicast = False
    if link_type == LINK_ETHERNET:
        if len(data) < 14:
            return PacketInfo(length, "OTHER", malformed=True)
        destination_mac = data[0:6]
        broadcast = destination_mac == b"\xff" * 6
        multicast = not broadcast and bool(destination_mac[0] & 1)
        ethertype, offset = struct.unpack("!H", data[12:14])[0], 14
        while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):  # VLAN tags: 4 bytes each
            ethertype, offset = struct.unpack("!H", data[offset + 2:offset + 4])[0], offset + 4
    elif link_type == LINK_LINUX_SLL:
        packet_type = struct.unpack("!H", data[0:2])[0]
        broadcast, multicast = packet_type == 1, packet_type == 2
        ethertype, offset = struct.unpack("!H", data[14:16])[0], 16
    elif link_type == LINK_LINUX_SLL2:
        ethertype = struct.unpack("!H", data[0:2])[0]
        broadcast, multicast = data[10] == 1, data[10] == 2
        offset = 20
    elif link_type in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        if not data:
            return PacketInfo(length, "OTHER", malformed=True)
        version = data[0] >> 4
        ethertype, offset = (ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6 if version == 6 else 0), 0
    else:
        return PacketInfo(length, "OTHER")

    if ethertype == ETHERTYPE_ARP:
        return PacketInfo(length, "ARP", broadcast=broadcast, multicast=multicast)
    if ethertype == ETHERTYPE_IPV4:
        return _ipv4(data, offset, length, broadcast, multicast)
    if ethertype == ETHERTYPE_IPV6:
        return _ipv6(data, offset, length, broadcast, multicast)
    return PacketInfo(length, "OTHER", broadcast=broadcast, multicast=multicast)


def _ipv4(data: bytes, offset: int, length: int, broadcast: bool, multicast: bool) -> PacketInfo:
    if len(data) < offset + 20 or data[offset] >> 4 != 4:
        return PacketInfo(length, "IPV4_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    header = (data[offset] & 0x0F) * 4
    if header < 20:
        return PacketInfo(length, "IPV4_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    protocol = data[offset + 9]
    source = str(ipaddress.IPv4Address(data[offset + 12:offset + 16]))
    destination_ip = ipaddress.IPv4Address(data[offset + 16:offset + 20])
    destination = str(destination_ip)
    broadcast = broadcast or destination == "255.255.255.255"
    multicast = multicast or destination_ip.is_multicast
    fragment_offset = struct.unpack("!H", data[offset + 6:offset + 8])[0] & 0x1FFF
    common = dict(source=source, destination=destination, broadcast=broadcast, multicast=multicast)
    if protocol == IPPROTO_ICMP:
        return PacketInfo(length, "ICMP", **common)
    if protocol == IPPROTO_IGMP:
        return PacketInfo(length, "IGMP", **common)
    if protocol in (IPPROTO_TCP, IPPROTO_UDP):
        if fragment_offset:  # a fragment that is not the first one carries no ports
            return PacketInfo(length, "TCP" if protocol == IPPROTO_TCP else "UDP",
                              transport="TCP" if protocol == IPPROTO_TCP else "UDP", **common)
        return _transport(data, offset + header, protocol, length, common)
    return PacketInfo(length, "IPV4_OTHER", **common)


def _ipv6(data: bytes, offset: int, length: int, broadcast: bool, multicast: bool) -> PacketInfo:
    if len(data) < offset + 40 or data[offset] >> 4 != 6:
        return PacketInfo(length, "IPV6_OTHER", broadcast=broadcast, multicast=multicast, malformed=True)
    next_header = data[offset + 6]
    source = str(ipaddress.IPv6Address(data[offset + 8:offset + 24]))
    destination_ip = ipaddress.IPv6Address(data[offset + 24:offset + 40])
    common = dict(source=source, destination=str(destination_ip), broadcast=broadcast,
                  multicast=multicast or destination_ip.is_multicast)
    position = offset + 40
    for _ in range(8):  # at most 8 extensions; more would be a crafted packet
        if next_header not in IPV6_EXTENSIONS:
            break
        if len(data) < position + 8:
            return PacketInfo(length, "IPV6_OTHER", malformed=True, **common)
        if next_header == 44:  # fragment: fixed size; if it is not the first one, there are no ports
            if struct.unpack("!H", data[position + 2:position + 4])[0] >> 3:
                return PacketInfo(length, "IPV6_OTHER", **common)
            next_header, position = data[position], position + 8
        else:
            next_header, position = data[position], position + (data[position + 1] + 1) * 8
    if next_header == IPPROTO_ICMPV6:
        return PacketInfo(length, "ICMPV6", **common)
    if next_header in (IPPROTO_TCP, IPPROTO_UDP):
        return _transport(data, position, next_header, length, common)
    return PacketInfo(length, "IPV6_OTHER", **common)


def _transport(data: bytes, offset: int, protocol: int, length: int, common: dict) -> PacketInfo:
    transport = "TCP" if protocol == IPPROTO_TCP else "UDP"
    if len(data) < offset + 4:  # the tool stored fewer bytes than the ports need
        return PacketInfo(length, transport, transport=transport, malformed=True, **common)
    source_port, destination_port = struct.unpack("!HH", data[offset:offset + 4])
    services = TCP_SERVICES if transport == "TCP" else UDP_SERVICES
    label = services.get(destination_port) or services.get(source_port) or transport
    return PacketInfo(length, label, transport=transport, service_port=service_port(source_port, destination_port),
                      **common)


def service_port(source: int, destination: int) -> Optional[int]:
    """The port that identifies the service: the well-known one of the two (the system chose the other one at random)."""
    known = [port for port in (destination, source) if 0 < port < EPHEMERAL_FROM]
    return min(known) if known else None
