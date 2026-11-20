#!/usr/bin/env python3
"""WiFiSense agent: measures your Wi-Fi network from a computer at home and sends a report to WiFiSense.

It only uses the Python 3.9+ standard library (nothing has to be installed) and works on Windows and Linux.

    python wifisense_agent.py pair CODE    connects the agent with the code from Mi Wi-Fi > Instalar agente
    python wifisense_agent.py setup        stores the key of the agent (created in Mi Wi-Fi > Agente)
    python wifisense_agent.py scan         shows what it would measure, without sending anything
    python wifisense_agent.py nearby       scans the nearby Wi-Fi networks and shows them, without sending anything
    python wifisense_agent.py run          sends a report every 5 minutes (Ctrl + C to stop)
    python wifisense_agent.py run --once   sends a single report
    python wifisense_agent.py capture-check        tells whether this computer can do technical captures and why
    python wifisense_agent.py capture-consent on   allows technical captures on this computer (off: forbids them)
    python wifisense_agent.py capture-local        tries a capture right here and shows the counts, sending nothing
    python wifisense_agent.py live                 measures live every 2 seconds and shows it, sending nothing

What it measures and what it sends:
  * Data of the Wi-Fi the system shows (name, security type, signal, channel, band) and how many neighbouring networks
    use each channel, to recommend the channel with the least interference.
  * Latency, variation (jitter) and loss towards the internet and towards the router.
  * How many devices are connected and, for each one, the maker (from the MAC) and the name it announces on the
    network, so you can recognise them as in Bluetooth. The MAC addresses do NOT leave your computer: a SHA-256
    fingerprint with a random salt of this installation is sent instead.
  * Which administration ports of the router accept connections (it only tries to connect; no data is sent).
  * When Mi Wi-Fi asks (or every hour, if the server asks), the nearby Wi-Fi networks the antenna sees: name, signal,
    channel, band and announced security. Of each access point only the fingerprint of its BSSID and its last byte
    leave, never the whole MAC, and the stored passwords are never read (see wifi_scan.py).
  * The traffic of this computer since the previous report (bytes and packets per protocol TCP, UDP and ICMP), read
    from the counters of the system. It is only stored when the agent is the sensor of a network of the WiFiSense
    team.
  * What this computer can do for technical captures (whether they were allowed, which tool there is, whether it runs
    as administrator). A capture only happens if a WiFiSense administrator asks for it for a team network AND whoever
    administers this computer allowed it with capture-consent on; only counts come out of it (see traffic_capture.py).
    The networks of Mi Wi-Fi never do captures.
  * While someone has «En vivo» open on the page (2.1.0), every 2 seconds: how much this computer downloads and uploads
    at that moment (counters of the card), the latency to the router and to the internet and the Wi-Fi signal. Only
    numbers of this computer; it stops when nobody is watching (see live_monitor.py).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

AGENT_VERSION = "2.1.0"
DEFAULT_SERVER = "https://patroneswifibackend-production.up.railway.app"
REPORT_PATH = "/api/agent/reports"
PAIR_PATH = "/api/agent/pair"
SCANS_PATH = "/api/agent/scans"
NEXT_SCAN_PATH = "/api/agent/scans/next"
SCAN_POLL_SECONDS = 30  # between reports, how often it asks whether the user asked for a scan
CAPTURES_PATH = "/api/agent/captures"
NEXT_CAPTURE_PATH = "/api/agent/captures/next"
NEXT_LIVE_PATH = "/api/agent/live/next"
LIVE_SAMPLES_PATH = "/api/agent/live/samples"
DEFAULT_INTERVAL = 300
MIN_INTERVAL = 60
ROUTER_PORTS = (21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080, 8443)
INTERNET_TARGET = ("1.1.1.1", 443)
SAMPLES = 10
MAX_DEVICES = 256
IS_WINDOWS = os.name == "nt"


# -------------------------------------------------------------------------------------------------- system commands

def run_command(args: list[str], timeout: float = 15) -> str:
    """Output of the command, or an empty string if it does not exist or fails. It never uses the shell."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return ""
    return console_text(result.stdout)


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------------------- Wi-Fi

try:  # the agent as a package (tests) or as loose scripts (PyInstaller, python wifisense_agent.py)
    from agent.dns_wire import dns_name, read_name
    from agent.wifi_text import (authentication_of, band_of, cipher_of, console_text, first_number, key_values,
                                 normalize_key, split_nmcli)
except ImportError:  # pragma: no cover
    from dns_wire import dns_name, read_name
    from wifi_text import (authentication_of, band_of, cipher_of, console_text, first_number, key_values,
                           normalize_key, split_nmcli)

# Prefixes of each field in English and in Spanish (including how they look when the console broke the accents).
WIFI_KEYS = {
    "state": ("state", "estado"),
    "ssid": ("ssid",),
    "authentication": ("authentication", "autenticac"),
    "cipher": ("cipher", "cifrado"),
    "signal": ("signal", "senal", "seal"),
    "rssi": ("rssi",),
    "channel": ("channel", "canal"),
    "band": ("band",),
    "radio": ("radiotype", "tipoderadio"),
    "rx": ("receiverate", "velocidadderecep"),
    "tx": ("transmitrate", "velocidaddetrans"),
}


def field_of(key: str) -> Optional[str]:
    normalized = normalize_key(key)
    if normalized in ("bssid", "apbssid"):
        return None
    for field, prefixes in WIFI_KEYS.items():
        if field == "ssid":
            if normalized == "ssid":
                return field
        elif any(normalized.startswith(prefix) for prefix in prefixes):
            return field
    return None


def parse_netsh_interfaces(text: str) -> dict:
    """Connected Wi-Fi interface in 'netsh wlan show interfaces' (Windows, in Spanish or English)."""
    blocks, current = [], {}
    for key, value in key_values(text):
        if normalize_key(key) in ("name", "nombre") and current:
            blocks.append(current)
            current = {}
        field = field_of(key)
        if field and field not in current:
            current[field] = value
    if current:
        blocks.append(current)
    connected = [b for b in blocks if normalize_key(b.get("state", "")).startswith(("connected", "conectado"))]
    block = (connected or [b for b in blocks if b.get("ssid")] or [{}])[0]
    if not block.get("ssid"):
        return {}

    channel = first_number(block.get("channel", ""))
    signal_pct = first_number(block.get("signal", ""))
    rssi = first_number(block.get("rssi", ""))
    return {
        "ssid": block["ssid"][:64],
        "authentication": authentication_of(block.get("authentication", ""), block.get("cipher", "")),
        "cipher": cipher_of(block.get("cipher", "")),
        "signalPercent": int(signal_pct) if signal_pct is not None else None,
        "signalDbm": int(rssi) if rssi is not None else (int(signal_pct / 2 - 100) if signal_pct is not None else None),
        "channel": int(channel) if channel else None,
        "band": band_of(block.get("band", ""), int(channel) if channel else None),
        "radioType": block.get("radio") or None,
        "rxRateMbps": first_number(block.get("rx", "")),
        "txRateMbps": first_number(block.get("tx", "")),
    }


def parse_netsh_networks(text: str) -> list[tuple[str, int]]:
    """(network name, channel) of each access point in 'netsh wlan show networks mode=bssid'."""
    found, ssid = [], ""
    for key, value in key_values(text):
        normalized = normalize_key(key)
        if normalized == "ssid":  # "SSID 1 : Mi red" (the digits are removed when normalizing)
            ssid = value
        elif field_of(key) == "channel":
            channel = first_number(value)
            if channel:
                found.append((ssid, int(channel)))
    return found


def parse_nmcli(text: str) -> tuple[dict, list[tuple[str, int]]]:
    """Output of 'nmcli -t -f ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE dev wifi list' (Linux)."""
    info, networks = {}, []
    for line in text.splitlines():
        parts = split_nmcli(line)
        if len(parts) < 7:
            continue
        active, ssid, chan, freq, signal, security, rate = parts[:7]
        channel = int(chan) if chan.isdigit() else None
        if channel:
            networks.append((ssid, channel))
        if active.lower() in ("yes", "sí", "si") and not info:
            signal_pct = first_number(signal)
            freq_mhz = first_number(freq)
            info = {
                "ssid": ssid,
                "authentication": authentication_of(security or "OPEN"),
                "cipher": None,
                "signalPercent": int(signal_pct) if signal_pct is not None else None,
                "signalDbm": int(signal_pct / 2 - 100) if signal_pct is not None else None,
                "channel": channel,
                "band": band_of(f"{freq_mhz / 1000:.1f}" if freq_mhz else "", channel),
                "radioType": None,
                "rxRateMbps": first_number(rate),
                "txRateMbps": None,
            }
    return info, networks


def neighbors_on_channel(networks: list[tuple[str, int]], ssid: str, channel: Optional[int]) -> tuple[int, int]:
    """(neighbouring networks on the same channel, neighbouring networks in total); the access points of your own network
    are not counted."""
    others = [(name, ch) for name, ch in networks if name != ssid]
    return sum(1 for _, ch in others if ch == channel), len({name for name, _ in others})


MAX_CHANNELS = 60


def channel_counts(networks: list[tuple[str, int]], ssid: str) -> list[dict]:
    """How many neighbouring access points (not counting those of your own network) use each channel, from lowest to
    highest. With this the AI recommends which channel to move the router to for less interference."""
    counts: dict[int, int] = {}
    for name, channel in networks:
        if name != ssid and 0 < channel <= 196:
            counts[channel] = counts.get(channel, 0) + 1
    return [{"channel": channel, "networks": count} for channel, count in sorted(counts.items())][:MAX_CHANNELS]


LOCATION_HINT = ("location", "ubicaci")


def wifi_info() -> dict:
    if IS_WINDOWS:
        text = run_command(["netsh", "wlan", "show", "interfaces"])
        info = parse_netsh_interfaces(text)
        if not info and any(hint in text.lower() for hint in LOCATION_HINT):
            info = {"note": "LOCATION_PERMISSION"}
        networks = parse_netsh_networks(run_command(["netsh", "wlan", "show", "networks", "mode=bssid"]))
    else:
        info, networks = parse_nmcli(run_command(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE", "dev", "wifi", "list"]))
    if info.get("ssid"):
        same, total = neighbors_on_channel(networks, info["ssid"], info.get("channel"))
        info["neighborsSameChannel"], info["neighborsTotal"] = same, total
        info["channelCounts"] = channel_counts(networks, info["ssid"])
    return info


# -------------------------------------------------------------------------------------------- local network

IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"


def parse_route_print(text: str) -> Optional[str]:
    """Gateway with the lowest metric in 'route print -4 0.0.0.0' (Windows)."""
    routes = re.findall(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+{IPV4}\s+{IPV4}\s+(\d+)", text, re.MULTILINE)
    return min(routes, key=lambda r: int(r[2]))[0] if routes else None


def parse_proc_route(text: str) -> Optional[str]:
    """Gateway in /proc/net/route (Linux): destination 00000000, address in little-endian hexadecimal."""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
            return socket.inet_ntoa(int(parts[2], 16).to_bytes(4, "little"))
    return None


def default_gateway() -> Optional[str]:
    if IS_WINDOWS:
        return parse_route_print(run_command(["route", "print", "-4", "0.0.0.0"]))
    return parse_proc_route(read_file("/proc/net/route"))


def local_ip() -> Optional[str]:
    """IP of this device on the home network. A 'connected' UDP socket sends no packet."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(INTERNET_TARGET)
            return sock.getsockname()[0]
        except OSError:
            return None


MAC = r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"


def parse_neighbors(text: str) -> dict[str, str]:
    """IP -> MAC from the ARP table ('arp -a' on Windows or /proc/net/arp on Linux)."""
    table = {}
    for line in text.splitlines():
        match = re.search(rf"{IPV4}\s+(?:\S+\s+){{0,2}}?{MAC}", line)
        if not match:
            continue
        ip, mac = match.group(1), match.group(2).lower().replace("-", ":")
        if mac == "00:00:00:00:00:00" or not is_unicast(mac):
            continue
        table[ip] = mac
    return table


def is_unicast(mac: str) -> bool:
    """Discards broadcast and multicast (the least significant bit of the first byte set)."""
    return not int(mac.split(":")[0], 16) & 1


def same_subnet(ips: dict[str, str], own_ip: str, prefix: int = 24) -> dict[str, str]:
    network = ipaddress.ip_network(f"{own_ip}/{prefix}", strict=False)
    return {ip: mac for ip, mac in ips.items()
            if ipaddress.ip_address(ip) in network and ipaddress.ip_address(ip) != network.broadcast_address}


# Up to 1.9 the agent assumed the network was a /24 (254 addresses) and did not see the devices with an IP outside
# that piece: on big networks (universities, companies) two laptops side by side can have 10.20.5.40 and 10.20.7.12.
# Since 2.0.0 the real mask is read; so as not to flood a huge network, at most the 1022 surrounding addresses (/22)
# are woken up. Whatever is already in the ARP table is accepted with the real mask.
DEFAULT_PREFIX = 24
WIDEST_WAKE_PREFIX = 22


def parse_ipconfig_prefix(text: str, own_ip: str) -> Optional[int]:
    """Mask of the interface with ``own_ip`` in 'ipconfig' (Windows, in any language): the first line after the IP whose
    value is a valid mask (255.x.x.x)."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(rf"(?<![\d.]){re.escape(own_ip)}(?![\d.])", line):
            continue
        for following in lines[index + 1:index + 6]:
            value = following.split(":", 1)[-1].strip()
            if re.fullmatch(r"255\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
                try:
                    return ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen
                except ValueError:
                    return None
        return None
    return None


def parse_ip_addr_prefix(text: str, own_ip: str) -> Optional[int]:
    """Prefix of ``own_ip`` in 'ip -o -4 addr show' (Linux): 'inet 10.20.5.40/21 brd ...'."""
    match = re.search(rf"inet {re.escape(own_ip)}/(\d{{1,2}})\b", text)
    return int(match.group(1)) if match and 8 <= int(match.group(1)) <= 32 else None


def network_prefix(own_ip: Optional[str]) -> int:
    """The real prefix of the network of this computer; /24 if the system does not say."""
    if not own_ip:
        return DEFAULT_PREFIX
    if IS_WINDOWS:
        found = parse_ipconfig_prefix(run_command(["ipconfig"]), own_ip)
    else:
        found = parse_ip_addr_prefix(run_command(["ip", "-o", "-4", "addr", "show"]), own_ip)
    return found if found and 8 <= found <= 30 else DEFAULT_PREFIX


def wake_neighbors(own_ip: str, prefix: int = DEFAULT_PREFIX) -> None:
    """An empty datagram to port 9 (discard) of each address of the network makes the system ask over ARP who has it,
    and so the ARP table fills with the devices that are on, even if they do not answer ping. On a network bigger
    than /22 only the surrounding addresses are woken up (see WIDEST_WAKE_PREFIX)."""
    network = ipaddress.ip_network(f"{own_ip}/{max(prefix, WIDEST_WAKE_PREFIX)}", strict=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for host in network.hosts():
            try:
                sock.sendto(b"", (str(host), 9))
            except OSError:
                pass


# Maker from the first 3 bytes of the MAC (the OUI, which the IEEE assigns to each maker). It lets the user recognise
# «an Apple device» or «a Samsung device» without the MAC leaving the computer. It is a list of the most common makers
# in a home; if the OUI is not there, no maker is sent (it shows as "unidentified device").
OUI_VENDORS = {
    "fcfbfb": "Apple", "a4c361": "Apple", "d0817a": "Apple", "f0d1a9": "Apple", "3c0754": "Apple", "a85c2c": "Apple",
    "ac1f74": "Apple", "88665a": "Apple", "f4f15a": "Apple", "9027e4": "Apple", "e0accb": "Apple", "dca904": "Apple",
    "a4b197": "Apple", "d49a20": "Apple", "7cd1c3": "Apple", "609217": "Apple", "8866a5": "Apple", "f0766f": "Apple",
    "c869cd": "Apple", "04d3cf": "Apple", "8c8590": "Apple", "a860b6": "Apple", "2c6134": "Apple",
    "ecfabc": "Samsung", "8425db": "Samsung", "f409d8": "Samsung", "5001bb": "Samsung", "bc1485": "Samsung",
    "e8508b": "Samsung", "a02bb8": "Samsung", "34231f": "Samsung", "c87e75": "Samsung", "d0667b": "Samsung",
    "8c7712": "Samsung", "1c62b8": "Samsung", "5056bf": "Samsung", "bc8ccd": "Samsung", "0023d7": "Samsung",
    "fcc734": "Samsung", "b8d9ce": "Samsung", "78f882": "Samsung",
    "286c07": "Xiaomi", "64b473": "Xiaomi", "f8a2d6": "Xiaomi", "acc1ee": "Xiaomi", "2082c0": "Xiaomi",
    "7c1dd9": "Xiaomi", "ac898c": "Xiaomi", "9c99a0": "Xiaomi", "3480b3": "Xiaomi", "d4970b": "Xiaomi",
    "50ec50": "Xiaomi", "a09f10": "Xiaomi", "fc64ba": "Xiaomi",
    "48e1e9": "Huawei", "70723c": "Huawei", "e8089f": "Huawei", "c40528": "Huawei", "00e0fc": "Huawei",
    "d8490b": "Huawei", "10b1f8": "Huawei", "ac4e91": "Huawei", "b4cd27": "Huawei", "24692a": "Huawei",
    "e0247f": "Honor", "80a359": "Honor",
    "f0d7aa": "Motorola", "ccc3ea": "Motorola", "40786a": "Motorola",
    "6c5697": "Lenovo", "70f087": "Lenovo",
    "c4f561": "Oppo", "d4a148": "Oppo",
    "94652d": "OnePlus", "64a2f9": "OnePlus",
    "3c28a6": "Vivo", "381d14": "Vivo",
    "10682b": "Realme",
    "f8a9d0": "LG", "d013fd": "LG", "a816b2": "LG", "00e091": "LG",
    "3c5ab4": "Google", "f4f5e8": "Google", "1c53f9": "Google", "d8eb97": "Google", "48d6d5": "Google",
    "1844e3": "Google", "6466b3": "Google", "9cfc01": "Google", "e4f042": "Google", "f4039a": "Google",
    "fc65de": "Amazon", "44650d": "Amazon", "68543d": "Amazon", "ac63be": "Amazon", "f0272d": "Amazon",
    "f8f005": "Amazon", "0c47c9": "Amazon", "40b4cd": "Amazon", "50dce7": "Amazon", "8871e5": "Amazon",
    "5c628b": "TP-Link", "f4ec38": "TP-Link", "c006c3": "TP-Link", "503eaa": "TP-Link", "d80d17": "TP-Link",
    "ec086b": "TP-Link", "a42bb0": "TP-Link", "9c5322": "TP-Link", "60a4b7": "TP-Link", "1c61b4": "TP-Link",
    "003192": "TP-Link",
    "c4e90a": "Mercusys",
    "d8070b": "Tenda", "c83a35": "Tenda",
    "ec2280": "D-Link", "1cbdb9": "D-Link",
    "9cd36d": "Netgear", "2cb05d": "Netgear",
    "04d9f5": "Asus", "88d7f6": "Asus", "2c4d54": "Asus",
    "788a20": "Ubiquiti", "fcecda": "Ubiquiti", "e063da": "Ubiquiti",
    "4c5e0c": "MikroTik", "cc2de0": "MikroTik",
    "002674": "ZTE", "4c09b4": "ZTE",
    "341513": "Technicolor",
    "84a8e4": "Sagemcom",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "001a11": "Intel", "3c970e": "Intel", "7c7a91": "Intel", "e4a471": "Intel", "a0a8cd": "Intel", "9cb6d0": "Intel",
    "a4c3f0": "Intel", "9c305b": "Intel",
    "f8e43b": "Dell", "f8bc12": "Dell",
    "3ca82a": "HP", "308d99": "HP",
    "001a4d": "Gigabyte",
    "d8bbc1": "Microsoft", "001ddf": "Microsoft", "582f40": "Microsoft", "7ced8d": "Microsoft",
    "c83f26": "Sony", "e89309": "Sony", "a8e3ee": "Sony", "fc0fe6": "Sony", "78c881": "Sony",
    "001315": "Nintendo", "0009bf": "Nintendo", "e0e751": "Nintendo",
    "cc6da0": "Roku", "b83e59": "Roku",
    "b8278a": "Sonos", "5cae8b": "Sonos",
    "a020a6": "Espressif", "246f28": "Espressif", "8caab5": "Espressif", "d8f15b": "Espressif",
    "bcff4d": "Espressif",
    "d4a651": "Tuya", "68572d": "Tuya",
    "4419b6": "Hikvision",
    "bc325f": "Dahua",
    "9c8ecd": "Reolink",
    "e84e06": "Realtek",
    "000c29": "VMware", "005056": "VMware",
    "080027": "VirtualBox",
    "70b3d5": "Cámara IP",
    "001788": "Philips Hue", "ecb5fa": "Philips Hue",
}


def vendor_of(mac: str) -> Optional[str]:
    """Maker of the device from the OUI of its MAC, or None if it is not in the list."""
    oui = mac.lower().replace(":", "").replace("-", "")[:6]
    return OUI_VENDORS.get(oui)


def is_private_mac(mac: str) -> bool:
    """«Private» or random MAC: the locally administered bit (the second least significant of the first byte) set.
    Modern phones and tablets (iPhone since iOS 14, Android since version 10) use one like that on each Wi-Fi network
    so they cannot be tracked; that is why their maker cannot be known, but it is almost always a phone or a tablet."""
    return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0b10)


# Suffixes the router or the system add to the name that tell the user nothing.
NAME_SUFFIXES = (".lan", ".home", ".local", ".localdomain", ".home.arpa", ".gateway")


def clean_hostname(raw: Optional[str], ip: str) -> Optional[str]:
    """Leaves the name of the device readable ('iPhone-de-Ana'), or None if the system only returned the IP or nothing."""
    if not raw:
        return None
    name = raw.strip().rstrip(".")
    lowered = name.lower()
    for suffix in NAME_SUFFIXES:
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    # A name that is the IP itself (reverse DNS that returns the address) says nothing.
    if not name or name == ip or re.fullmatch(r"[0-9.]+", name):
        return None
    return name[:63]


def hostname_of(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Name the device announces on the network (as Bluetooth or the Wi-Fi hotspot of a phone show it). It tries reverse
    DNS, NetBIOS on Windows and finally mDNS (used by iPhone, Mac, Chromecast, printers and many TVs); if nobody
    answers in time, it stays without a name."""
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = clean_hostname(socket.gethostbyaddr(ip)[0], ip)
        if name:
            return name
    except (OSError, UnicodeError):
        pass
    finally:
        socket.setdefaulttimeout(previous)
    if IS_WINDOWS:
        name = netbios_name(ip)
        if name:
            return name
    return mdns_name(ip, timeout)


MDNS_GROUP = ("224.0.0.251", 5353)
DNS_PTR = 12


def mdns_query(ip: str) -> bytes:
    """PTR question for the reversed IP (4.3.2.1.in-addr.arpa) with the QU bit, so the device answers directly."""
    reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)  # id 0, consulta normal, 1 pregunta
    return header + dns_name(reverse) + struct.pack("!HH", DNS_PTR, 0x8001)  # PTR type, class IN with the QU bit


def parse_mdns_ptr(data: bytes) -> Optional[str]:
    """First PTR record of the answers of an mDNS packet (the .local name of the device), or None."""
    try:
        _, flags, questions, answers = struct.unpack_from("!HHHH", data, 0)
        if not flags & 0x8000:  # not an answer
            return None
        offset = 12
        for _ in range(questions):
            offset = read_name(data, offset)[1] + 4
        for _ in range(answers):
            offset = read_name(data, offset)[1]
            rtype, _, _, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if rtype == DNS_PTR:
                return read_name(data, offset)[0]
            offset += length
    except (struct.error, IndexError, ValueError):
        pass
    return None


def mdns_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Name of the device over mDNS (Bonjour). It is sent from any port, so the device answers this computer directly and
    port 5353 does not have to be taken."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(mdns_query(ip), MDNS_GROUP)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data, _ = sock.recvfrom(4096)
                name = parse_mdns_ptr(data)
                if name:
                    return clean_hostname(name, ip)
    except OSError:
        pass
    return None


def netbios_name(ip: str) -> Optional[str]:
    """NetBIOS name on Windows ('nbtstat -A ip'): the first <20> or <00> entry of type UNIQUE is the device's."""
    for line in run_command(["nbtstat", "-A", ip], timeout=3).splitlines():
        match = re.match(r"\s*(\S.*?)\s+<(00|20)>\s+UNIQUE", line)
        if match:
            return clean_hostname(match.group(1), ip)
    return None


def mac_fingerprint(mac: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{mac.lower()}".encode()).hexdigest()[:24]


def own_mac() -> Optional[str]:
    import uuid
    node = uuid.getnode()
    if node >> 40 & 1:  # uuid invented a random number: there is no MAC
        return None
    return ":".join(f"{node >> shift & 0xff:02x}" for shift in range(40, -1, -8))


try:  # the agent as a package (tests) or as loose scripts (PyInstaller, python wifisense_agent.py)
    from agent import device_discovery as discovery
    from agent import wifi_scan
    from agent import router_sources
    from agent import traffic_capture
    from agent import capture_backends
    from agent import live_monitor
except ImportError:  # pragma: no cover
    import device_discovery as discovery
    import wifi_scan
    import router_sources
    import traffic_capture
    import capture_backends
    import live_monitor

IDENTITY_MAX_AGE = 1800  # what devices announce and their ports change little: it is checked every 30 minutes
_identity_cache: dict = {"at": 0.0, "macs": frozenset(), "by_mac": {}}


def identities(by_ip: dict[str, str], own_ip: str, gateway: Optional[str], now: Optional[float] = None,
               identify=None) -> dict[str, dict]:
    """Name, model and suggested kind of each MAC. The network is asked again every 30 minutes or when a new device shows
    up (in identify mode the agent reports every minute and must not scan every time)."""
    now = time.time() if now is None else now
    identify = identify or discovery.identify
    macs = frozenset(by_ip.values())
    cache = _identity_cache
    if now - cache["at"] > IDENTITY_MAX_AGE or not macs <= cache["macs"]:
        found = identify(list(by_ip), own_ip, gateway)
        cache.update(at=now, macs=macs, by_mac={mac: found.get(ip, {}) for ip, mac in by_ip.items()})
    return cache["by_mac"]


def devices(own_ip: Optional[str], salt: str, wait: float = 2.0, gateway: Optional[str] = None) -> list[dict]:
    """Devices connected to the network (this one included), as {fingerprint, maker, name}. The fingerprint is a salted
    SHA-256: the MAC does not leave the computer. The maker comes from the OUI of the MAC and the name of the device
    (as in Bluetooth or the Wi-Fi hotspot) from what it announces, from its DHCP request or from reverse DNS, NetBIOS
    or mDNS; any of them can be missing. If the MAC is private (random) it is flagged, because it is almost always a
    phone or a tablet."""
    if not own_ip:
        return []
    prefix = network_prefix(own_ip)
    wake_neighbors(own_ip, prefix)
    time.sleep(wait)
    table = run_command(["arp", "-a"]) if IS_WINDOWS else read_file("/proc/net/arp")
    by_ip = same_subnet(parse_neighbors(table), own_ip, prefix)
    mine = own_mac()
    if mine:
        by_ip[own_ip] = mine
    own_name = clean_hostname(socket.gethostname(), own_ip)
    # The names are resolved in parallel because each one can take up to a second.
    with ThreadPoolExecutor(max_workers=min(len(by_ip), 32) or 1) as pool:
        names = dict(zip(by_ip, pool.map(hostname_of, by_ip)))
    # What each device said when asking for an address (DHCP): listened to from the first report and accumulated.
    discovery.DHCP.start()
    dhcp = discovery.DHCP.snapshot()
    try:
        announced = identities(by_ip, own_ip, gateway)
    except Exception as error:  # recognising devices is an extra: if it fails, they are sent as before
        print(f"  aviso: no se pudo identificar los equipos: {error}", file=sys.stderr)
        announced = {}
    from_router = router_names(gateway, [ip for ip in by_ip if ip not in (own_ip, gateway)])
    found = []
    for ip, mac in sorted(by_ip.items(), key=lambda item: item[1]):
        found.append(describe_device(ip, mac, salt, own_ip, gateway, own_name if ip == own_ip else names.get(ip),
                                     announced.get(mac, {}), dhcp.get(mac, {}), from_router.get(ip)))
    return found[:MAX_DEVICES]


def router_names(gateway: Optional[str], ips: list[str], source_factory=None) -> dict[str, str]:
    """Names the router itself knows (its DNS, without a password). If the router does not answer, there are no names
    from there."""
    if not gateway or not ips:
        return {}
    source = (source_factory or router_sources.source_for)(gateway)
    if source is None:
        return {}
    try:
        return {ip: name for ip, name in source.names(ips).items() if clean_hostname(name, ip)}
    except Exception as error:  # the router may have no DNS: it is an extra
        print(f"  aviso: el router no respondió nombres: {error}", file=sys.stderr)
        return {}


def same_name(first: Optional[str], second: Optional[str]) -> bool:
    """«Portatil-de-Ana» and «portatil-de-ana.lan» are the same name."""
    def plain(name: Optional[str]) -> str:
        return re.sub(r"[^a-z0-9]", "", (name or "").lower().split(".")[0])
    return bool(plain(first)) and plain(first) == plain(second)


def describe_device(ip: str, mac: str, salt: str, own_ip: str, gateway: Optional[str], hostname: Optional[str],
                    announced: dict, dhcp: Optional[dict] = None, router_name: Optional[str] = None) -> dict:
    """What is sent of a device: its fingerprint (never the MAC), maker, name, model, kind and role. The name comes, in
    this order, from what it announces over mDNS or UPnP, from what it said when asking for an address (DHCP), from
    the DNS of the router or from the network (reverse DNS, NetBIOS or mDNS). Since 2.0.0 it says where it came from
    (nameSource): ANNOUNCED (the device said it), ROUTER (the router said it), DNS (the network said it) or CONFIRMED
    (the device and the router say the same). The maker from the MAC is an estimate and is never presented as the
    name."""
    dhcp = dhcp or {}
    device = {"id": mac_fingerprint(mac, salt)}
    vendor = vendor_of(mac)
    private = not vendor and is_private_mac(mac)
    if vendor:
        device["vendor"] = vendor
    elif private:
        device["privateMac"] = True  # almost always a phone or tablet with the random MAC turned on
    # The name the device announces over mDNS or UPnP ("iPhone de Ana", "Sala TV") is the one the person gave it.
    own_name = announced.get("name") or clean_hostname(dhcp.get("name"), ip)
    from_router = clean_hostname(router_name, ip)
    name = own_name or from_router or hostname
    if name:
        device["name"] = name[:63]
        if own_name and from_router and same_name(own_name, from_router):
            device["nameSource"] = "CONFIRMED"
        elif own_name:
            device["nameSource"] = "ANNOUNCED"
        elif from_router:
            device["nameSource"] = "ROUTER"
        else:
            device["nameSource"] = "DNS"
    if announced.get("model"):
        device["model"] = announced["model"][:63]
    if ip == own_ip:
        device["role"], device["kind"] = "SELF", "COMPUTER"
    elif ip == gateway:
        device["role"] = "ROUTER"
    else:
        hints = announced.get("kinds", []) + [k for k in [discovery.dhcp_kind(dhcp.get("vendorClass"))] if k]
        kind = discovery.decide_kind(name, announced.get("model"), vendor, hints, private)
        if kind:
            device["kind"] = kind
    return device


# --------------------------------------------------------------------------------------------- latency and ports

def connect_time(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    """Milliseconds until the destination answers a TCP connection. A refusal is also an answer (it measures the round
    trip all the same); only silence counts as a loss."""
    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            pass
        except OSError:
            return None
    return (time.perf_counter() - start) * 1000


def summarize(samples: list[Optional[float]]) -> dict:
    ok = [s for s in samples if s is not None]
    loss = round(100 * (len(samples) - len(ok)) / len(samples), 1) if samples else 100.0
    if not ok:
        return {"latencyMs": None, "jitterMs": None, "packetLossPct": loss}
    jitter = statistics.mean(abs(b - a) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else 0.0
    return {"latencyMs": round(statistics.median(ok), 1), "jitterMs": round(jitter, 1), "packetLossPct": loss}


def measure(host: str, port: int, count: int = SAMPLES, pause: float = 0.2,
            probe: Callable[[str, int], Optional[float]] = connect_time) -> dict:
    samples = []
    for i in range(count):
        samples.append(probe(host, port))
        if i < count - 1:
            time.sleep(pause)
    return summarize(samples)


def open_ports(host: str, ports=ROUTER_PORTS, timeout: float = 0.8) -> list[int]:
    def is_open(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        return [port for port, ok in zip(ports, pool.map(is_open, ports)) if ok]


# ------------------------------------------------------------------------------------------------------ traffic
# Counters of the operating system (no capture programs): bytes and packets of the network card and packets per
# protocol. The agent sends how much they changed since the previous report. Only the sensor of a team network stores
# them; they are the traffic of THIS computer, not of the whole network (only the router sees that).
TRAFFIC_MAX_AGE = 3600          # if the previous report is older (computer turned off), that time is not mixed in
WRAP_32 = 2 ** 32
SKIP_INTERFACES = ("lo", "docker", "veth", "br-", "virbr", "vmnet", "tun", "tailscale")


def parse_proc_net_dev(text: str) -> dict[str, int]:
    """Bytes and packets from /proc/net/dev (Linux), adding up the real cards (no loopback nor bridges)."""
    totals = {"bytes.in": 0, "bytes.out": 0, "packets.in": 0, "packets.out": 0}
    found = False
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        values = data.split()
        if len(values) < 10 or name.startswith(SKIP_INTERFACES):
            continue
        found = True
        totals["bytes.in"] += int(values[0])
        totals["packets.in"] += int(values[1])
        totals["bytes.out"] += int(values[8])
        totals["packets.out"] += int(values[9])
    return totals if found else {}


def parse_proc_net_snmp(snmp: str, snmp6: str = "") -> dict[str, int]:
    """Packets per protocol from /proc/net/snmp and /proc/net/snmp6 (Linux)."""
    wanted = {"Tcp": ("InSegs", "OutSegs", "TCP"), "Udp": ("InDatagrams", "OutDatagrams", "UDP"),
              "Icmp": ("InMsgs", "OutMsgs", "ICMP")}
    counters: dict[str, int] = {}
    lines = snmp.splitlines()
    for header, values in zip(lines, lines[1:]):
        prefix = header.split(":", 1)[0]
        if prefix not in wanted or not values.startswith(prefix + ":") or header == values:
            continue
        row = dict(zip(header.split()[1:], values.split()[1:]))
        received, sent, protocol = wanted[prefix]
        if received in row and sent in row and row[received].isdigit():
            counters[f"{protocol}.in4"] = int(row[received])
            counters[f"{protocol}.out4"] = int(row[sent])
    for line in snmp6.splitlines():
        parts = line.split()
        names = {"Udp6InDatagrams": "UDP.in6", "Udp6OutDatagrams": "UDP.out6",
                 "Icmp6InMsgs": "ICMP.in6", "Icmp6OutMsgs": "ICMP.out6"}
        if len(parts) == 2 and parts[0] in names and parts[1].isdigit():
            counters[names[parts[0]]] = int(parts[1])
    return counters


def linux_counters() -> dict[str, int]:
    counters = parse_proc_net_dev(read_file("/proc/net/dev"))
    counters.update(parse_proc_net_snmp(read_file("/proc/net/snmp"), read_file("/proc/net/snmp6")))
    return counters


def windows_counters() -> dict[str, int]:
    """Windows counters through the IP Helper API (iphlpapi.dll), the same in any language of the system."""
    import ctypes
    from ctypes import wintypes

    u64, enum = ctypes.c_uint64, ctypes.c_int

    class MibIfRow2(ctypes.Structure):  # MIB_IF_ROW2 of netioapi.h: 1352 bytes
        _fields_ = [("InterfaceLuid", u64), ("InterfaceIndex", wintypes.ULONG), ("InterfaceGuid", ctypes.c_ubyte * 16),
                    ("Alias", ctypes.c_wchar * 257), ("Description", ctypes.c_wchar * 257),
                    ("PhysicalAddressLength", wintypes.ULONG), ("PhysicalAddress", ctypes.c_ubyte * 32),
                    ("PermanentPhysicalAddress", ctypes.c_ubyte * 32), ("Mtu", wintypes.ULONG),
                    ("Type", wintypes.ULONG), ("TunnelType", enum), ("MediaType", enum),
                    ("PhysicalMediumType", enum), ("AccessType", enum), ("DirectionType", enum),
                    ("Flags", ctypes.c_ubyte), ("OperStatus", enum), ("AdminStatus", enum),
                    ("MediaConnectState", enum), ("NetworkGuid", ctypes.c_ubyte * 16), ("ConnectionType", enum),
                    ("TransmitLinkSpeed", u64), ("ReceiveLinkSpeed", u64)]
        _fields_ += [(name, u64) for name in (
            "InOctets", "InUcastPkts", "InNUcastPkts", "InDiscards", "InErrors", "InUnknownProtos", "InUcastOctets",
            "InMulticastOctets", "InBroadcastOctets", "OutOctets", "OutUcastPkts", "OutNUcastPkts", "OutDiscards",
            "OutErrors", "OutUcastOctets", "OutMulticastOctets", "OutBroadcastOctets", "OutQLen")]

    class MibTcpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "RtoAlgorithm", "RtoMin", "RtoMax", "MaxConn", "ActiveOpens", "PassiveOpens", "AttemptFails",
            "EstabResets", "CurrEstab", "InSegs", "OutSegs", "RetransSegs", "InErrs", "OutRsts", "NumConns")]

    class MibUdpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "NumAddrs")]

    class MibIcmpStats(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in (
            "Msgs", "Errors", "DestUnreachs", "TimeExcds", "ParmProbs", "SrcQuenchs", "Redirects", "Echos",
            "EchoReps", "Timestamps", "TimestampReps", "AddrMasks", "AddrMaskReps")]

    class MibIcmp(ctypes.Structure):
        _fields_ = [("In", MibIcmpStats), ("Out", MibIcmpStats)]

    if ctypes.sizeof(MibIfRow2) != 1352:  # a badly described structure would read garbage: better to send nothing
        return {}
    api = ctypes.WinDLL("iphlpapi.dll")
    counters: dict[str, int] = {}

    table = ctypes.c_void_p()
    if api.GetIfTable2(ctypes.byref(table)) == 0:
        try:
            count = ctypes.cast(table, ctypes.POINTER(wintypes.ULONG))[0]
            rows = ctypes.cast(table.value + 8, ctypes.POINTER(MibIfRow2 * count)).contents
            # Physical cards that are connected (no filters nor virtual ones); the Wi-Fi if there is one, if not the cable.
            physical = [row for row in rows if row.Flags & 1 and not row.Flags & 2 and row.OperStatus == 1]
            chosen = [row for row in physical if row.Type == 71] or [row for row in physical if row.Type == 6]
            if chosen:
                counters["bytes.in"] = sum(row.InOctets for row in chosen)
                counters["bytes.out"] = sum(row.OutOctets for row in chosen)
                counters["packets.in"] = sum(row.InUcastPkts + row.InNUcastPkts for row in chosen)
                counters["packets.out"] = sum(row.OutUcastPkts + row.OutNUcastPkts for row in chosen)
        finally:
            api.FreeMibTable(table)

    for family, suffix in ((2, "4"), (23, "6")):  # AF_INET, AF_INET6; these counters are 32-bit
        tcp, udp = MibTcpStats(), MibUdpStats()
        if api.GetTcpStatisticsEx(ctypes.byref(tcp), family) == 0:
            counters[f"TCP.in{suffix}"], counters[f"TCP.out{suffix}"] = tcp.InSegs, tcp.OutSegs
        if api.GetUdpStatisticsEx(ctypes.byref(udp), family) == 0:
            counters[f"UDP.in{suffix}"], counters[f"UDP.out{suffix}"] = udp.InDatagrams, udp.OutDatagrams
    icmp = MibIcmp()
    if api.GetIcmpStatistics(ctypes.byref(icmp)) == 0:
        counters["ICMP.in4"], counters["ICMP.out4"] = icmp.In.Msgs, icmp.Out.Msgs
    return counters


def traffic_counters() -> dict[str, int]:
    """The current counters; empty if the system does not give them (then the report goes without traffic)."""
    try:
        return windows_counters() if IS_WINDOWS else linux_counters()
    except (OSError, AttributeError, ValueError) as error:
        print(f"  aviso: no se pudo leer el tráfico: {error}", file=sys.stderr)
        return {}


def counter_delta(now: int, before: int, name: str) -> Optional[int]:
    """How much a counter advanced. The protocol counters of Windows are 32-bit and wrap around; a counter that really
    goes back (the computer restarted) does not give a reliable value."""
    if now >= before:
        return now - before
    if not name.startswith("bytes") and not name.startswith("packets") and before - now > WRAP_32 // 2:
        return now + WRAP_32 - before
    return None


def traffic_fields(previous: Optional[dict], current: dict, now: Optional[float] = None) -> dict:
    """Fields of the report with the traffic since the previous report; empty the first time or if something does not
    add up."""
    now = time.time() if now is None else now
    if not previous or not current or now - previous.get("at", 0) > TRAFFIC_MAX_AGE:
        return {}
    counters = previous.get("counters", {})
    deltas: dict[str, int] = {}
    for name, value in current.items():
        if name in counters:
            delta = counter_delta(value, counters[name], name)
            if delta is None:
                return {}
            deltas[name] = delta
    fields: dict = {}
    if all(f"{kind}.{way}" in deltas for kind in ("bytes", "packets") for way in ("in", "out")):
        fields["trafficBytes"] = min(deltas["bytes.in"] + deltas["bytes.out"], 10 ** 13)
        fields["trafficPackets"] = min(deltas["packets.in"] + deltas["packets.out"], 10 ** 11)
    protocols = []
    for protocol in ("TCP", "UDP", "ICMP"):
        values = [value for name, value in deltas.items() if name.startswith(protocol + ".")]
        if values:
            protocols.append({"protocol": protocol, "packets": min(sum(values), 10 ** 11)})
    if protocols:
        fields["protocolPackets"] = protocols
    return fields


def traffic_state_path() -> Path:
    return config_path().with_name("traffic.json")


def load_traffic_state(path: Optional[Path] = None) -> Optional[dict]:
    try:
        return json.loads((path or traffic_state_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_traffic_state(counters: dict, path: Optional[Path] = None, now: Optional[float] = None,
                       network: Optional[str] = None) -> None:
    """Keeps the counters of the last report sent. If a send fails they are not kept, and the next report also covers
    that interval. ``network`` (the start of the key) avoids mixing the traffic of two networks when the computer
    changes Wi-Fi."""
    path = path or traffic_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"at": time.time() if now is None else now, "counters": counters,
                                    "network": network}), encoding="utf-8")
    except OSError as error:
        print(f"  aviso: no se pudo guardar el tráfico: {error}", file=sys.stderr)


# ------------------------------------------------------------------------------------------------------ reporte

def collect(salt: str) -> dict:
    """Measures everything in parallel (about 5 seconds) and builds the report that is sent."""
    own_ip, gateway = local_ip(), default_gateway()
    results: dict = {}

    def task(name: str, fn: Callable[[], object]) -> threading.Thread:
        def target():
            try:
                results[name] = fn()
            except Exception as error:  # a measurement that fails must not prevent sending the others
                results[name] = None
                print(f"  aviso: no se pudo medir {name}: {error}", file=sys.stderr)
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    threads = [task("wifi", wifi_info), task("internet", lambda: measure(*INTERNET_TARGET)),
               task("devices", lambda: devices(own_ip, salt, gateway=gateway))]
    if gateway:
        threads += [task("router", lambda: measure(gateway, 80, count=5)), task("ports", lambda: open_ports(gateway))]
    for thread in threads:
        thread.join(timeout=60)
    return build_report(results.get("wifi") or {}, results.get("internet") or summarize([]),
                        results.get("router"), results.get("devices") or [], results.get("ports") or [])


def build_report(wifi: dict, internet: dict, router: Optional[dict], found_devices: list[dict],
                 ports: list[int]) -> dict:
    # Compatibility: the previous backend understands deviceHashes (a list); the new version devices (with maker).
    device_hashes = [device["id"] for device in found_devices]
    report = {
        "agentVersion": AGENT_VERSION,
        "platform": platform.system()[:20] or "desconocido",
        "ssid": wifi.get("ssid"),
        "authentication": wifi.get("authentication", "UNKNOWN"),
        "cipher": wifi.get("cipher"),
        "band": wifi.get("band"),
        "channel": wifi.get("channel"),
        "signalDbm": wifi.get("signalDbm"),
        "signalPercent": wifi.get("signalPercent"),
        "rxRateMbps": wifi.get("rxRateMbps"),
        "txRateMbps": wifi.get("txRateMbps"),
        "neighborsSameChannel": wifi.get("neighborsSameChannel"),
        "neighborsTotal": wifi.get("neighborsTotal"),
        "channelCounts": wifi.get("channelCounts") or None,
        "wifiNote": wifi.get("note"),
        "latencyMs": internet.get("latencyMs"),
        "jitterMs": internet.get("jitterMs"),
        "packetLossPct": internet.get("packetLossPct"),
        "gatewayLatencyMs": (router or {}).get("latencyMs"),
        "deviceCount": len(device_hashes),
        "deviceHashes": device_hashes,
        "devices": found_devices or None,
        "openPorts": ports,
    }
    return {key: value for key, value in report.items() if value is not None}


# ------------------------------------------------------------------------------------------------- configuration

def config_path() -> Path:
    base = os.environ.get("APPDATA") if IS_WINDOWS else os.environ.get("XDG_CONFIG_HOME")
    return Path(base or Path.home() / ".config") / "WiFiSense" / "agent.json"


def load_config(path: Optional[Path] = None) -> dict:
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    if os.environ.get("WIFISENSE_AGENT_KEY"):
        config["key"] = os.environ["WIFISENSE_AGENT_KEY"]
    if os.environ.get("WIFISENSE_SERVER"):
        config["server"] = os.environ["WIFISENSE_SERVER"]
    config.setdefault("server", DEFAULT_SERVER)
    return config


def save_config(config: dict, path: Optional[Path] = None) -> Path:
    """Stores the configuration only for the current user (permissions 600 on Linux; on Windows the %APPDATA% folder is
    already private to each user)."""
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
    return path


KEY_PATTERN = re.compile(r"^wsa_[A-Za-z0-9_-]{32,64}$")


def validate_server(url: str) -> str:
    """HTTPS only, except on the computer itself (local tests): the key must not travel unencrypted."""
    parsed = urllib.parse.urlparse(url.strip())
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("el servidor debe usar https://")
    if not parsed.hostname:
        raise ValueError("dirección del servidor inválida")
    return f"{parsed.scheme}://{parsed.netloc}"


# ----------------------------------------------------------------------------------------------------- sending

class SendError(Exception):
    def __init__(self, message: str, retry_after: Optional[int] = None, fatal: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.fatal = fatal


def server_detail(error: urllib.error.HTTPError) -> str:
    """The reason the server gives (and the rejected field, if any), to know what to fix."""
    try:
        problem = json.loads(error.read() or b"{}")
    except (OSError, ValueError):
        return ""
    if not isinstance(problem, dict):
        return ""
    parts = [str(problem.get("detail") or "").strip()]
    errors = problem.get("errors")
    if isinstance(errors, dict):
        parts += [f"{field}: {message}" for field, message in errors.items()]
    elif isinstance(errors, list):
        parts += [str(message) for message in errors]
    text = " | ".join(part for part in parts if part)
    return f": {text[:300]}" if text else ""


def send(report: dict, server: str, key: str, opener=urllib.request.urlopen) -> dict:
    request = urllib.request.Request(
        validate_server(server) + REPORT_PATH, data=json.dumps(report).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Key": key,
                 "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise SendError("la clave del agente no es válida o fue revocada; crea una nueva en Mi Wi-Fi > Agente "
                            "y ejecuta 'setup' otra vez", fatal=True)
        if error.code == 429:
            retry = error.headers.get("Retry-After") if error.headers else None
            raise SendError("demasiados reportes seguidos", retry_after=int(retry) if retry and retry.isdigit() else 60)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}")
    except (urllib.error.URLError, OSError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")


# ------------------------------------------------------------------------------------- redes cercanas (1.9.0)

class ScansUnavailable(Exception):
    """The server offers no scans to this key (an older backend, or the key belongs to the sensor of a team network):
    it stops asking until the next report."""


def agent_call(method: str, path: str, server: str, key: str, body: Optional[dict] = None,
               opener=urllib.request.urlopen) -> tuple[int, dict]:
    """Call of the agent to the server with its key; (code, answer). Errors come out as SendError."""
    request = urllib.request.Request(
        validate_server(server) + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-Agent-Key": key,
                 "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            status = getattr(response, "status", 200)
            raw = response.read() or b"{}"
            return status, json.loads(raw) if status != 204 else {}
    except urllib.error.HTTPError as error:
        if error.code in (401, 403, 404, 405):
            raise ScansUnavailable(str(error.code))
        if error.code == 429:
            retry = error.headers.get("Retry-After") if error.headers else None
            raise SendError("demasiadas consultas seguidas", retry_after=int(retry) if retry and retry.isdigit() else 30)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}")
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")


def next_scan(server: str, key: str, opener=urllib.request.urlopen) -> Optional[int]:
    """The number of the scan the user asked for in Mi Wi-Fi, or None if there is none. The server can only ask for a
    scan: the agent never runs orders that come from the server."""
    status, answer = agent_call("GET", NEXT_SCAN_PATH, server, key, opener=opener)
    return scan_id_of(answer) if status == 200 else None


def scan_id_of(answer) -> Optional[int]:
    scan_id = answer.get("scanId") if isinstance(answer, dict) else None
    return scan_id if isinstance(scan_id, int) and not isinstance(scan_id, bool) and scan_id > 0 else None


def run_scan(scan_id: int, server: str, key: str, salt: str, opener=urllib.request.urlopen, scanner=None) -> dict:
    """Scans the nearby networks and delivers the result to the scan ``scan_id``."""
    result = wifi_scan.scan(scan_id, AGENT_VERSION, lambda mac: mac_fingerprint(mac, salt), vendor_of, scanner)
    print(f"  {wifi_scan.summary(result)}")
    try:
        agent_call("POST", SCANS_PATH, server, key, result, opener=opener)
    except (SendError, ScansUnavailable) as error:
        print(f"  No se entregó el escaneo: {error}")
    return result


def wait_watching_scans(seconds: int, server: str, key: str, salt: str, sleep: Callable[[float], None] = time.sleep,
                        clock: Callable[[], float] = time.monotonic, opener=urllib.request.urlopen) -> None:
    """Waits until the next report, asking every 30 seconds whether the user asked to scan the nearby networks (so the
    button of the page answers in less than a minute). A failed question does not change the wait."""
    wait_watching_tasks(seconds, server, key, salt, None, sleep=sleep, clock=clock, opener=opener)


def wait_watching_tasks(seconds: int, server: str, key: str, salt: str, config: Optional[dict],
                        sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                        opener=urllib.request.urlopen) -> None:
    """Waits until the next report, asking every 30 seconds whether there is something to do: a scan of nearby networks
    (Mi Wi-Fi) or, if ``config`` is not None, a technical capture (the sensor of a team network) and whether someone
    opened «En vivo» on the page (2.1.0). A question the server does not offer to this key (404) is not repeated
    until the next report. The live measurement runs apart and does not change this wait."""
    end = clock() + seconds
    asking = {"scans": True, "captures": config is not None, "live": config is not None}
    while True:
        left = end - clock()
        if left <= 0:
            return
        sleep(min(SCAN_POLL_SECONDS, left) if any(asking.values()) else left)
        if not any(asking.values()) or clock() >= end:
            continue
        for kind in ("scans", "captures", "live"):
            if not asking[kind]:
                continue
            try:
                if kind == "scans":
                    scan_id = next_scan(server, key, opener=opener)
                    if scan_id is not None:
                        run_scan(scan_id, server, key, salt, opener=opener)
                elif kind == "captures":
                    task = next_capture(server, key, opener=opener)
                    if task is not None:
                        run_capture_task(task, server, key, config, opener=opener)
                elif not live_running():
                    live = next_live(server, key, opener=opener)
                    if live is not None:
                        start_live(live, server, key, opener=opener)
            except ScansUnavailable:
                asking[kind] = False
            except SendError as error:
                if error.retry_after:
                    sleep(min(error.retry_after, max(end - clock(), 0)))


# ------------------------------------------------------------------------------ technical captures (2.0.0)

def capture_task_of(answer) -> Optional[dict]:
    """The only thing the server can ask for: the number of a capture and its limits (numbers). Anything else, such as a
    command or a path, is ignored: the agent never runs orders that come from the server."""
    if not isinstance(answer, dict):
        return None
    task = {}
    for name in ("captureId", "maxSeconds", "maxPackets", "maxBytes"):
        value = answer.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            task[name] = value
    return task if "captureId" in task else None


def next_capture(server: str, key: str, opener=urllib.request.urlopen) -> Optional[dict]:
    status, answer = agent_call("GET", NEXT_CAPTURE_PATH, server, key, opener=opener)
    return capture_task_of(answer) if status == 200 else None


def run_capture_task(task: dict, server: str, key: str, config: dict, opener=urllib.request.urlopen,
                     backends: Optional[list] = None) -> dict:
    """Does a capture an administrator asked for (if this computer allows it) and delivers only the counts."""
    capture_id = task["captureId"]
    own_ip = local_ip()
    prefixes = [f"{own_ip}/{network_prefix(own_ip)}"] if own_ip else []

    def deliver(result: dict) -> None:
        agent_call("POST", CAPTURES_PATH, server, key, result, opener=opener)

    def ask_stop() -> bool:
        try:
            _status, answer = agent_call("GET", f"{CAPTURES_PATH}/{int(capture_id)}/state", server, key,
                                         opener=opener)
        except ScansUnavailable:
            return True  # the capture no longer exists for this sensor
        return bool(answer.get("stop")) if isinstance(answer, dict) else False

    return traffic_capture.run_capture(task, config, AGENT_VERSION, deliver, ask_stop, own_ip, prefixes,
                                       backends=backends)


# ------------------------------------------------------------------------------- live measurement (2.1.0)

def link_info() -> dict:
    """Signal and link speed of the connected Wi-Fi. A single command, without the list of neighbouring networks: it is
    fast and can be read every 2 seconds."""
    if IS_WINDOWS:
        return parse_netsh_interfaces(run_command(["netsh", "wlan", "show", "interfaces"], timeout=5))
    return parse_nmcli(run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE", "dev", "wifi",
                                    "list"], timeout=5))[0]


def live_sampler() -> "live_monitor.LiveSampler":
    return live_monitor.LiveSampler(traffic_counters, link_info, connect_time, default_gateway(), INTERNET_TARGET)


def next_live(server: str, key: str, opener=urllib.request.urlopen) -> Optional[dict]:
    """Whether someone opened «En vivo» on the page: every how many seconds to measure and for how long. None if nobody."""
    status, answer = agent_call("GET", NEXT_LIVE_PATH, server, key, opener=opener)
    return live_monitor.live_task_of(answer) if status == 200 else None


def send_live(sample: dict, server: str, key: str, opener=urllib.request.urlopen) -> bool:
    """Delivers a sample; True while someone is still watching the page."""
    try:
        _status, answer = agent_call("POST", LIVE_SAMPLES_PATH, server, key, sample, opener=opener)
    except ScansUnavailable as error:  # the key no longer works or the server has no «En vivo»
        raise live_monitor.LiveStopped(str(error))
    return bool(answer.get("keepGoing")) if isinstance(answer, dict) else False


_live_session: dict = {"thread": None}


def live_running() -> bool:
    thread = _live_session["thread"]
    return thread is not None and thread.is_alive()


def start_live(task: dict, server: str, key: str, opener=urllib.request.urlopen,
               sampler: Optional["live_monitor.LiveSampler"] = None) -> threading.Thread:
    """Measures live in a separate thread: the reports, scans and captures keep their own pace."""
    sampler = sampler or live_sampler()

    def target() -> None:
        sent = live_monitor.run_session(task, sampler, lambda sample: send_live(sample, server, key, opener=opener))
        print(time.strftime("[%H:%M:%S] ") + f"En vivo terminado: {sent} muestras enviadas.")

    thread = threading.Thread(target=target, name="wifisense-live", daemon=True)
    _live_session["thread"] = thread
    print(time.strftime("[%H:%M:%S] ") + f"Alguien abrió «En vivo»: midiendo cada {task['sampleSeconds']} s.")
    thread.start()
    return thread


def parse_monitor_mode(text: str) -> Optional[bool]:
    """'Network monitor mode : Supported' of 'netsh wlan show wirelesscapabilities' (Windows 10 or later, in Spanish or
    English). It only tells whether the card declares it: the agent never turns monitor mode on."""
    for key, value in key_values(text):
        if "monitor" not in normalize_key(key):
            continue
        plain = normalize_key(value)
        if plain.startswith(("no", "not")) or "unsupported" in plain:
            return False
        if any(word in plain for word in ("support", "compat", "admit", "si")):
            return True
    return None


def monitor_mode_hint() -> Optional[bool]:
    if not IS_WINDOWS:
        return None
    return parse_monitor_mode(run_command(["netsh", "wlan", "show", "wirelesscapabilities"]))


CAPABILITIES_MAX_AGE = 600
_capabilities_cache: dict = {"at": -CAPABILITIES_MAX_AGE, "value": None, "consent": None}


def agent_capabilities(config: dict, now: Optional[float] = None, backends: Optional[list] = None) -> Optional[dict]:
    """What this computer can do for captures, checked at most every 10 minutes (or when the local permission changes).
    If the check fails, the report goes without capabilities: the server then does not allow capturing."""
    now = time.monotonic() if now is None else now
    consent = traffic_capture.consent_given(config)
    cache = _capabilities_cache
    if cache["value"] is None or now - cache["at"] > CAPABILITIES_MAX_AGE or cache["consent"] != consent:
        try:
            cache.update(at=now, consent=consent,
                         value=traffic_capture.capabilities(config, local_ip(), backends=backends,
                                                            monitor_hint=monitor_mode_hint()))
        except Exception as error:
            print(f"  aviso: no se pudo revisar qué puede capturar este computador: {error}", file=sys.stderr)
            return None
    return cache["value"]


CODE_PATTERN = re.compile(r"^[A-HJKMNP-Z2-9]{8}$")


def normalize_code(text: str) -> Optional[str]:
    """'k7qm 4rzd' or 'K7QM-4RZD' -> 'K7QM-4RZD'; None if it cannot be a code."""
    code = re.sub(r"[\s-]", "", text or "").upper()
    return f"{code[:4]}-{code[4:]}" if CODE_PATTERN.match(code) else None


def pair(code: str, server: str, opener=urllib.request.urlopen) -> dict:
    """Exchanges the short code of Mi Wi-Fi for the key of the agent. Returns {key, prefix, networkName}."""
    normalized = normalize_code(code)
    if not normalized:
        raise SendError("el código tiene 8 letras y números, por ejemplo K7QM-4RZD", fatal=True)
    request = urllib.request.Request(
        validate_server(server) + PAIR_PATH, data=json.dumps({"code": normalized}).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"WiFiSense-Agent/{AGENT_VERSION}"})
    try:
        with opener(request, timeout=30) as response:
            answer = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise SendError("demasiados intentos; espera unos minutos", retry_after=600)
        raise SendError(f"el servidor respondió {error.code}{server_detail(error)}", fatal=error.code == 400)
    except (urllib.error.URLError, OSError) as error:
        raise SendError(f"no se pudo conectar con el servidor ({getattr(error, 'reason', error)})")
    if not KEY_PATTERN.match(str(answer.get("key", ""))):
        raise SendError("el servidor no devolvió una clave válida")
    return answer


# ------------------------------------------------------------------------------------------- varias redes (1.6.0)
#
# A computer can have the code of several networks (for example the two Wi-Fi of a home, or the one of the home and
# the one of the university). Each key is bound to the Wi-Fi the computer was connected to when the code was used, and
# in each report the agent uses the key of the Wi-Fi it is on: if you change Wi-Fi, the agent changes network by
# itself. On a Wi-Fi without a code it sends nothing, so its measurements are not stored as if they were another one's.

def config_networks(config: dict) -> list[dict]:
    """The networks of this computer: [{key, network, ssid}]. It also reads the configuration from before 1.6.0 (a
    single key, without Wi-Fi) and the key from the WIFISENSE_AGENT_KEY environment variable (development)."""
    if os.environ.get("WIFISENSE_AGENT_KEY"):
        return [{"key": os.environ["WIFISENSE_AGENT_KEY"], "network": None, "ssid": None}]
    networks = config.get("networks")
    if isinstance(networks, list):
        return [n for n in networks if isinstance(n, dict) and n.get("key")]
    if config.get("key"):
        return [{"key": config["key"], "network": config.get("network"), "ssid": config.get("ssid")}]
    return []


def choose_network(networks: list[dict], ssid: Optional[str]) -> Optional[dict]:
    """The network the current Wi-Fi belongs to. A key without a known Wi-Fi (installed before 1.6.0, or without location
    permission) works for any Wi-Fi that has no key of its own, and learns it the first time (see learn_ssid). When
    the Wi-Fi cannot be read (cable or permission) it only sends if there is no doubt about which network it is."""
    if ssid:
        for network in networks:
            if network.get("ssid") == ssid:
                return network
    wildcards = [n for n in networks if not n.get("ssid")]
    if len(wildcards) == 1:
        return wildcards[0]
    if not ssid and len(networks) == 1:
        return networks[0]
    return None


def store_networks(networks: list[dict], path: Optional[Path] = None, server: Optional[str] = None) -> Path:
    """Writes the networks (and removes the loose keys of the previous format)."""
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    for old in ("key", "network", "ssid"):
        config.pop(old, None)
    if server:
        config["server"] = validate_server(server)
    config["networks"] = [{"key": n["key"], "network": n.get("network"), "ssid": n.get("ssid")} for n in networks]
    config.setdefault("salt", secrets.token_hex(16))
    return save_config(config, path)


def learn_ssid(network: dict, ssid: Optional[str], path: Optional[Path] = None) -> None:
    """A key without a Wi-Fi gets bound to the first Wi-Fi it is used on (that of its network, in an older install)."""
    if not ssid or network.get("ssid") or os.environ.get("WIFISENSE_AGENT_KEY"):
        return
    networks = config_networks(load_config(path))
    for stored in networks:
        if stored["key"] == network["key"]:
            stored["ssid"] = network["ssid"] = ssid
    store_networks(networks, path)


def forget_network(network: dict, path: Optional[Path] = None) -> list[dict]:
    """Removes a revoked key (for example, the network was disconnected from the page); returns the remaining ones."""
    networks = [n for n in config_networks(load_config(path)) if n["key"] != network["key"]]
    if not os.environ.get("WIFISENSE_AGENT_KEY"):
        store_networks(networks, path)
    return networks


def current_ssid() -> Optional[str]:
    """The Wi-Fi this computer is connected to now; None if it cannot be read (cable or permission)."""
    try:
        return wifi_info().get("ssid")
    except Exception:  # reading the Wi-Fi must never prevent installing
        return None


def save_pairing(answer: dict, server: str, path: Optional[Path] = None, ssid: Optional[str] = None) -> Path:
    """Adds the received key to the networks of this computer, bound to the current Wi-Fi (``ssid``). A new code for the
    same Wi-Fi replaces the previous key of that Wi-Fi; those of other Wi-Fi are kept."""
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    networks = [n for n in config_networks(config) if n.get("ssid") != ssid]
    networks.append({"key": answer["key"], "network": answer.get("networkName"), "ssid": ssid})
    return store_networks(networks, path, server)


def describe_networks(networks: list[dict]) -> str:
    """'«Casa» on Casa-5G; «Laboratorio» on Lab-Redes' to show what this computer measures."""
    parts = [f"«{n.get('network') or 'sin nombre'}» " + (f"en {n['ssid']}" if n.get("ssid") else "en cualquier Wi-Fi")
             for n in networks]
    return "; ".join(parts) if parts else "ninguna red"


# --------------------------------------------------------------------------------------------------- command line

KIND_LABELS = {"PHONE": "celular o tableta", "COMPUTER": "computador", "TV": "televisor", "PRINTER": "impresora",
               "CAMERA": "cámara", "SPEAKER": "parlante", "CONSOLE": "consola", "IOT": "casa inteligente"}


def describe(report: dict) -> str:
    lines = [f"  Red: {report.get('ssid', 'sin Wi-Fi (¿cable?)')}  seguridad {report.get('authentication')}"
             f"  banda {report.get('band', '?')} GHz  canal {report.get('channel', '?')}"
             f"  señal {report.get('signalDbm', '?')} dBm",
             f"  Internet: {report.get('latencyMs', '?')} ms, jitter {report.get('jitterMs', '?')} ms, "
             f"pérdida {report.get('packetLossPct', '?')} %   Router: {report.get('gatewayLatencyMs', '?')} ms",
             f"  Equipos conectados: {report['deviceCount']}   Puertos abiertos en el router: "
             f"{', '.join(map(str, report['openPorts'])) or 'ninguno de los revisados'}"]
    if "trafficBytes" in report:
        protocols = ", ".join(f"{p['protocol']} {p['packets']}" for p in report.get("protocolPackets", []))
        lines.append(f"  Tráfico de este computador desde el reporte anterior: "
                     f"{report['trafficBytes'] / 1048576:.1f} MB, {report['trafficPackets']} paquetes"
                     + (f" ({protocols})" if protocols else ""))
    known = [d for d in report.get("devices") or [] if d.get("name") or d.get("kind")]
    if known:
        lines.append("  Equipos reconocidos: " + ", ".join(
            (d.get("name") or "sin nombre") + (f" ({KIND_LABELS[d['kind']]})" if d.get("kind") in KIND_LABELS else "")
            for d in known[:12]))
    if report.get("wifiNote") == "LOCATION_PERMISSION":
        lines.append("  Windows no deja leer el Wi-Fi: Configuración > Privacidad > Ubicación > activa "
                     "'Permitir que las aplicaciones de escritorio accedan a tu ubicación'.")
    return "\n".join(lines)


def command_setup(_args) -> int:
    config = load_config()
    print("Configuración del agente WiFiSense")
    server = input(f"Servidor [{config['server']}]: ").strip() or config["server"]
    key = getpass.getpass("Clave del agente (no se muestra al escribir): ").strip()
    try:
        server = validate_server(server)
    except ValueError as error:
        print(f"Error: {error}")
        return 2
    if not KEY_PATTERN.match(key):
        print("Error: la clave debe empezar por 'wsa_'. Cópiala completa desde Mi Wi-Fi > Agente.")
        return 2
    config.update(server=server, key=key)
    config.setdefault("salt", secrets.token_hex(16))
    print(f"Guardado en {save_config(config)}")
    print("Ahora ejecuta: python wifisense_agent.py run")
    return 0


def command_pair(args) -> int:
    config = load_config()
    code = args.code or input("Código de instalación (Mi Wi-Fi > Agente WiFiSense, o Redes > Sensor): ")
    try:
        answer = pair(code, config["server"])
    except SendError as error:
        print(f"Error: {error}")
        return 1
    ssid = current_ssid()
    saved = save_pairing(answer, config["server"], ssid=ssid)
    where = f" cuando este computador esté en «{ssid}»" if ssid else ""
    print(f"Conectado con la red «{answer.get('networkName', '')}»{where}. Guardado en {saved}")
    print("Ahora ejecuta: python wifisense_agent.py run")
    return 0


def ensure_salt(config: dict, path: Optional[Path] = None) -> str:
    """The salt is stored in the configuration file; a key that comes from an environment variable is not written."""
    if not config.get("salt"):
        try:
            stored = json.loads((path or config_path()).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = {}
        stored["salt"] = config["salt"] = secrets.token_hex(16)
        save_config(stored, path)
    return config["salt"]


def command_scan(_args) -> int:
    config = load_config()
    print("Midiendo (unos segundos)...")
    report = collect(config.get("salt") or secrets.token_hex(16))
    print(describe(report))
    print("\nEsto es lo que se enviaría:")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def command_nearby(args) -> int:
    """Shows the nearby Wi-Fi networks without sending anything (and, with --output, stores the result just as it would
    be sent: without any MAC). It is used to test the scan on a real computer."""
    salt = load_config().get("salt") or secrets.token_hex(16)
    print("Escaneando las redes Wi-Fi cercanas (unos segundos)...")
    result = wifi_scan.scan(0, AGENT_VERSION, lambda mac: mac_fingerprint(mac, salt), vendor_of)
    print(wifi_scan.summary(result))
    for ap in result.get("accessPoints") or []:
        signal = f"{ap['signalPercent']} %" if ap.get("signalPercent") is not None else "?"
        band = f"{ap['band']} GHz" if ap.get("band") else "?"
        mark = "  <- conectado" if ap.get("connected") else ""
        print(f"  {(ap.get('ssid') or '(red oculta)')[:32]:<32} {signal:>6}  canal {ap.get('channel') or '?':>3}  "
              f"{band:<7} {ap.get('securityLabel') or ap.get('authentication')}{mark}")
    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if result.get("status") == "COMPLETED" else 1


def command_capture_consent(args) -> int:
    """Allows (on) or forbids (off) technical captures on THIS computer. Whoever administers it decides: it cannot be
    turned on from the page."""
    config = load_config()
    allowed = args.state == "on"
    save_config(traffic_capture.set_consent(config, allowed))
    if allowed:
        print("Capturas técnicas PERMITIDAS en este computador. Solo se harán cuando un administrador de WiFiSense las "
              "pida para la red de la que este agente es sensor, con un propósito, y dentro de sus límites. Solo se "
              "cuentan cabeceras; el contenido no se guarda ni se envía. Para prohibirlas: capture-consent off")
    else:
        print("Capturas técnicas PROHIBIDAS en este computador. Las que se pidan fallarán con ese motivo.")
    return 0


def command_capture_check(_args) -> int:
    """Tells what this computer can capture and why not, without capturing anything."""
    config = load_config()
    own_ip = local_ip()
    _chosen, checks = capture_backends.choose_all(capture_backends.all_backends(), own_ip)
    caps = traffic_capture.capabilities(config, own_ip, monitor_hint=monitor_mode_hint())
    if getattr(_args, "output", None):  # the program without a console (WiFiSenseAgente.exe) does not show what it prints
        Path(_args.output).write_text(json.dumps({"capabilities": caps, "checks": {
            code: {"usable": c.usable, "present": c.present, "reason": c.reason, "detail": c.detail}
            for code, c in checks.items()}}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(traffic_capture.describe_capabilities(caps, checks))
    print("Escenario A (este computador): " + ("disponible" if caps["captureConsent"] and any(
        caps[k] for k in ("npcap", "pktmon", "rawSocket", "packetSocket")) else "no disponible"))
    print("Escenario B (puerto espejo de un switch): solo si este computador está conectado a uno; no se puede comprobar.")
    print("Escenario C (modo monitor): el agente no lo activa nunca.")
    print("Escenario D (estadísticas del router): no hay integración con ningún router.")
    return 0


def command_capture_local(args) -> int:
    """Tries a capture right here with the available tool and shows the counts that would be sent (it sends nothing).
    It is the manual test on a real computer."""
    config = traffic_capture.set_consent(load_config(), True)  # the person asked for it on their own computer
    own_ip = local_ip()
    prefixes = [f"{own_ip}/{network_prefix(own_ip)}"] if own_ip else []
    task = {"captureId": 1, "maxSeconds": max(1, min(args.seconds, 300)), "maxPackets": max(1, min(args.packets,
                                                                                                   100_000))}
    shown: dict = {}
    traffic_capture.run_capture(task, config, AGENT_VERSION, shown.update, lambda: False, own_ip, prefixes)
    print(json.dumps(shown, indent=2, ensure_ascii=False))
    if args.output:
        Path(args.output).write_text(json.dumps(shown, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if shown.get("status") == "COMPLETED" else 1


def command_live(args) -> int:
    """Measures live right here and shows it, without sending anything (with --output it stores the samples). It is used
    to test the live measurement on a real computer."""
    seconds = max(2, min(args.seconds, 300))
    samples: list[dict] = []

    def show(sample: dict) -> bool:
        samples.append(sample)
        print("  " + live_monitor.describe_sample(sample))
        return True

    print(f"Midiendo en vivo cada 2 segundos durante {seconds} s (Ctrl + C para detener)...")
    live_monitor.run_session({"sampleSeconds": 2, "maxSeconds": seconds}, live_sampler(), show)
    if args.output:
        Path(args.output).write_text(json.dumps({"agentVersion": AGENT_VERSION, "samples": samples},
                                                ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if samples else 1


def next_wait(answer: dict, interval: int) -> int:
    """While someone identifies a device on the page, the server asks to report every minute; never more often than
    MIN_INTERVAL nor slower than the normal interval."""
    asked = answer.get("nextReportSeconds") if isinstance(answer, dict) else None
    if isinstance(asked, (int, float)) and asked > 0:
        return int(max(MIN_INTERVAL, min(asked, interval)))
    return interval


def command_run(args) -> int:
    config = load_config()
    if not config_networks(config):
        print("Primero ejecuta: python wifisense_agent.py pair CODIGO")
        return 2
    salt = ensure_salt(config)
    interval = max(args.interval, MIN_INTERVAL)
    while True:
        config = load_config()  # a new code (another network) is used without restarting the agent
        networks = config_networks(config)
        print(time.strftime("[%H:%M:%S] Midiendo..."))
        report = collect(salt)
        ssid = report.get("ssid")
        network = choose_network(networks, ssid)
        wait, sent = interval, False
        if network is None:
            print(f"  No se envió: este computador está en «{ssid}», que no tiene código aquí. Mide: "
                  f"{describe_networks(networks)}." if ssid else
                  "  No se envió: no se pudo leer el Wi-Fi y este computador tiene códigos de varias redes.")
        else:
            learn_ssid(network, ssid)
            tag = network["key"][:12]
            counters = traffic_counters()
            previous = load_traffic_state()
            if previous and previous.get("network") not in (None, tag):
                previous = None  # the previous report was from another network: its traffic is not this one's
            report.update(traffic_fields(previous, counters))
            caps = agent_capabilities(config)
            if caps:
                report["capabilities"] = caps
            print(describe(report))
            try:
                answer = send(report, config["server"], network["key"])
                sent = True
                wait = next_wait(answer, interval)
                if counters:
                    save_traffic_state(counters, network=tag)
                print(f"  Enviado a «{network.get('network') or 'tu red'}». {answer.get('summary', '')}".rstrip())
                if scan_id_of(answer) is not None:
                    run_scan(scan_id_of(answer), config["server"], network["key"], salt)
                if isinstance(answer, dict) and capture_task_of({"captureId": answer.get("captureId")}):
                    # the report only notifies: the capture is taken with its limits (if another request already took it, nothing)
                    try:
                        task = next_capture(config["server"], network["key"])
                    except (SendError, ScansUnavailable) as error:
                        print(f"  No se pudo tomar la captura pedida: {error}")
                        task = None
                    if task is not None:
                        run_capture_task(task, config["server"], network["key"], config)
            except SendError as error:
                print(f"  No se envió: {error}")
                if error.fatal:
                    if not forget_network(network):
                        return 1
                    print("  Se quitó esa red de este computador; las demás siguen.")
                wait = max(interval, error.retry_after or 0)
        if args.once:
            return 0 if sent else 1
        if sent:
            wait_watching_tasks(wait, config["server"], network["key"], salt, config)
        else:
            time.sleep(wait)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Agente WiFiSense: mide tu red Wi-Fi y la envía a WiFiSense.")
    commands = parser.add_subparsers(dest="command", required=True)
    pair_parser = commands.add_parser("pair", help="conectar con el código de Mi Wi-Fi")
    pair_parser.add_argument("code", nargs="?", help="código de 8 caracteres, por ejemplo K7QM-4RZD")
    pair_parser.set_defaults(handler=command_pair)
    commands.add_parser("setup", help="guardar la clave del agente").set_defaults(handler=command_setup)
    commands.add_parser("scan", help="medir y mostrar sin enviar").set_defaults(handler=command_scan)
    nearby = commands.add_parser("nearby", help="escanear las redes Wi-Fi cercanas y mostrarlas sin enviar")
    nearby.add_argument("--output", help="guardar el resultado (sin MAC) en este archivo JSON")
    nearby.set_defaults(handler=command_nearby)
    consent = commands.add_parser("capture-consent", help="permitir (on) o prohibir (off) capturas técnicas aquí")
    consent.add_argument("state", choices=("on", "off"))
    consent.set_defaults(handler=command_capture_consent)
    check = commands.add_parser("capture-check", help="qué puede capturar este computador")
    check.add_argument("--output", help="guardar el resultado en este archivo JSON")
    check.set_defaults(handler=command_capture_check)
    local = commands.add_parser("capture-local", help="probar una captura aquí, sin enviar nada")
    local.add_argument("--seconds", type=int, default=10, help="duración (1 a 300 segundos)")
    local.add_argument("--packets", type=int, default=5000, help="paquetes como máximo")
    local.add_argument("--output", help="guardar los conteos (sin direcciones) en este archivo JSON")
    local.set_defaults(handler=command_capture_local)
    live = commands.add_parser("live", help="medir en vivo cada 2 segundos y mostrarlo, sin enviar nada")
    live.add_argument("--seconds", type=int, default=20, help="duración (2 a 300 segundos)")
    live.add_argument("--output", help="guardar las muestras en este archivo JSON")
    live.set_defaults(handler=command_live)
    run = commands.add_parser("run", help="medir y enviar periódicamente")
    run.add_argument("--once", action="store_true", help="enviar un solo reporte y salir")
    run.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="segundos entre reportes (mínimo 60)")
    run.set_defaults(handler=command_run)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        print("\nAgente detenido.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
