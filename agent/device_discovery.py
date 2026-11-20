"""Recognising the devices of the network (agent 1.8.0): which name they announce, which model they are and which kind
of device they seem to be.

Phones hide their maker behind a private MAC and many announce no name over DNS or NetBIOS. What many devices do
announce is what they offer on the network, so that others can find them:

* **mDNS / Bonjour** (``_service._tcp.local``): an iPhone or a Mac announces ``_companion-link`` with its name
  ("iPhone de Ana"), a Chromecast ``_googlecast`` with the name of the room ("Sala TV") and its model, a printer
  ``_ipp``, a smart home accessory ``_hap``...
* **UPnP / SSDP**: TVs, set-top boxes, consoles and speakers answer with an address where they describe their name,
  maker and model.
* **Open ports**: an iPhone or iPad has 62078 open, a Chromecast 8009, a printer 9100, a camera 554 (RTSP)... It only
  checks whether the port accepts a connection (sending nothing) and only on the local network.
* **DHCP** (agent 1.8.0): when it connects, each device asks for its address with a message to the whole network that
  includes the name it is configured with ("Galaxy-A54-de-Ana", "DESKTOP-7Q2M"). That is where the router gets the list
  of connected devices from. The agent only listens to those messages (it neither answers nor asks anything) and
  remembers the name of each device while it is open. Windows must allow the agent to receive them (it asks the first
  time) and the network must not block messages between devices, which many university and public networks do.

From that the **kind** is deduced (PHONE, COMPUTER, TV, PRINTER, CAMERA, SPEAKER, CONSOLE or IOT), which is always a
guess. None of this leaves the computer except the name, the model and the kind: the MAC still stays here.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
import threading
import time
import urllib.request
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

try:  # the agent as a package (tests) or as loose scripts (PyInstaller, python wifisense_agent.py)
    from agent.dns_wire import dns_name, read_name
except ImportError:  # pragma: no cover
    from dns_wire import dns_name, read_name

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
DNS_A, DNS_PTR, DNS_TXT, DNS_SRV = 1, 12, 16, 33

# Services the devices of a home or an office announce and the kind of device they suggest (None: says nothing).
SERVICES = {
    "_companion-link._tcp.local": None,      # iPhone, iPad and Mac (the name decides)
    "_apple-mobdev2._tcp.local": "PHONE",
    "_device-info._tcp.local": None,          # model of Apple devices ("MacBookPro18,1", "iPad13,4")
    "_airplay._tcp.local": "TV",
    "_raop._tcp.local": "SPEAKER",
    "_googlecast._tcp.local": "TV",
    "_androidtvremote2._tcp.local": "TV",
    "_amzn-wplay._tcp.local": "TV",
    "_spotify-connect._tcp.local": "SPEAKER",
    "_sonos._tcp.local": "SPEAKER",
    "_ipp._tcp.local": "PRINTER",
    "_ipps._tcp.local": "PRINTER",
    "_printer._tcp.local": "PRINTER",
    "_pdl-datastream._tcp.local": "PRINTER",
    "_hap._tcp.local": "IOT",
    "_matter._tcp.local": "IOT",
    "_smb._tcp.local": "COMPUTER",
    "_workstation._tcp.local": "COMPUTER",
    "_rfb._tcp.local": "COMPUTER",
}

# Open port -> kind of device. Only very characteristic ports, so as not to confuse.
PORT_KINDS = {
    62078: "PHONE",     # sync service of iPhone and iPad
    8009: "TV",         # Google Cast (Chromecast, Google TV, TVs with Cast)
    8060: "TV",         # Roku
    8001: "TV",         # televisores Samsung
    1925: "TV",         # televisores Philips
    3001: "TV",         # televisores LG (webOS)
    9100: "PRINTER",
    631: "PRINTER",
    515: "PRINTER",
    554: "CAMERA",      # RTSP: IP cameras and recorders
    1400: "SPEAKER",    # Sonos
    445: "COMPUTER",    # Windows shared folders
    3389: "COMPUTER",   # Windows remote desktop
    1883: "IOT",        # MQTT
}

# Words in the name or the model that tell the kind with more certainty than a port.
NAME_KINDS = (
    (r"iphone|galaxy|pixel|redmi|moto|celular|android|xiaomi|huawei|honor|oppo|vivo|realme|oneplus", "PHONE"),
    (r"ipad|tablet|tab[ -]", "PHONE"),
    (r"macbook|imac|mac ?mini|mac ?pro|laptop|portatil|portátil|desktop|thinkpad|notebook|pc\b|windows", "COMPUTER"),
    (r"chromecast|google tv|smart ?tv|\btv\b|roku|fire ?tv|apple ?tv|televisor|bravia|webos", "TV"),
    (r"playstation|ps[45]|xbox|nintendo|switch", "CONSOLE"),
    (r"printer|impresora|epson|canon|laserjet|deskjet|brother", "PRINTER"),
    (r"camera|cámara|camara|ipc|hikvision|dahua|reolink|tapo c|ezviz", "CAMERA"),
    (r"echo|alexa|google home|nest (mini|audio|hub)|homepod|sonos|speaker|parlante|bocina", "SPEAKER"),
    (r"bulb|bombillo|plug|enchufe|switch-|tuya|shelly|sonoff|esp[-_]", "IOT"),
)


# -------------------------------------------------------------------------------------------------------------- DHCP

DHCP_SERVER_PORT = 67
DHCP_MAGIC = b"\x63\x82\x53\x63"
# Names that say nothing: those the system sets by itself (old Android, ESP smart home boards) or empty ones.
GENERIC_DHCP_NAMES = re.compile(r"^(android-[0-9a-f]{6,}|localhost|unknown|espressif|esp[-_]?[0-9a-f]{4,}|"
                                r"[0-9a-f]{12}|[0-9a-f:-]{17})$", re.I)


def fqdn_first_label(value: bytes) -> Optional[str]:
    """Option 81 (client FQDN): flags, two codes and the name, as text or in DNS format (flag E)."""
    if len(value) < 4:
        return None
    flags, name = value[0], value[3:]
    if flags & 0x04:  # DNS format: length + label
        length = name[0]
        return name[1:1 + length].decode("utf-8", "replace") if length else None
    return name.decode("utf-8", "replace").split(".")[0]


def parse_dhcp_request(data: bytes) -> Optional[dict]:
    """From a DHCP request (DISCOVER or REQUEST): the MAC of the device, the name it gives and its vendor class
    ("android-dhcp-14", "MSFT 5.0"). None if the packet is not a DHCP request from Ethernet or Wi-Fi."""
    if len(data) < 240 or data[0] != 1 or data[1] != 1 or data[2] != 6 or data[236:240] != DHCP_MAGIC:
        return None
    found = {"mac": ":".join(f"{b:02x}" for b in data[28:34])}
    i = 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        i += 2 + length
        if code == 12:
            found["name"] = value.decode("utf-8", "replace")
        elif code == 81 and "name" not in found:
            label = fqdn_first_label(value)
            if label:
                found["fqdn"] = label
        elif code == 60:
            found["vendorClass"] = value.decode("ascii", "replace")
    name = (found.pop("name", None) or found.pop("fqdn", None) or "").strip("\x00 .").strip()
    found.pop("fqdn", None)
    if name and not GENERIC_DHCP_NAMES.match(name):
        found["name"] = name[:63]
    return found


def dhcp_kind(vendor_class: Optional[str]) -> Optional[str]:
    """The vendor class tells the system: 'android-dhcp-14' is an Android, 'MSFT 5.0' a Windows."""
    text = (vendor_class or "").lower()
    if text.startswith("android"):
        return "PHONE"
    if text.startswith("msft"):
        return "COMPUTER"
    return None


class DhcpWatcher:
    """Listens in the background to the DHCP requests of the network and remembers, by MAC, the name and the class of
    each device. If port 67 cannot be opened (another program uses it or the system does not allow it), it does
    nothing."""

    def __init__(self) -> None:
        self._seen: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._started = False

    def learn(self, data: bytes) -> None:
        request = parse_dhcp_request(data)
        if not request or ("name" not in request and "vendorClass" not in request):
            return
        with self._lock:
            known = self._seen.setdefault(request["mac"], {})
            known.update({k: v for k, v in request.items() if k != "mac"})

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            return {mac: dict(info) for mac, info in self._seen.items()}

    def start(self) -> bool:
        if self._started:
            return True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", DHCP_SERVER_PORT))
        except OSError:
            return False
        self._started = True
        threading.Thread(target=self._listen, args=(sock,), daemon=True).start()
        return True

    def _listen(self, sock: socket.socket) -> None:
        while True:
            try:
                data, _ = sock.recvfrom(2048)
            except OSError:
                return
            self.learn(data)


DHCP = DhcpWatcher()


# ---------------------------------------------------------------------------------------------------- mDNS / Bonjour

def mdns_browse_query(services: Iterable[str]) -> bytes:
    """A single PTR question for each service, with the QU bit so the devices answer this computer directly."""
    services = list(services)
    packet = struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0)
    for service in services:
        packet += dns_name(service) + struct.pack("!HH", DNS_PTR, 0x8001)
    return packet


def parse_txt(data: bytes) -> dict[str, str]:
    values, offset = {}, 0
    while offset < len(data):
        length = data[offset]
        entry = data[offset + 1: offset + 1 + length].decode("utf-8", "replace")
        offset += 1 + length
        if "=" in entry:
            key, value = entry.split("=", 1)
            values[key.lower()] = value
    return values


def parse_mdns_records(data: bytes) -> list[tuple[str, int, object]]:
    """All the records (answers and additional) of an mDNS packet: (name, type, value)."""
    records = []
    try:
        _, flags, questions, answers, authority, additional = struct.unpack_from("!HHHHHH", data, 0)
        if not flags & 0x8000:
            return []
        offset = 12
        for _ in range(questions):
            offset = read_name(data, offset)[1] + 4
        for _ in range(answers + authority + additional):
            name, offset = read_name(data, offset)
            rtype, _, _, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset: offset + length]
            if rtype == DNS_PTR:
                records.append((name, rtype, read_name(data, offset)[0]))
            elif rtype == DNS_SRV:
                records.append((name, rtype, read_name(data, offset + 6)[0]))
            elif rtype == DNS_TXT:
                records.append((name, rtype, parse_txt(rdata)))
            elif rtype == DNS_A and length == 4:
                records.append((name, rtype, socket.inet_ntoa(rdata)))
            offset += length
    except (struct.error, IndexError, OSError, ValueError):
        pass
    return records


def instance_label(instance: str, service: str) -> str:
    """'iPhone de Ana._companion-link._tcp.local' -> 'iPhone de Ana'."""
    return instance[: -len(service) - 1] if instance.endswith("." + service) else instance.split("._")[0]


def mdns_identity(packets: Iterable[tuple[str, bytes]]) -> dict[str, dict]:
    """By IP: the name it announces, its model and the kind its services suggest."""
    found: dict[str, dict] = {}
    for source_ip, data in packets:
        info = found.setdefault(source_ip, {})
        records = parse_mdns_records(data)
        for name, rtype, value in records:
            if rtype == DNS_PTR and name in SERVICES:
                label = instance_label(str(value), name).strip()
                if SERVICES[name]:
                    info.setdefault("kinds", []).append(SERVICES[name])
                if label and name in ("_companion-link._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
                                      "_ipp._tcp.local", "_printer._tcp.local", "_hap._tcp.local",
                                      "_spotify-connect._tcp.local", "_smb._tcp.local", "_workstation._tcp.local"):
                    label = re.sub(r"^[0-9A-F]{12}@", "", label)  # RAOP puts the MAC first: not used
                    label = re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", label, flags=re.I)  # _workstation adds the MAC
                    info.setdefault("name", label)
            elif rtype == DNS_TXT and isinstance(value, dict):
                if value.get("fn"):            # Google Cast: the name it was given ("Sala TV")
                    info["name"] = value["fn"]
                model = value.get("model") or value.get("md") or value.get("am") or value.get("ty") or value.get("rpmd")
                if model:
                    info.setdefault("model", model)
    return {ip: info for ip, info in found.items() if info}


def mdns_browse(timeout: float = 2.5) -> dict[str, dict]:
    """Asks the network which services there are and gathers the answers that arrive within ``timeout`` seconds."""
    packets: list[tuple[str, bytes]] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.3)
            query = mdns_browse_query(SERVICES)
            sock.sendto(query, MDNS_GROUP)
            deadline = time.monotonic() + timeout
            resent = False
            while time.monotonic() < deadline:
                if not resent and time.monotonic() > deadline - timeout / 2:
                    sock.sendto(query, MDNS_GROUP)  # a second time: some sleeping devices are slow
                    resent = True
                try:
                    data, (ip, _) = sock.recvfrom(9000)
                except socket.timeout:
                    continue
                packets.append((ip, data))
    except OSError:
        pass
    return mdns_identity(packets)


# --------------------------------------------------------------------------------------------------------- UPnP / SSDP

SSDP_SEARCH = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
               "ST: ssdp:all\r\n\r\n").encode()


def parse_ssdp_location(response: bytes) -> Optional[str]:
    match = re.search(rb"^location:\s*(\S+)", response, re.I | re.M)
    return match.group(1).decode("latin-1") if match else None


def parse_upnp_description(xml_text: str) -> dict:
    """friendlyName, maker and model from the UPnP description of a device."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return {}
    device = next((element for element in root.iter() if element.tag.endswith("device")), None)
    if device is None:
        return {}

    def field(tag: str) -> Optional[str]:
        element = next((e for e in device if e.tag.endswith(tag)), None)
        return element.text.strip() if element is not None and element.text and element.text.strip() else None

    info = {}
    name, maker, model = field("friendlyName"), field("manufacturer"), field("modelName")
    if name:
        info["name"] = name
    if model:
        info["model"] = f"{maker} {model}" if maker and maker.lower() not in model.lower() else model
    elif maker:
        info["model"] = maker
    kind = kind_from_text(" ".join(filter(None, [name, maker, model])))
    if kind:
        info["kinds"] = [kind]
    return info


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def fetch_description(location: str, source_ip: str, timeout: float = 1.5) -> dict:
    """Only descriptions of the same device that answered, on the local network, and of at most 64 KB."""
    match = re.match(r"https?://([^/:]+)", location)
    if not match or match.group(1) != source_ip or not is_private(source_ip):
        return {}
    try:
        with urllib.request.urlopen(location, timeout=timeout) as response:
            return parse_upnp_description(response.read(65536).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return {}


def ssdp_discover(timeout: float = 2.5) -> dict[str, dict]:
    locations: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.3)
            sock.sendto(SSDP_SEARCH, SSDP_GROUP)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, (ip, _) = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                location = parse_ssdp_location(data)
                if location and ip not in locations:
                    locations[ip] = location
    except OSError:
        pass
    if not locations:
        return {}
    with ThreadPoolExecutor(max_workers=min(len(locations), 16)) as pool:
        described = dict(zip(locations, pool.map(lambda ip: fetch_description(locations[ip], ip), locations)))
    return {ip: info for ip, info in described.items() if info}


# ----------------------------------------------------------------------------------------------------- puertos

def port_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_kinds(ips: Iterable[str], skip: Iterable[str] = ()) -> dict[str, list[str]]:
    """By IP, the kinds its open ports suggest (only private IPs; never the router nor this computer)."""
    skip = set(skip)
    targets = [(ip, port) for ip in ips if ip not in skip and is_private(ip) for port in PORT_KINDS]
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=64) as pool:
        results = pool.map(lambda target: port_open(*target), targets)
        kinds: dict[str, list[str]] = {}
        for (ip, port), is_open in zip(targets, results):
            if is_open:
                kinds.setdefault(ip, []).append(PORT_KINDS[port])
    return kinds


# ----------------------------------------------------------------------------------------------------- tipo final

def kind_from_text(text: Optional[str]) -> Optional[str]:
    lowered = (text or "").lower()
    for pattern, kind in NAME_KINDS:
        if re.search(pattern, lowered):
            return kind
    return None


def decide_kind(name: Optional[str], model: Optional[str], vendor: Optional[str], hints: list[str],
                private_mac: bool) -> Optional[str]:
    """The name or the model rule; then what services and ports suggest (the most repeated one); and a private MAC with
    nothing else is almost always a phone or a tablet."""
    by_text = kind_from_text(" ".join(filter(None, [name, model])))
    if by_text:
        return by_text
    if hints:
        return max(set(hints), key=hints.count)
    by_vendor = kind_from_text(vendor)
    if by_vendor:
        return by_vendor
    if vendor in ("Nintendo", "Sony"):
        return "CONSOLE"
    if vendor in ("Hikvision", "Dahua", "Reolink", "Cámara IP"):
        return "CAMERA"
    if vendor in ("Espressif", "Tuya", "Philips Hue"):
        return "IOT"
    if vendor in ("Roku",):
        return "TV"
    if vendor in ("Sonos",):
        return "SPEAKER"
    return "PHONE" if private_mac else None


def identify(ips: list[str], own_ip: Optional[str], gateway: Optional[str]) -> dict[str, dict]:
    """Gathers what they announce (mDNS and UPnP) and the ports of each IP, in parallel (about 3 seconds in total)."""
    with ThreadPoolExecutor(max_workers=3) as pool:
        mdns = pool.submit(mdns_browse)
        ssdp = pool.submit(ssdp_discover)
        ports = pool.submit(port_kinds, ips, [own_ip, gateway])
        results = (mdns.result(), ssdp.result(), ports.result())
    merged: dict[str, dict] = {}
    for source in results[:2]:
        for ip, info in source.items():
            target = merged.setdefault(ip, {})
            for key in ("name", "model"):
                if info.get(key) and not target.get(key):
                    target[key] = info[key][:63].strip()
            target.setdefault("kinds", []).extend(info.get("kinds", []))
    for ip, kinds in results[2].items():
        merged.setdefault(ip, {}).setdefault("kinds", []).extend(kinds)
    return merged
