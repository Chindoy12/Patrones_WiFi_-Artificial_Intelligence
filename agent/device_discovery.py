"""Reconocer los equipos de la red (agente 1.7.0): qué nombre anuncian, qué modelo son y qué tipo de equipo parecen.

Los celulares esconden su fabricante detrás de una MAC privada y muchos no anuncian un nombre por DNS ni NetBIOS. Lo
que sí anuncian muchos equipos es lo que ofrecen en la red, para que otros los encuentren:

* **mDNS / Bonjour** (``_servicio._tcp.local``): un iPhone o un Mac anuncia ``_companion-link`` con su nombre
  ("iPhone de Ana"), un Chromecast ``_googlecast`` con el nombre de la sala ("Sala TV") y su modelo, una impresora
  ``_ipp``, un accesorio de casa inteligente ``_hap``…
* **UPnP / SSDP**: televisores, decodificadores, consolas y parlantes responden con una dirección donde describen su
  nombre, fabricante y modelo.
* **Puertos abiertos**: un iPhone o iPad tiene abierto el 62078, un Chromecast el 8009, una impresora el 9100, una
  cámara el 554 (RTSP)… Se prueba solo si el puerto acepta conexión (sin enviar nada) y solo en la red local.

Con eso se deduce el **tipo** (PHONE, COMPUTER, TV, PRINTER, CAMERA, SPEAKER, CONSOLE o IOT), que siempre es una
suposición. Nada de esto sale del computador salvo el nombre, el modelo y el tipo: la MAC sigue quedándose aquí.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

MDNS_GROUP = ("224.0.0.251", 5353)
SSDP_GROUP = ("239.255.255.250", 1900)
DNS_A, DNS_PTR, DNS_TXT, DNS_SRV = 1, 12, 16, 33

# Servicios que anuncian los equipos de una casa o una oficina y el tipo de equipo que sugieren (None: no dice nada).
SERVICES = {
    "_companion-link._tcp.local": None,      # iPhone, iPad y Mac (el nombre decide)
    "_apple-mobdev2._tcp.local": "PHONE",
    "_device-info._tcp.local": None,          # modelo de equipos Apple ("MacBookPro18,1", "iPad13,4")
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

# Puerto abierto -> tipo de equipo. Solo puertos muy característicos, para no confundir.
PORT_KINDS = {
    62078: "PHONE",     # servicio de sincronización de iPhone y iPad
    8009: "TV",         # Google Cast (Chromecast, Google TV, televisores con Cast)
    8060: "TV",         # Roku
    8001: "TV",         # televisores Samsung
    1925: "TV",         # televisores Philips
    3001: "TV",         # televisores LG (webOS)
    9100: "PRINTER",
    631: "PRINTER",
    515: "PRINTER",
    554: "CAMERA",      # RTSP: cámaras IP y grabadores
    1400: "SPEAKER",    # Sonos
    445: "COMPUTER",    # carpetas compartidas de Windows
    3389: "COMPUTER",   # escritorio remoto de Windows
    1883: "IOT",        # MQTT
}

# Palabras en el nombre o el modelo que dicen el tipo con más certeza que un puerto.
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


# ---------------------------------------------------------------------------------------------------- mDNS / Bonjour

def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split(".") if part) + b"\0"


def mdns_browse_query(services: Iterable[str]) -> bytes:
    """Una sola pregunta PTR por cada servicio, con el bit QU para que los equipos respondan directo a este computador."""
    services = list(services)
    packet = struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0)
    for service in services:
        packet += dns_name(service) + struct.pack("!HH", DNS_PTR, 0x8001)
    return packet


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Nombre DNS con punteros de compresión -> (nombre, posición siguiente)."""
    parts, end = [], None
    while depth < 20:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            end = end if end is not None else offset + 2
            offset, depth = pointer, depth + 1
            continue
        parts.append(data[offset + 1: offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return ".".join(parts), end if end is not None else offset


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
    """Todos los registros (respuestas y adicionales) de un paquete mDNS: (nombre, tipo, valor)."""
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
    except (struct.error, IndexError, OSError):
        pass
    return records


def instance_label(instance: str, service: str) -> str:
    """'iPhone de Ana._companion-link._tcp.local' -> 'iPhone de Ana'."""
    return instance[: -len(service) - 1] if instance.endswith("." + service) else instance.split("._")[0]


def mdns_identity(packets: Iterable[tuple[str, bytes]]) -> dict[str, dict]:
    """Por IP: el nombre que anuncia, su modelo y el tipo que sugieren sus servicios."""
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
                    label = re.sub(r"^[0-9A-F]{12}@", "", label)  # RAOP antepone la MAC: no se usa
                    label = re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", label, flags=re.I)  # _workstation agrega la MAC
                    info.setdefault("name", label)
            elif rtype == DNS_TXT and isinstance(value, dict):
                if value.get("fn"):            # Google Cast: nombre que le pusieron ("Sala TV")
                    info["name"] = value["fn"]
                model = value.get("model") or value.get("md") or value.get("am") or value.get("ty") or value.get("rpmd")
                if model:
                    info.setdefault("model", model)
    return {ip: info for ip, info in found.items() if info}


def mdns_browse(timeout: float = 2.5) -> dict[str, dict]:
    """Pregunta en la red qué servicios hay y junta las respuestas que lleguen en ``timeout`` segundos."""
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
                    sock.sendto(query, MDNS_GROUP)  # una segunda vez: algunos equipos dormidos tardan
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
    """friendlyName, fabricante y modelo de la descripción UPnP de un equipo."""
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
    """Solo descripciones del mismo equipo que respondió, en la red local, y de máximo 64 KB."""
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
    """Por IP, los tipos que sugieren sus puertos abiertos (solo IPs privadas; nunca el router ni este computador)."""
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
    """El nombre o el modelo mandan; luego lo que sugieren servicios y puertos (el más repetido); y una MAC privada
    sin nada más casi siempre es un celular o una tableta."""
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
    """Junta lo que anuncian (mDNS y UPnP) y los puertos de cada IP, en paralelo (unos 3 segundos en total)."""
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
