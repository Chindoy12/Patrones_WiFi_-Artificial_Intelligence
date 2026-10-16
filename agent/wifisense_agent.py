#!/usr/bin/env python3
"""Agente WiFiSense: mide tu red Wi-Fi desde un computador de la casa y envía un reporte a WiFiSense.

Solo usa la biblioteca estándar de Python 3.9 o superior (no hay que instalar nada) y funciona en Windows y Linux.

    python wifisense_agent.py pair CODIGO  conecta el agente con el código de Mi Wi-Fi > Instalar agente
    python wifisense_agent.py setup        guarda la clave del agente (se crea en Mi Wi-Fi > Agente)
    python wifisense_agent.py scan         muestra lo que mediría, sin enviar nada
    python wifisense_agent.py run          envía un reporte cada 5 minutos (Ctrl + C para detener)
    python wifisense_agent.py run --once   envía un solo reporte

Qué mide y qué envía:
  * Datos del Wi-Fi que muestra el sistema (nombre, tipo de seguridad, señal, canal, banda) y cuántas redes vecinas
    usan el mismo canal.
  * Latencia, variación (jitter) y pérdida hacia internet y hacia el router.
  * Cuántos equipos hay conectados. Las direcciones MAC NO salen de tu computador: se envía una huella SHA-256 con
    una sal aleatoria propia de esta instalación, que sirve para saber si aparece un equipo nuevo y nada más.
  * Qué puertos de administración del router aceptan conexiones (solo se intenta conectar, no se envían datos).
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
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

AGENT_VERSION = "1.1.0"
DEFAULT_SERVER = "https://patroneswifibackend-production.up.railway.app"
REPORT_PATH = "/api/agent/reports"
PAIR_PATH = "/api/agent/pair"
DEFAULT_INTERVAL = 300
MIN_INTERVAL = 60
ROUTER_PORTS = (21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080, 8443)
INTERNET_TARGET = ("1.1.1.1", 443)
SAMPLES = 10
MAX_DEVICES = 256
IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------------------------- comandos del sistema

def decode(raw: bytes) -> str:
    """netsh escribe en la página de códigos de la consola (cp850 en español); se prueba UTF-8 primero."""
    for encoding in ("utf-8", "oem", "cp850", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def run_command(args: list[str], timeout: float = 15) -> str:
    """Salida del comando, o cadena vacía si no existe o falla. Nunca usa el shell."""
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return ""
    return decode(result.stdout)


def read_file(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------------------- Wi-Fi

def normalize_key(key: str) -> str:
    """Clave de netsh en minúsculas, sin tildes ni espacios ('Autenticación' -> 'autenticacion')."""
    ascii_key = unicodedata.normalize("NFKD", key.lower())
    return "".join(c for c in ascii_key if "a" <= c <= "z")


# Prefijos de cada campo en inglés y en español (incluye cómo se ven si la consola dañó las tildes).
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


def key_values(text: str) -> list[tuple[str, str]]:
    pairs = []
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            pairs.append((key.strip(), value.strip()))
    return pairs


def first_number(text: str) -> Optional[float]:
    match = re.search(r"-?\d+(?:[.,]\d+)?", text or "")
    return float(match.group().replace(",", ".")) if match else None


def authentication_of(auth: str, cipher: str = "") -> str:
    """Texto del sistema -> OPEN, WEP, WPA, WPA2, WPA3 o UNKNOWN (lo que entiende la auditoría de la IA)."""
    auth_u, cipher_u = (auth or "").upper(), (cipher or "").upper()
    if "WPA3" in auth_u or "SAE" in auth_u or "OWE" in auth_u:
        return "WPA3"
    if "WPA2" in auth_u or "RSN" in auth_u:
        return "WPA2"
    if "WPA" in auth_u:
        return "WPA"
    if "WEP" in cipher_u or "WEP" in auth_u or "SHARED" in auth_u or "COMPARTIDA" in auth_u:
        return "WEP"
    if auth_u.startswith(("OPEN", "ABIERT")) or auth_u in ("--", "NONE"):
        return "OPEN"
    return "UNKNOWN"


CIPHERS = (("GCMP-256", "GCMP-256"), ("GCMP", "GCMP"), ("CCMP", "CCMP"), ("AES", "CCMP"), ("TKIP", "TKIP"),
           ("WEP", "WEP"), ("NINGUN", "NONE"), ("NONE", "NONE"))


def cipher_of(text: str) -> Optional[str]:
    """Nombre corto del cifrado. Algunas versiones de Windows escriben una descripción larga (por ejemplo varios
    cifrados o el nombre del proveedor); el servidor solo acepta hasta 20 caracteres."""
    upper = (text or "").upper()
    for token, name in CIPHERS:
        if token in upper:
            return name
    return (text or "").strip()[:20] or None


def band_of(band_text: str, channel: Optional[int]) -> Optional[str]:
    number = first_number(band_text or "")
    if number is not None:
        return "2.4" if number < 3 else "5" if number < 5.9 else "6"
    if channel:
        return "2.4" if channel <= 14 else "5"
    return None


def parse_netsh_interfaces(text: str) -> dict:
    """Interfaz Wi-Fi conectada en 'netsh wlan show interfaces' (Windows, en español o inglés)."""
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
    """(nombre de red, canal) de cada punto de acceso en 'netsh wlan show networks mode=bssid'."""
    found, ssid = [], ""
    for key, value in key_values(text):
        normalized = normalize_key(key)
        if normalized == "ssid":  # "SSID 1 : Mi red" (los dígitos se quitan al normalizar)
            ssid = value
        elif field_of(key) == "channel":
            channel = first_number(value)
            if channel:
                found.append((ssid, int(channel)))
    return found


def split_nmcli(line: str) -> list[str]:
    """nmcli -t separa con ':' y escapa los ':' de los valores con '\\:'."""
    return [part.replace("\\:", ":") for part in re.split(r"(?<!\\):", line)]


def parse_nmcli(text: str) -> tuple[dict, list[tuple[str, int]]]:
    """Salida de 'nmcli -t -f ACTIVE,SSID,CHAN,FREQ,SIGNAL,SECURITY,RATE dev wifi list' (Linux)."""
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
    """(redes vecinas en el mismo canal, redes vecinas en total); no cuenta los puntos de acceso de tu propia red."""
    others = [(name, ch) for name, ch in networks if name != ssid]
    return sum(1 for _, ch in others if ch == channel), len({name for name, _ in others})


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
    return info


# ------------------------------------------------------------------------------------------------ red local

IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"


def parse_route_print(text: str) -> Optional[str]:
    """Puerta de enlace con menor métrica en 'route print -4 0.0.0.0' (Windows)."""
    routes = re.findall(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+{IPV4}\s+{IPV4}\s+(\d+)", text, re.MULTILINE)
    return min(routes, key=lambda r: int(r[2]))[0] if routes else None


def parse_proc_route(text: str) -> Optional[str]:
    """Puerta de enlace en /proc/net/route (Linux): destino 00000000, dirección en hexadecimal little-endian."""
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
    """IP de este equipo en la red de la casa. Un socket UDP 'conectado' no envía ningún paquete."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(INTERNET_TARGET)
            return sock.getsockname()[0]
        except OSError:
            return None


MAC = r"((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"


def parse_neighbors(text: str) -> dict[str, str]:
    """IP -> MAC de la tabla ARP ('arp -a' en Windows o /proc/net/arp en Linux)."""
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
    """Descarta difusión y multidifusión (el bit menos significativo del primer byte en 1)."""
    return not int(mac.split(":")[0], 16) & 1


def same_subnet(ips: dict[str, str], own_ip: str, prefix: int = 24) -> dict[str, str]:
    network = ipaddress.ip_network(f"{own_ip}/{prefix}", strict=False)
    return {ip: mac for ip, mac in ips.items()
            if ipaddress.ip_address(ip) in network and ipaddress.ip_address(ip) != network.broadcast_address}


def wake_neighbors(own_ip: str) -> None:
    """Un datagrama vacío al puerto 9 (discard) de cada dirección de la red obliga al sistema a preguntar por ARP
    quién la tiene, y así la tabla ARP se llena con los equipos encendidos, aunque no respondan al ping."""
    network = ipaddress.ip_network(f"{own_ip}/24", strict=False)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for host in network.hosts():
            try:
                sock.sendto(b"", (str(host), 9))
            except OSError:
                pass


def mac_fingerprint(mac: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}:{mac.lower()}".encode()).hexdigest()[:24]


def own_mac() -> Optional[str]:
    import uuid
    node = uuid.getnode()
    if node >> 40 & 1:  # uuid inventó un número al azar: no hay MAC
        return None
    return ":".join(f"{node >> shift & 0xff:02x}" for shift in range(40, -1, -8))


def devices(own_ip: Optional[str], salt: str, wait: float = 2.0) -> list[str]:
    """Huellas de los equipos conectados a la red (incluido este)."""
    if not own_ip:
        return []
    wake_neighbors(own_ip)
    time.sleep(wait)
    table = run_command(["arp", "-a"]) if IS_WINDOWS else read_file("/proc/net/arp")
    macs = set(same_subnet(parse_neighbors(table), own_ip).values())
    mine = own_mac()
    if mine:
        macs.add(mine)
    return sorted(mac_fingerprint(mac, salt) for mac in macs)[:MAX_DEVICES]


# -------------------------------------------------------------------------------------------- latencia y puertos

def connect_time(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    """Milisegundos hasta que el destino responde a una conexión TCP. Un rechazo también es una respuesta (mide el
    viaje de ida y vuelta igual), solo el silencio cuenta como pérdida."""
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


# ------------------------------------------------------------------------------------------------------ reporte

def collect(salt: str) -> dict:
    """Mide todo en paralelo (unos 5 segundos) y arma el reporte que se envía."""
    own_ip, gateway = local_ip(), default_gateway()
    results: dict = {}

    def task(name: str, fn: Callable[[], object]) -> threading.Thread:
        def target():
            try:
                results[name] = fn()
            except Exception as error:  # una medición que falla no debe impedir enviar las demás
                results[name] = None
                print(f"  aviso: no se pudo medir {name}: {error}", file=sys.stderr)
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    threads = [task("wifi", wifi_info), task("internet", lambda: measure(*INTERNET_TARGET)),
               task("devices", lambda: devices(own_ip, salt))]
    if gateway:
        threads += [task("router", lambda: measure(gateway, 80, count=5)), task("ports", lambda: open_ports(gateway))]
    for thread in threads:
        thread.join(timeout=60)
    return build_report(results.get("wifi") or {}, results.get("internet") or summarize([]),
                        results.get("router"), results.get("devices") or [], results.get("ports") or [])


def build_report(wifi: dict, internet: dict, router: Optional[dict], device_hashes: list[str],
                 ports: list[int]) -> dict:
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
        "wifiNote": wifi.get("note"),
        "latencyMs": internet.get("latencyMs"),
        "jitterMs": internet.get("jitterMs"),
        "packetLossPct": internet.get("packetLossPct"),
        "gatewayLatencyMs": (router or {}).get("latencyMs"),
        "deviceCount": len(device_hashes),
        "deviceHashes": device_hashes,
        "openPorts": ports,
    }
    return {key: value for key, value in report.items() if value is not None}


# ------------------------------------------------------------------------------------------------- configuración

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
    """Guarda la configuración solo para el usuario actual (permisos 600 en Linux; en Windows la carpeta
    %APPDATA% ya es privada de cada usuario)."""
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
    """Solo HTTPS, salvo en el propio computador (pruebas locales): la clave no debe viajar sin cifrar."""
    parsed = urllib.parse.urlparse(url.strip())
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("el servidor debe usar https://")
    if not parsed.hostname:
        raise ValueError("dirección del servidor inválida")
    return f"{parsed.scheme}://{parsed.netloc}"


# ------------------------------------------------------------------------------------------------------- envío

class SendError(Exception):
    def __init__(self, message: str, retry_after: Optional[int] = None, fatal: bool = False):
        super().__init__(message)
        self.retry_after = retry_after
        self.fatal = fatal


def server_detail(error: urllib.error.HTTPError) -> str:
    """El motivo que da el servidor (y el campo rechazado, si lo hay), para saber qué corregir."""
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


CODE_PATTERN = re.compile(r"^[A-HJKMNP-Z2-9]{8}$")


def normalize_code(text: str) -> Optional[str]:
    """'k7qm 4rzd' o 'K7QM-4RZD' -> 'K7QM-4RZD'; None si no puede ser un código."""
    code = re.sub(r"[\s-]", "", text or "").upper()
    return f"{code[:4]}-{code[4:]}" if CODE_PATTERN.match(code) else None


def pair(code: str, server: str, opener=urllib.request.urlopen) -> dict:
    """Cambia el código corto de Mi Wi-Fi por la clave del agente. Devuelve {key, prefix, networkName}."""
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


def save_pairing(answer: dict, server: str, path: Optional[Path] = None) -> Path:
    """Guarda la clave recibida (y una sal nueva si no había) solo para el usuario actual."""
    path = path or config_path()
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        config = {}
    config.update(server=validate_server(server), key=answer["key"], network=answer.get("networkName"))
    config.setdefault("salt", secrets.token_hex(16))
    return save_config(config, path)


# ---------------------------------------------------------------------------------------------- línea de comandos

def describe(report: dict) -> str:
    lines = [f"  Red: {report.get('ssid', 'sin Wi-Fi (¿cable?)')}  seguridad {report.get('authentication')}"
             f"  banda {report.get('band', '?')} GHz  canal {report.get('channel', '?')}"
             f"  señal {report.get('signalDbm', '?')} dBm",
             f"  Internet: {report.get('latencyMs', '?')} ms, jitter {report.get('jitterMs', '?')} ms, "
             f"pérdida {report.get('packetLossPct', '?')} %   Router: {report.get('gatewayLatencyMs', '?')} ms",
             f"  Equipos conectados: {report['deviceCount']}   Puertos abiertos en el router: "
             f"{', '.join(map(str, report['openPorts'])) or 'ninguno de los revisados'}"]
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
    code = args.code or input("Código de instalación (Mi Wi-Fi > Agente WiFiSense > Instalar agente): ")
    try:
        answer = pair(code, config["server"])
    except SendError as error:
        print(f"Error: {error}")
        return 1
    print(f"Conectado con la red «{answer.get('networkName', '')}». Guardado en {save_pairing(answer, config['server'])}")
    print("Ahora ejecuta: python wifisense_agent.py run")
    return 0


def ensure_salt(config: dict, path: Optional[Path] = None) -> str:
    """La sal se guarda en el archivo de configuración; la clave que llega por variable de entorno no se escribe."""
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


def command_run(args) -> int:
    config = load_config()
    if not config.get("key"):
        print("Primero ejecuta: python wifisense_agent.py setup")
        return 2
    salt = ensure_salt(config)
    interval = max(args.interval, MIN_INTERVAL)
    while True:
        print(time.strftime("[%H:%M:%S] Midiendo..."))
        report = collect(salt)
        print(describe(report))
        wait, sent = interval, False
        try:
            answer = send(report, config["server"], config["key"])
            sent = True
            print(f"  Enviado. {answer.get('summary', '')}".rstrip())
        except SendError as error:
            print(f"  No se envió: {error}")
            if error.fatal:
                return 1
            wait = max(interval, error.retry_after or 0)
        if args.once:
            return 0 if sent else 1
        time.sleep(wait)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Agente WiFiSense: mide tu red Wi-Fi y la envía a WiFiSense.")
    commands = parser.add_subparsers(dest="command", required=True)
    pair_parser = commands.add_parser("pair", help="conectar con el código de Mi Wi-Fi")
    pair_parser.add_argument("code", nargs="?", help="código de 8 caracteres, por ejemplo K7QM-4RZD")
    pair_parser.set_defaults(handler=command_pair)
    commands.add_parser("setup", help="guardar la clave del agente").set_defaults(handler=command_setup)
    commands.add_parser("scan", help="medir y mostrar sin enviar").set_defaults(handler=command_scan)
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
