"""Scan of the nearby Wi-Fi networks: the ones the Wi-Fi antenna of this computer can see.

How it works:
  * On Windows the system is asked for a new scan (WlanScan, from wlanapi.dll, without administrator permissions) and,
    a few seconds later, the list is read with ``netsh wlan show networks mode=bssid``. If the new scan could not be
    asked, the last list Windows has is read, and the result says so (``fresh`` = False).
  * On Linux ``nmcli dev wifi list --rescan yes`` is used (and, if it does not allow rescanning that often, the last
    list).
  * Each access point (BSSID) comes out as a dictionary with what the system said about it. What the system did not
    say stays None: nothing is invented (for example, Windows gives the signal in %, so the signal in dBm stays empty).
  * The BSSID never leaves the computer: its fingerprint with the salt of this installation is sent (like the devices
    of the network) and only its last byte, so the user can recognise their own router by the label.
  * The passwords of the Wi-Fi profiles are never read nor exported.

That a network shows up does not mean it belongs to the user or that they can connect to it: only that the antenna
saw it. Nor is it the list of every network that exists: only the ones this adapter could hear at that moment.

There are two tools (Strategy): ``NetshScanner`` and ``NmcliScanner``; ``scanner_for`` picks the one of the system
(Factory). Both return the same result (Adapter), so the rest of the agent does not know which one was used.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from typing import Callable, Optional

try:  # the agent as a package (tests) or as loose scripts (PyInstaller, python wifisense_agent.py)
    from agent.wifi_text import authentication_of, band_of, cipher_of, console_text, first_number, key_values, \
        normalize_key, split_nmcli
except ImportError:  # pragma: no cover
    from wifi_text import authentication_of, band_of, cipher_of, console_text, first_number, key_values, \
        normalize_key, split_nmcli

COMMAND_TIMEOUT = 20      # seconds netsh or nmcli may take before it is cancelled
FRESH_SCAN_WAIT = 4.0     # seconds Windows needs to finish the scan it was asked for
MAX_ACCESS_POINTS = 300   # the server does not accept more in a single scan
FAILURES = ("NO_ADAPTER", "ADAPTER_OFF", "SERVICE_OFF", "LOCATION_PERMISSION", "COMMAND_FAILED", "TIMEOUT",
            "UNREADABLE_OUTPUT", "UNSUPPORTED_OS")
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")

# -------------------------------------------------------------------------------------------------- system command


class CommandResult:
    """What a command answered: its exit code, its text and whether it timed out or does not exist."""

    def __init__(self, code: Optional[int], text: str, timed_out: bool = False, missing: bool = False):
        self.code, self.text, self.timed_out, self.missing = code, text, timed_out, missing


def run(args: list[str], timeout: float = COMMAND_TIMEOUT) -> CommandResult:
    """Runs a command with its arguments separated (never through the shell, so a network name cannot inject anything)
    and with a time limit."""
    try:
        done = subprocess.run(args, capture_output=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return CommandResult(None, "", timed_out=True)
    except FileNotFoundError:
        return CommandResult(None, "", missing=True)
    except (OSError, subprocess.SubprocessError) as error:
        return CommandResult(None, str(error))
    return CommandResult(done.returncode, console_text(done.stdout) + console_text(done.stderr))


# ----------------------------------------------------------------------------------------------- Windows errors

# What netsh answers (in Spanish or in English) when it cannot scan, and the reason sent to the server.
# They are checked in this order: the location permission also mentions the interface, for example.
FAILURE_HINTS = (
    ("LOCATION_PERMISSION", ("location permission", "location services", "permiso de ubicaci", "servicios de ubicaci")),
    ("SERVICE_OFF", ("wlansvc", "autoconfig service", "configuracion automatica de wlan",
                     "configuración automática de wlan")),
    ("NO_ADAPTER", ("no wireless interface", "ninguna interfaz inal", "no hay interfaces inal")),
)
RADIO_OFF = ("software off", "hardware off", "software apagado", "hardware apagado", "software desactivado",
             "hardware desactivado")


def failure_of(text: str) -> Optional[str]:
    """The reason why netsh could not scan, according to its message; None if the message is not an error."""
    lower = (text or "").lower()
    for reason, hints in FAILURE_HINTS:
        if any(hint in lower for hint in hints):
            return reason
    return None


def radio_off(interfaces_text: str) -> bool:
    """The Wi-Fi is turned off (with the keyboard button, airplane mode or in Settings) according to
    'netsh wlan show interfaces'."""
    lower = (interfaces_text or "").lower()
    return any(hint in lower for hint in RADIO_OFF)


# ------------------------------------------------------------------------------------------------- lectura (netsh)

# Exact keys of 'netsh wlan show networks mode=bssid' already normalized (without accents, spaces or numbers), in
# English and in Spanish, even when the console broke the accent ('Se¤al' -> 'seal'). They are exact on purpose:
# Windows 11 adds 'Channel Utilization', which is not the channel.
SCAN_KEYS = {
    "interface": {"interfacename", "nombredelainterfaz", "nombredeinterfaz"},
    "ssid": {"ssid"},
    "bssid": {"bssid"},
    "authentication": {"authentication", "autenticacion", "autenticacin"},
    "cipher": {"encryption", "cipher", "cifrado"},
    "signal": {"signal", "senal", "seal"},
    "radio": {"radiotype", "tipoderadio"},
    "band": {"band", "banda"},
    "channel": {"channel", "canal"},
}


def scan_key(key: str) -> Optional[str]:
    normalized = normalize_key(key)
    for field, names in SCAN_KEYS.items():
        if normalized in names:
            return field
    return None


def clean_ssid(value: Optional[str]) -> Optional[str]:
    """The name as the network announces it (accents, emoji and quotes included), without control characters; empty is
    a hidden network."""
    if value is None:
        return None
    visible = "".join(c for c in value if c.isprintable())
    return visible[:64] if visible.strip() else None


def parse_netsh_scan(text: str) -> tuple[Optional[str], list[dict]]:
    """(adapter, access points) of 'netsh wlan show networks mode=bssid'. Each access point still carries the MAC:
    ``describe`` replaces it with its fingerprint before it leaves the computer."""
    interface, found = None, []
    network: dict = {}
    current: Optional[dict] = None
    for key, value in key_values(text):
        field = scan_key(key)
        if field == "interface" and interface is None:
            interface = value or None
        elif field == "ssid":
            network = {"ssid": clean_ssid(value), "authentication": None, "cipher": None}
            current = None
        elif field in ("authentication", "cipher") and current is None:
            network[field] = value or None
        elif field == "bssid":
            mac = value.strip().lower().replace("-", ":")
            current = {"mac": mac, **network} if MAC.match(mac) else None
            if current is not None:
                found.append(current)
        elif current is not None and field in ("signal", "radio", "band", "channel"):
            current[field] = value or None
    return interface, [access_point(ap) for ap in found]


def access_point(raw: dict) -> dict:
    """An access point with the names and units the server expects. Whatever is missing stays None."""
    channel = first_number(raw.get("channel") or "")
    channel = int(channel) if channel and 1 <= channel <= 233 else None
    signal = first_number(raw.get("signal") or "")
    auth = raw.get("authentication")
    return {
        "mac": raw["mac"],
        "ssid": raw.get("ssid"),
        "signalPercent": int(signal) if signal is not None and 0 <= signal <= 100 else None,
        "signalDbm": None,  # netsh only gives the percentage: it is not computed
        "channel": channel,
        "band": band_of(raw.get("band") or "", channel) if raw.get("band") or channel else None,
        "radioType": (raw.get("radio") or "")[:20] or None,
        "authentication": authentication_of(auth or "", raw.get("cipher") or "") if auth else "UNKNOWN",
        "securityLabel": (auth or "")[:40] or None,
        "cipher": cipher_of(raw.get("cipher") or "") if raw.get("cipher") else None,
    }


def connected_bssid(interfaces_text: str) -> Optional[str]:
    """The MAC of the access point this computer is connected to, according to 'netsh wlan show interfaces' ('BSSID' on
    Windows 10 and 'AP BSSID' on Windows 11), or None if it is not connected."""
    state, bssid = None, None
    for key, value in key_values(interfaces_text or ""):
        normalized = normalize_key(key)
        if normalized in ("name", "nombre"):
            if state and bssid:
                break
            state, bssid = None, None
        elif normalized in ("state", "estado"):
            state = normalize_key(value).startswith(("connected", "conectado"))
        elif normalized in ("bssid", "apbssid"):
            mac = value.strip().lower().replace("-", ":")
            bssid = mac if MAC.match(mac) else None
    return bssid if state and bssid else None


# ------------------------------------------------------------------------------------------------- lectura (nmcli)

NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY"


def parse_nmcli_scan(text: str) -> list[dict]:
    """Access points of 'nmcli -t -f IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY dev wifi list'."""
    found = []
    for line in (text or "").splitlines():
        parts = split_nmcli(line)
        if len(parts) < 7:
            continue
        in_use, mac, ssid, chan, freq, signal, security = parts[:7]
        mac = mac.strip().lower()
        if not MAC.match(mac):
            continue
        freq_mhz = first_number(freq)
        security = security.strip()
        ap = access_point({"mac": mac, "ssid": clean_ssid(ssid), "channel": chan, "signal": signal,
                           "band": f"{freq_mhz / 1000:.1f}" if freq_mhz else "",
                           "authentication": security if security and security != "--" else "OPEN"})
        ap["securityLabel"] = security[:40] if security and security != "--" else None
        ap["connected"] = in_use.strip() == "*"
        found.append(ap)
    return found


# --------------------------------------------------------------------------------------- new scan on Windows (API)

WLAN_INTERFACE_INFO_SIZE = 532  # GUID (16) + WCHAR[256] (512) + WLAN_INTERFACE_STATE (4)


def request_fresh_scan(library=None, sleep: Callable[[float], None] = time.sleep,
                       wait: float = FRESH_SCAN_WAIT) -> bool:
    """Asks Windows to search for networks again with each Wi-Fi adapter (WlanScan) and waits for it to finish. It asks
    for no administrator permissions and installs nothing. False if it could not be asked (another system, no adapter,
    service stopped or no permission): then the last list Windows has is read."""
    if library is None:
        if os.name != "nt":
            return False
        try:
            library = ctypes.windll.wlanapi
        except (AttributeError, OSError):
            return False
    handle, version = ctypes.c_void_p(), ctypes.c_uint32()
    if library.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return False
    asked = False
    try:
        interfaces = ctypes.c_void_p()
        if library.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces)) != 0 or not interfaces.value:
            return False
        try:
            count = ctypes.c_uint32.from_address(interfaces.value).value
            first = interfaces.value + 8  # dwNumberOfItems and dwIndex come before the list
            for index in range(min(count, 16)):
                guid = ctypes.c_void_p(first + index * WLAN_INTERFACE_INFO_SIZE)
                asked = library.WlanScan(handle, guid, None, None, None) == 0 or asked
        finally:
            library.WlanFreeMemory(interfaces)
    finally:
        library.WlanCloseHandle(handle, None)
    if asked:
        sleep(wait)
    return asked


# ---------------------------------------------------------------------------------------------- herramientas


class ScanOutcome:
    """What a tool obtained: the access points (still with their MAC) or the reason of the failure."""

    def __init__(self, tool: str, access_points: Optional[list] = None, failure: Optional[str] = None,
                 interface: Optional[str] = None, fresh: Optional[bool] = None):
        self.tool, self.access_points, self.failure = tool, access_points or [], failure
        self.interface, self.fresh = interface, fresh


class NetshScanner:
    """Windows: new scan with WlanScan and reading with netsh."""
    tool = "NETSH"

    def __init__(self, runner: Callable[[list[str]], CommandResult] = run,
                 fresh: Callable[[], bool] = request_fresh_scan):
        self.runner, self.fresh = runner, fresh

    def scan(self) -> ScanOutcome:
        fresh = self.fresh()
        listed = self.runner(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if listed.timed_out:
            return ScanOutcome(self.tool, failure="TIMEOUT", fresh=fresh)
        if listed.missing:
            return ScanOutcome(self.tool, failure="COMMAND_FAILED", fresh=fresh)
        reason = failure_of(listed.text)
        if reason:
            return ScanOutcome(self.tool, failure=reason, fresh=fresh)
        interface, access_points = parse_netsh_scan(listed.text)
        if interface is None and not access_points:
            # not even the name of the adapter: netsh answered something that is not the list (another error, another language)
            return ScanOutcome(self.tool, failure="COMMAND_FAILED" if listed.code else "UNREADABLE_OUTPUT",
                               fresh=fresh)
        interfaces = self.runner(["netsh", "wlan", "show", "interfaces"])
        if not access_points and radio_off(interfaces.text):
            return ScanOutcome(self.tool, failure="ADAPTER_OFF", interface=interface, fresh=fresh)
        mine = connected_bssid(interfaces.text)
        for ap in access_points:
            ap["connected"] = mine is not None and ap["mac"] == mine
        return ScanOutcome(self.tool, access_points, interface=interface, fresh=fresh)


class NmcliScanner:
    """Linux with NetworkManager."""
    tool = "NMCLI"

    def __init__(self, runner: Callable[[list[str]], CommandResult] = run):
        self.runner = runner

    def scan(self) -> ScanOutcome:
        base = ["nmcli", "-t", "-f", NMCLI_FIELDS, "dev", "wifi", "list"]
        listed, fresh = self.runner(base + ["--rescan", "yes"]), True
        if not listed.timed_out and not listed.missing and listed.code:
            # NetworkManager does not allow rescanning that often: the last list is read
            listed, fresh = self.runner(base + ["--rescan", "no"]), False
        if listed.timed_out:
            return ScanOutcome(self.tool, failure="TIMEOUT", fresh=fresh)
        if listed.missing:
            return ScanOutcome(self.tool, failure="UNSUPPORTED_OS")
        if listed.code:
            lower = listed.text.lower()
            reason = "NO_ADAPTER" if "no wi-fi device" in lower else "ADAPTER_OFF" if "disabled" in lower \
                else "SERVICE_OFF" if "not running" in lower else "COMMAND_FAILED"
            return ScanOutcome(self.tool, failure=reason, fresh=fresh)
        return ScanOutcome(self.tool, parse_nmcli_scan(listed.text), fresh=fresh)


def scanner_for(platform: str = sys.platform):
    """The tool of the system, or None if this system has none the agent knows how to use (macOS, for example)."""
    if platform.startswith("win"):
        return NetshScanner()
    if platform.startswith("linux"):
        return NmcliScanner()
    return None


# ------------------------------------------------------------------------------------------------- resultado


def describe(ap: dict, fingerprint: Callable[[str], str], vendor: Callable[[str], Optional[str]]) -> dict:
    """The access point as it leaves the computer: the MAC is replaced with its salted fingerprint and its last byte;
    the maker only if the MAC is the factory one (a locally administered MAC does not say who made it)."""
    mac = ap["mac"]
    local = bool(int(mac[:2], 16) & 0b10)
    described = {key: value for key, value in ap.items() if key != "mac"}
    described.update(bssid=fingerprint(mac), bssidSuffix=mac[-2:].upper(), vendor=None if local else vendor(mac))
    described["connected"] = bool(ap.get("connected"))
    return described


def scan(scan_id: int, agent_version: str, fingerprint: Callable[[str], str],
         vendor: Callable[[str], Optional[str]], scanner=None, clock: Callable[[], float] = time.monotonic) -> dict:
    """Scans and builds what is sent to the server for the scan ``scan_id``. It never raises: any problem is returned as
    a failed scan with its reason."""
    started = clock()
    scanner = scanner if scanner is not None else scanner_for()
    result: dict = {"scanId": scan_id, "agentVersion": agent_version}
    if scanner is None:
        outcome = ScanOutcome(None, failure="UNSUPPORTED_OS")
    else:
        try:
            outcome = scanner.scan()
        except Exception as error:  # an odd adapter must not bring the agent down
            print(f"  aviso: el escaneo falló: {error}", file=sys.stderr)
            outcome = ScanOutcome(scanner.tool, failure="COMMAND_FAILED")
    seen: dict[str, dict] = {}
    for ap in outcome.access_points:
        previous = seen.get(ap["mac"])
        if previous is None or (ap.get("signalPercent") or -1) > (previous.get("signalPercent") or -1):
            seen[ap["mac"]] = ap
    strongest = sorted(seen.values(), key=lambda ap: ap.get("signalPercent") or -1, reverse=True)
    result.update({
        "status": "FAILED" if outcome.failure else "COMPLETED",
        "failureReason": outcome.failure if outcome.failure in FAILURES else None,
        "interfaceName": (outcome.interface or "")[:64] or None,
        "scanTool": outcome.tool,
        "fresh": outcome.fresh,
        "durationMs": max(int((clock() - started) * 1000), 0),
        "accessPoints": [] if outcome.failure else
        [describe(ap, fingerprint, vendor) for ap in strongest[:MAX_ACCESS_POINTS]],
    })
    return {key: value for key, value in result.items() if value is not None}


def summary(result: dict) -> str:
    """A line for the console, without any MAC."""
    if result.get("status") == "FAILED":
        return f"Escaneo de redes cercanas: no se pudo ({result.get('failureReason')})."
    access_points = result.get("accessPoints") or []
    names = {ap.get("ssid") for ap in access_points if ap.get("ssid")}
    hidden = sum(1 for ap in access_points if not ap.get("ssid"))
    text = f"Escaneo de redes cercanas: {len(names) + hidden} redes, {len(access_points)} puntos de acceso"
    return text + ("." if result.get("fresh") else " (lista que ya tenía el sistema).")
