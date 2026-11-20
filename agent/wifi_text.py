"""How to read what the system says about the Wi-Fi: netsh keys in Spanish or in English, numbers, security type,
cipher, band and the columns of nmcli. The measurement of the agent (wifisense_agent.py) and the scan of nearby
networks (wifi_scan.py) use it, so both read the system the same way.

Standard library only.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional


def console_text(raw: bytes) -> str:
    """What a command wrote, as text: netsh writes in the code page of the console (cp850 in Spanish), so UTF-8 is
    tried first and latin-1, which decodes anything, last."""
    for encoding in ("utf-8", "oem", "cp850", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")  # pragma: no cover (latin-1 always decodes)


def normalize_key(key: str) -> str:
    """netsh key in lowercase, without accents or spaces ('Autenticación' -> 'autenticacion')."""
    ascii_key = unicodedata.normalize("NFKD", key.lower())
    return "".join(c for c in ascii_key if "a" <= c <= "z")

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
    """Text of the system -> OPEN, WEP, WPA, WPA2, WPA3 or UNKNOWN (what the security audit of the AI understands)."""
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
    """Short name of the cipher. Some versions of Windows write a long description (for example several ciphers or the
    name of the provider); the server only accepts up to 20 characters."""
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

def split_nmcli(line: str) -> list[str]:
    """nmcli -t separates with ':' and escapes the ':' of the values with '\\:'."""
    return [part.replace("\\:", ":") for part in re.split(r"(?<!\\):", line)]
