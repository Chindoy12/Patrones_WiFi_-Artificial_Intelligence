"""The agent runs on the user's computer; these tests cover what it reads from the system and what it sends."""
import io
import json
import os
import urllib.error

import pytest

from agent import wifisense_agent as agent

NETSH_ES = """
Hay 1 interfaz en el sistema:

    Nombre                 : Wi-Fi
    Descripción            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 0b5c6c3e-0000-0000-0000-000000000000
    Dirección física       : 4c:79:6e:00:00:01
    Tipo de interfaz       : Principal
    Estado                 : conectado
    SSID                   : Casa_Lopez
    AP BSSID               : 9c:a2:f4:00:00:02
    Banda                  : 5 GHz
    Canal                  : 44
    Tipo de radio          : 802.11ac
    Autenticación          : WPA2-Personal
    Cifrado                : CCMP
    Modo de conexión       : Conexión automática
    Velocidad de recepción (Mbps)  : 433.3
    Velocidad de transmisión (Mbps) : 390
    Señal                  : 82%
    Perfil                 : Casa_Lopez
"""

NETSH_EN_WEP = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : OldRouter
    BSSID                  : 00:11:22:33:44:55
    Radio type             : 802.11g
    Authentication         : Open
    Cipher                 : WEP
    Channel                : 6
    Receive rate (Mbps)    : 54
    Transmit rate (Mbps)   : 54
    Signal                 : 40%
    Rssi                   : -71
"""

NETSH_NETWORKS = """
SSID 1 : Casa_Lopez
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    BSSID 1                 : 9c:a2:f4:00:00:02
         Señal             : 82%
         Canal            : 44
    BSSID 2                 : 9c:a2:f4:00:00:03
         Canal            : 6
SSID 2 : Vecino_1
    BSSID 1                 : aa:bb:cc:00:00:01
         Canal            : 44
SSID 3 : Vecino_2
    BSSID 1                 : aa:bb:cc:00:00:02
         Canal            : 6
SSID 4 :
    BSSID 1                 : aa:bb:cc:00:00:03
         Canal            : 44
"""


def test_reads_wifi_from_spanish_netsh():
    info = agent.parse_netsh_interfaces(NETSH_ES)

    assert info["ssid"] == "Casa_Lopez"
    assert info["authentication"] == "WPA2"
    assert info["cipher"] == "CCMP"
    assert info["band"] == "5"
    assert info["channel"] == 44
    assert info["signalPercent"] == 82
    assert info["signalDbm"] == -59
    assert info["rxRateMbps"] == 433.3
    assert info["txRateMbps"] == 390


def test_reads_wifi_from_english_netsh_and_prefers_rssi():
    info = agent.parse_netsh_interfaces(NETSH_EN_WEP)

    assert info["authentication"] == "WEP"
    assert info["signalDbm"] == -71
    assert info["band"] == "2.4"


def test_netsh_without_wifi_or_permission_returns_nothing():
    assert agent.parse_netsh_interfaces("Hay 0 interfaces en el sistema.") == {}


def test_counts_neighbors_on_the_same_channel_excluding_own_network():
    networks = agent.parse_netsh_networks(NETSH_NETWORKS)

    assert agent.neighbors_on_channel(networks, "Casa_Lopez", 44) == (2, 3)


@pytest.mark.parametrize("auth, cipher, expected", [
    ("WPA3-Personal", "GCMP", "WPA3"), ("WPA2-Personal", "CCMP", "WPA2"), ("WPA-Personal", "TKIP", "WPA"),
    ("Abierta", "WEP", "WEP"), ("Abierta", "Ninguno", "OPEN"), ("Open", "None", "OPEN"),
    ("WPA2 WPA3", "", "WPA3"), ("", "", "UNKNOWN"),
])
def test_authentication_mapping(auth, cipher, expected):
    assert agent.authentication_of(auth, cipher) == expected


def test_reads_wifi_from_nmcli_with_escaped_colons():
    text = ("no:Vecino:6:2437 MHz:60:WPA2:130 Mbit/s\n"
            "yes:Mi\\:Red:36:5180 MHz:74:WPA2 WPA3:866 Mbit/s\n"
            "no:Otro:36:5180 MHz:30:WPA1:54 Mbit/s\n")

    info, networks = agent.parse_nmcli(text)

    assert info["ssid"] == "Mi:Red"
    assert info["authentication"] == "WPA3"
    assert info["band"] == "5"
    assert info["signalDbm"] == -63
    assert agent.neighbors_on_channel(networks, "Mi:Red", 36) == (1, 2)


def test_default_gateway_on_windows_takes_the_lowest_metric():
    text = """
IPv4 Tabla de enrutamiento
Rutas activas:
Destino de red        Máscara de red   Puerta de enlace   Interfaz  Métrica
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.23     50
          0.0.0.0          0.0.0.0      10.10.0.1      10.10.0.5        25
"""
    assert agent.parse_route_print(text) == "10.10.0.1"


def test_default_gateway_on_linux():
    text = ("Iface\tDestination\tGateway \tFlags\n"
            "wlan0\t0000A8C0\t00000000\t0001\n"
            "wlan0\t00000000\t0101A8C0\t0003\n")
    assert agent.parse_proc_route(text) == "192.168.1.1"


def test_arp_table_on_windows_keeps_only_real_devices():
    text = """
Interfaz: 192.168.1.23 --- 0xb
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           9c-a2-f4-00-00-02     dinámico
  192.168.1.40          D2-11-22-33-44-55     dinámico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  10.0.0.9              aa-aa-aa-aa-aa-aa     dinámico
"""
    table = agent.same_subnet(agent.parse_neighbors(text), "192.168.1.23")

    assert table == {"192.168.1.1": "9c:a2:f4:00:00:02", "192.168.1.40": "d2:11:22:33:44:55"}


def test_arp_table_on_linux_skips_incomplete_entries():
    text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         9c:a2:f4:00:00:02     *        wlan0\n"
            "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
    assert agent.parse_neighbors(text) == {"192.168.1.1": "9c:a2:f4:00:00:02"}


def test_mac_fingerprints_do_not_reveal_the_mac_and_depend_on_the_salt():
    one = agent.mac_fingerprint("9C:A2:F4:00:00:02", "sal-1")

    assert one == agent.mac_fingerprint("9c:a2:f4:00:00:02", "sal-1")
    assert one != agent.mac_fingerprint("9c:a2:f4:00:00:02", "sal-2")
    assert "9ca2f4" not in one
    assert len(one) == 24


def test_latency_summary_counts_silence_as_loss():
    samples = [10.0, 12.0, None, 11.0, None]

    assert agent.summarize(samples) == {"latencyMs": 11.0, "jitterMs": 1.5, "packetLossPct": 40.0}
    assert agent.summarize([None, None])["latencyMs"] is None


def test_measure_uses_the_probe(monkeypatch):
    monkeypatch.setattr(agent.time, "sleep", lambda _: None)
    values = iter([20.0, 22.0, 21.0])

    result = agent.measure("1.1.1.1", 443, count=3, probe=lambda host, port: next(values))

    assert result["latencyMs"] == 21.0
    assert result["packetLossPct"] == 0.0


def test_report_leaves_out_what_could_not_be_measured():
    report = agent.build_report({"ssid": "Casa", "authentication": "WPA2", "channel": 6},
                                {"latencyMs": 20.0, "jitterMs": 2.0, "packetLossPct": 0.0}, None,
                                [{"id": "a" * 24, "vendor": "Apple", "name": "iPhone"}, {"id": "b" * 24}], [80, 443])

    assert report["deviceCount"] == 2
    assert report["deviceHashes"] == ["a" * 24, "b" * 24]
    assert report["devices"] == [{"id": "a" * 24, "vendor": "Apple", "name": "iPhone"}, {"id": "b" * 24}]
    assert report["openPorts"] == [80, 443]
    assert "gatewayLatencyMs" not in report
    assert "signalDbm" not in report
    assert report["agentVersion"] == agent.AGENT_VERSION


@pytest.mark.parametrize("mac, vendor", [
    ("FC:FB:FB:11:22:33", "Apple"), ("ec:fa:bc:00:11:22", "Samsung"), ("b8-27-eb-aa-bb-cc", "Raspberry Pi"),
    ("5c:62:8b:00:00:01", "TP-Link"), ("00:11:22:33:44:55", None),
])
def test_vendor_comes_from_the_mac_oui(mac, vendor):
    assert agent.vendor_of(mac) == vendor


def test_devices_carry_a_fingerprint_vendor_and_name(monkeypatch):
    monkeypatch.setattr(agent, "wake_neighbors", lambda ip: None)
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)
    monkeypatch.setattr(agent, "IS_WINDOWS", False)
    monkeypatch.setattr(agent, "read_file", lambda _p: (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         fc:fb:fb:11:22:33     *        wlan0\n"
        "192.168.1.9      0x1         0x2         00:11:22:33:44:55     *        wlan0\n"))
    monkeypatch.setattr(agent, "own_mac", lambda: None)
    monkeypatch.setattr(agent, "hostname_of", lambda ip: {"192.168.1.5": "iPhone-de-Ana"}.get(ip))

    found = agent.devices("192.168.1.2", "sal", wait=0)

    by_vendor = {d.get("vendor"): d for d in found}
    assert len(found) == 2
    assert by_vendor["Apple"]["id"] == agent.mac_fingerprint("fc:fb:fb:11:22:33", "sal")
    assert by_vendor["Apple"]["name"] == "iPhone-de-Ana"
    assert None in by_vendor  # el equipo sin OUI conocido no lleva fabricante
    assert "name" not in by_vendor[None]  # tampoco nombre si nadie respondió
    assert all("fc:fb:fb" not in device["id"] for device in found)  # la MAC nunca viaja


@pytest.mark.parametrize("raw, ip, expected", [
    ("iPhone-de-Ana.lan", "192.168.1.5", "iPhone-de-Ana"), ("PC-SALA.local.", "192.168.1.6", "PC-SALA"),
    ("galaxy-s21", "192.168.1.7", "galaxy-s21"), ("192.168.1.8", "192.168.1.8", None),
    ("", "192.168.1.9", None), (None, "192.168.1.9", None),
])
def test_clean_hostname(raw, ip, expected):
    assert agent.clean_hostname(raw, ip) == expected


def test_netbios_name_reads_the_unique_entry(monkeypatch):
    output = (
        "Nombre            Tipo         Estado\n"
        "---------------------------------------------\n"
        "LAPTOP-ANA     <00>  UNIQUE      Registrado\n"
        "GRUPO_TRABAJO  <00>  GROUP       Registrado\n")
    monkeypatch.setattr(agent, "run_command", lambda *a, **k: output)
    assert agent.netbios_name("192.168.1.5") == "LAPTOP-ANA"


@pytest.mark.parametrize("url, ok", [
    ("https://wifisense.example.com/", True), ("http://localhost:8099", True), ("http://127.0.0.1:8080", True),
    ("http://wifisense.example.com", False), ("ftp://localhost", False), ("https://", False),
])
def test_server_must_use_https_except_locally(url, ok):
    if ok:
        assert agent.validate_server(url).startswith(("https://", "http://"))
    else:
        with pytest.raises(ValueError):
            agent.validate_server(url)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_send_posts_json_with_the_agent_key():
    seen = {}

    def opener(request, timeout):
        seen.update(url=request.full_url, key=request.get_header("X-agent-key"), body=json.loads(request.data))
        return FakeResponse(b'{"summary": "ok"}')

    answer = agent.send({"deviceCount": 3}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)

    assert answer == {"summary": "ok"}
    assert seen["url"] == "https://wifisense.example.com/api/agent/reports"
    assert seen["key"].startswith("wsa_")
    assert seen["body"] == {"deviceCount": 3}


@pytest.mark.parametrize("code, fatal, retry", [(401, True, None), (429, False, 60), (500, False, None)])
def test_send_errors(code, fatal, retry):
    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, code, "error", {}, None)

    with pytest.raises(agent.SendError) as error:
        agent.send({}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)
    assert error.value.fatal is fatal
    assert error.value.retry_after == retry


def test_config_is_private_and_env_overrides(tmp_path, monkeypatch):
    path = tmp_path / "WiFiSense" / "agent.json"
    agent.save_config({"server": "https://a.example.com", "key": "wsa_" + "k" * 43, "salt": "s"}, path)

    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", "wsa_" + "e" * 43)
    config = agent.load_config(path)
    assert config["key"] == "wsa_" + "e" * 43
    assert config["server"] == "https://a.example.com"


def test_key_format():
    assert agent.KEY_PATTERN.match("wsa_" + "A1_-" * 11)
    assert not agent.KEY_PATTERN.match("wsa_corta")
    assert not agent.KEY_PATTERN.match("Bearer " + "x" * 40)


def test_salt_is_saved_without_writing_the_key_from_the_environment(tmp_path, monkeypatch):
    path = tmp_path / "agent.json"
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", "wsa_" + "e" * 43)
    config = agent.load_config(path)

    salt = agent.ensure_salt(config, path)

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored == {"salt": salt}
    assert agent.ensure_salt(agent.load_config(path), path) == salt


def test_send_shows_why_the_server_rejected_the_report():
    body = io.BytesIO(json.dumps({"detail": "Revisa los datos ingresados.",
                                  "errors": {"neighborsTotal": "debe ser menor que o igual a 500"}}).encode())

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, body)

    with pytest.raises(agent.SendError) as error:
        agent.send({}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)
    assert str(error.value) == ("el servidor respondió 400: Revisa los datos ingresados. | "
                                "neighborsTotal: debe ser menor que o igual a 500")


@pytest.mark.parametrize("text, expected", [
    ("CCMP", "CCMP"), ("GCMP-256", "GCMP-256"), ("TKIP", "TKIP"), ("Ninguno", "NONE"), ("", None),
    ("CCMP (cifrado de grupo: TKIP) Microsoft", "CCMP"), ("Algo desconocido y muy largo del fabricante", "Algo desconocido y m"),
])
def test_cipher_is_always_short(text, expected):
    assert agent.cipher_of(text) == expected
    assert expected is None or len(agent.cipher_of(text)) <= 20
