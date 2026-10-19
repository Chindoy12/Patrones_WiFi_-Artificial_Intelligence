"""Installation logic of the Windows agent, with a fake registry (the real one only exists on Windows)."""
import json
import os
import shutil
import subprocess
import time
import urllib.error

import pytest

from agent import app
from agent import installation
from agent import wifisense_agent as agent
from agent import windows_install as setup


class FakeRegistry:
    def __init__(self):
        self.keys = {}

    def set_values(self, key, values):
        self.keys.setdefault(key, {}).update(values)

    def get_value(self, key, name):
        return self.keys.get(key, {}).get(name)

    def delete_value(self, key, name):
        self.keys.get(key, {}).pop(name, None)

    def delete_key(self, key):
        self.keys.pop(key, None)


@pytest.fixture
def paths(tmp_path):
    return setup.Paths.for_user({"LOCALAPPDATA": str(tmp_path / "Local"), "APPDATA": str(tmp_path / "Roaming")})


@pytest.fixture
def program(tmp_path):
    exe = tmp_path / "Descargas" / "WiFiSenseAgente (1).exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ" + b"0" * 4096)
    return exe


def test_installs_for_the_current_user_and_shows_up_as_an_installed_app(paths, program):
    registry = FakeRegistry()

    exe = setup.install(program, paths, registry, "1.1.0", autostart=True)

    assert exe == paths.exe and exe.read_bytes() == program.read_bytes()
    entry = registry.keys[setup.UNINSTALL_KEY]
    assert entry["DisplayName"] == "Agente WiFiSense"
    assert entry["UninstallString"] == f'"{paths.exe}" uninstall'
    assert entry["DisplayVersion"] == "1.1.0"
    assert registry.get_value(setup.RUN_KEY, setup.APP_ID) == f'"{paths.exe}" run'
    assert setup.is_installed(registry) and setup.starts_with_windows(registry)
    assert "Local" in str(paths.install_dir) and "Programs" in str(paths.install_dir)


def test_starting_with_windows_is_the_users_choice(paths, program):
    registry = FakeRegistry()
    setup.install(program, paths, registry, "1.1.0", autostart=False)
    assert not setup.starts_with_windows(registry)

    setup.set_autostart(paths, registry, True)
    assert setup.starts_with_windows(registry)


def test_uninstall_removes_everything_including_the_key(paths, program):
    registry = FakeRegistry()
    setup.install(program, paths, registry, "1.1.0", autostart=True)
    paths.config_dir.mkdir(parents=True)
    (paths.config_dir / "agent.json").write_text('{"key": "wsa_x"}')
    stopped, removed = [], []

    setup.uninstall(paths, registry, stop=stopped.append, schedule_removal=removed.append)

    assert stopped == [paths]
    assert removed == [paths.install_dir]
    assert not setup.is_installed(registry) and not setup.starts_with_windows(registry)
    assert not paths.config_dir.exists() and not paths.data_dir.exists()


def test_stopping_ignores_a_missing_or_foreign_pid(paths):
    paths.data_dir.mkdir(parents=True)
    setup.stop_running_agent(paths)  # no pid file: nothing to do
    paths.pid.write_text(str(os.getpid()))
    setup.stop_running_agent(paths)  # its own pid: never kills itself


@pytest.mark.parametrize("typed, expected", [
    ("k7qm 4rzd", "K7QM-4RZD"), ("K7QM-4RZD", "K7QM-4RZD"), (" k7qm4rzd ", "K7QM-4RZD"),
    ("O0O0-1I1I", None), ("K7QM-4RZ", None), ("", None),
])
def test_codes_are_read_the_way_people_type_them(typed, expected):
    assert agent.normalize_code(typed) == expected


class Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


def test_pairing_exchanges_the_code_for_the_key_and_saves_it_privately(tmp_path):
    sent = {}

    def opener(request, timeout):
        sent.update(url=request.full_url, body=json.loads(request.data), key=request.get_header("X-agent-key"))
        return Response(json.dumps({"key": "wsa_" + "k" * 43, "prefix": "wsa_kkkk", "networkName": "Casa"}).encode())

    answer = agent.pair("k7qm 4rzd", "https://wifisense.example.com", opener=opener)
    path = agent.save_pairing(answer, "https://wifisense.example.com", tmp_path / "agent.json")

    assert sent == {"url": "https://wifisense.example.com/api/agent/pair", "body": {"code": "K7QM-4RZD"}, "key": None}
    saved = json.loads(path.read_text())
    assert saved["networks"] == [{"key": "wsa_" + "k" * 43, "network": "Casa", "ssid": None}]
    assert len(saved["salt"]) == 32
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_a_wrong_code_is_explained_and_not_retried():
    def opener(request, timeout):
        body = json.dumps({"detail": "El código no es válido o ya venció."}).encode()
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, __import__("io").BytesIO(body))

    with pytest.raises(agent.SendError) as error:
        agent.pair("K7QM-4RZD", "https://wifisense.example.com", opener=opener)
    assert error.value.fatal
    assert "El código no es válido" in str(error.value)
    with pytest.raises(agent.SendError):
        agent.pair("mal", "https://wifisense.example.com", opener=opener)


def test_background_log_is_kept_small(tmp_path):
    log = tmp_path / "WiFiSense" / "agente.log"
    log.parent.mkdir()
    log.write_bytes(b"x" * (app.MAX_LOG_BYTES + 1))

    with app.open_log(log) as handle:
        handle.write("nuevo\n")

    assert log.read_text() == "nuevo\n"
    assert (tmp_path / "WiFiSense" / "agente.log.1").stat().st_size > app.MAX_LOG_BYTES


def test_commands_other_than_install_go_to_the_agent(monkeypatch):
    called = []
    monkeypatch.setattr(agent, "main", lambda args: called.append(args) or 0)

    assert app.main(["scan"]) == 0
    assert called == [["scan"]]


def test_copying_waits_while_windows_keeps_the_old_program_locked(tmp_path):
    attempts, waits = [], []

    def locked_twice(source, target):
        attempts.append(target)
        if len(attempts) < 3:
            raise PermissionError(32, "El proceso no tiene acceso al archivo porque está siendo utilizado")

    setup.copy_with_retry(tmp_path / "a.exe", tmp_path / "b.exe", copy=locked_twice, sleep=waits.append)
    assert len(attempts) == 3 and waits == [0.5, 0.5]

    with pytest.raises(PermissionError):
        setup.copy_with_retry(tmp_path / "a.exe", tmp_path / "b.exe", attempts=2,
                              copy=lambda *_: (_ for _ in ()).throw(PermissionError(32, "en uso")), sleep=waits.append)


def test_stopping_ends_every_agent_running_from_the_installed_program_but_never_the_installer(paths):
    ended = []
    running = {os.getpid(), os.getppid(), 4100, 4200}  # the installer (and its launcher) and the old agent's two

    setup.stop_running_agent(paths, find=lambda exe: sorted(running) if exe == paths.exe else [],
                             terminate=ended.append)

    assert ended == [4100, 4200]


class Steps:
    """Fakes for the installation, recording the order in which they happen."""

    def __init__(self, copy_error=None, pair_error=None):
        self.done = []
        self.copy_error = copy_error
        self.pair_error = pair_error

    def stop(self, paths):
        self.done.append("stop")

    def copy_in(self):
        self.done.append("copy")
        if self.copy_error:
            raise self.copy_error
        return "C:/WiFiSense/WiFiSenseAgente.exe"

    def pair(self, code, server):
        self.done.append("pair")
        if self.pair_error:
            raise self.pair_error
        return {"key": "wsa_" + "k" * 43, "networkName": "Lab-Redes"}

    def start(self, paths):
        self.done.append("start")


@pytest.fixture
def configured(monkeypatch, paths):
    """An agent already installed and measuring another network."""
    paths.install_dir.mkdir(parents=True)
    paths.exe.write_bytes(b"MZ")
    saved = []
    monkeypatch.setattr(agent, "load_config", lambda: {"server": "https://wifisense.example.com", "key": "wsa_old"})
    monkeypatch.setattr(agent, "current_ssid", lambda: "Lab-Redes")
    monkeypatch.setattr(agent, "save_pairing",
                        lambda answer, server, ssid=None: saved.append((answer["networkName"], ssid)))
    return saved


def run(steps, paths):
    return installation.install_and_pair("K7QM-4RZD", True, paths, FakeRegistry(), pair=steps.pair, stop=steps.stop,
                                         copy_in=steps.copy_in, start=steps.start)


def test_the_code_is_used_only_after_the_program_is_in_place(paths, configured):
    steps = Steps()

    assert run(steps, paths) == ("Lab-Redes", "C:/WiFiSense/WiFiSenseAgente.exe")
    assert steps.done == ["stop", "copy", "pair", "start"]
    assert configured == [("Lab-Redes", "Lab-Redes")]  # the key is tied to the Wi-Fi the computer is on


def test_if_windows_does_not_let_copy_the_code_is_not_spent(paths, configured):
    steps = Steps(copy_error=PermissionError(32, "El proceso no tiene acceso al archivo"))

    message = run(steps, paths)

    assert "pair" not in steps.done
    assert "el código no se gastó" in message and "Administrador de tareas" in message
    assert steps.done[-1] == "start"  # the agent that was installed goes on measuring its network
    assert configured == []


def test_a_refused_code_keeps_the_previous_agent_measuring(paths, configured):
    steps = Steps(pair_error=agent.SendError("el servidor respondió 400: El código no es válido", fatal=True))

    message = run(steps, paths)

    assert message.startswith("No se pudo instalar: el servidor respondió 400")
    assert steps.done == ["stop", "copy", "pair", "start"]
    assert configured == []


@pytest.mark.skipif(os.name != "nt", reason="solo en Windows: un programa en ejecución no se puede reemplazar")
def test_reinstalling_replaces_the_program_while_the_old_agent_is_running(paths, program):
    paths.install_dir.mkdir(parents=True)
    shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), paths.exe)
    old_agent = subprocess.Popen([str(paths.exe), "-n", "60", "127.0.0.1"], stdout=subprocess.DEVNULL)
    try:
        time.sleep(1)
        assert old_agent.pid in setup.processes_running_from(paths.exe)
        with pytest.raises(PermissionError):
            setup.copy_with_retry(program, paths.exe, attempts=1)  # what the old installer ran into

        setup.stop_running_agent(paths)
        setup.install(program, paths, FakeRegistry(), "1.5.0", autostart=False)

        assert old_agent.wait(timeout=10) is not None
        assert paths.exe.read_bytes() == program.read_bytes()
    finally:
        old_agent.kill()
