"""Instalación del agente en Windows, para el usuario actual y sin permisos de administrador.

Lo que hace es lo mismo que cualquier programa instalado por el usuario, y todo se puede ver y deshacer:

* copia el programa a %LOCALAPPDATA%\\Programs\\WiFiSense;
* si la persona lo marca, lo agrega al inicio de Windows (aparece en Administrador de tareas > Aplicaciones de
  inicio, donde se puede desactivar);
* lo registra en Configuración > Aplicaciones > Aplicaciones instaladas como «Agente WiFiSense», con su opción
  Desinstalar, que borra todo lo anterior y la configuración (la clave del agente).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Protocol

APP_ID = "WiFiSenseAgente"
DISPLAY_NAME = "Agente WiFiSense"
PUBLISHER = "WiFiSense (proyecto universitario)"
EXE_NAME = "WiFiSenseAgente.exe"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\WiFiSenseAgente"


class Registry(Protocol):
    """Lo mínimo del registro de Windows (HKEY_CURRENT_USER) que usa el instalador."""

    def set_values(self, key: str, values: dict) -> None: ...

    def get_value(self, key: str, name: str) -> Optional[str]: ...

    def delete_value(self, key: str, name: str) -> None: ...

    def delete_key(self, key: str) -> None: ...


class WindowsRegistry:
    """HKEY_CURRENT_USER real. Solo existe en Windows; nunca toca HKEY_LOCAL_MACHINE."""

    def __init__(self):
        import winreg  # noqa: PLC0415 - solo existe en Windows
        self.winreg = winreg

    def set_values(self, key: str, values: dict) -> None:
        with self.winreg.CreateKeyEx(self.winreg.HKEY_CURRENT_USER, key, 0, self.winreg.KEY_SET_VALUE) as handle:
            for name, value in values.items():
                kind = self.winreg.REG_DWORD if isinstance(value, int) else self.winreg.REG_SZ
                self.winreg.SetValueEx(handle, name, 0, kind, value)

    def get_value(self, key: str, name: str) -> Optional[str]:
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, key) as handle:
                return self.winreg.QueryValueEx(handle, name)[0]
        except OSError:
            return None

    def delete_value(self, key: str, name: str) -> None:
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_CURRENT_USER, key, 0, self.winreg.KEY_SET_VALUE) as handle:
                self.winreg.DeleteValue(handle, name)
        except OSError:
            pass

    def delete_key(self, key: str) -> None:
        try:
            self.winreg.DeleteKey(self.winreg.HKEY_CURRENT_USER, key)
        except OSError:
            pass


@dataclass(frozen=True)
class Paths:
    install_dir: Path
    data_dir: Path
    config_dir: Path

    @property
    def exe(self) -> Path:
        return self.install_dir / EXE_NAME

    @property
    def log(self) -> Path:
        return self.data_dir / "agente.log"

    @property
    def pid(self) -> Path:
        return self.data_dir / "agente.pid"

    @staticmethod
    def for_user(env=os.environ) -> "Paths":
        local = Path(env.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        roaming = Path(env.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        return Paths(install_dir=local / "Programs" / "WiFiSense", data_dir=local / "WiFiSense",
                     config_dir=roaming / "WiFiSense")


def run_command_line(exe: Path) -> str:
    return f'"{exe}" run'


def is_installed(registry: Registry) -> bool:
    return registry.get_value(UNINSTALL_KEY, "DisplayName") is not None


def starts_with_windows(registry: Registry) -> bool:
    return registry.get_value(RUN_KEY, APP_ID) is not None


def install(source_exe: Path, paths: Paths, registry: Registry, version: str, autostart: bool) -> Path:
    """Copia el programa y lo registra como aplicación instalada (y en el inicio, si se pidió)."""
    paths.install_dir.mkdir(parents=True, exist_ok=True)
    paths.data_dir.mkdir(parents=True, exist_ok=True)
    if source_exe.resolve() != paths.exe.resolve():
        copy_with_retry(source_exe, paths.exe)
    size_kb = max(paths.exe.stat().st_size // 1024, 1)
    registry.set_values(UNINSTALL_KEY, {
        "DisplayName": DISPLAY_NAME,
        "DisplayVersion": version,
        "Publisher": PUBLISHER,
        "DisplayIcon": str(paths.exe),
        "InstallLocation": str(paths.install_dir),
        "UninstallString": f'"{paths.exe}" uninstall',
        "EstimatedSize": int(size_kb),
        "NoModify": 1,
        "NoRepair": 1,
    })
    set_autostart(paths, registry, autostart)
    return paths.exe


def set_autostart(paths: Paths, registry: Registry, enabled: bool) -> None:
    if enabled:
        registry.set_values(RUN_KEY, {APP_ID: run_command_line(paths.exe)})
    else:
        registry.delete_value(RUN_KEY, APP_ID)


def uninstall(paths: Paths, registry: Registry, stop=None, schedule_removal=None) -> None:
    """Detiene el agente, quita el inicio automático y el registro, y borra la configuración (incluida la clave)."""
    (stop or stop_running_agent)(paths)
    registry.delete_value(RUN_KEY, APP_ID)
    registry.delete_key(UNINSTALL_KEY)
    shutil.rmtree(paths.config_dir, ignore_errors=True)
    shutil.rmtree(paths.data_dir, ignore_errors=True)
    # El .exe que está corriendo no se puede borrar a sí mismo: se borra la carpeta un par de segundos después.
    (schedule_removal or schedule_folder_removal)(paths.install_dir)


NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


def start_agent(paths: Paths) -> None:
    """Arranca el agente en segundo plano (el mismo comando que usa el inicio de Windows)."""
    subprocess.Popen([str(paths.exe), "run"], creationflags=NO_WINDOW | DETACHED, close_fds=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def copy_with_retry(source: Path, target: Path, attempts: int = 20, wait: float = 0.5,
                    copy: Callable = shutil.copy2, sleep: Callable = time.sleep) -> None:
    """Copies the program; Windows keeps a file locked for a moment after its process ends, so it tries again."""
    for attempt in range(1, attempts + 1):
        try:
            copy(source, target)
            return
        except PermissionError:
            if attempt == attempts:
                raise
            sleep(wait)


def stop_running_agent(paths: Paths, find: Optional[Callable[[Path], Iterable[int]]] = None,
                       terminate: Optional[Callable[[int], None]] = None) -> None:
    """
    Stops every agent running from the installed program, so it can be replaced. Earlier versions only stopped the
    process of the pid file, but the .exe made by PyInstaller runs as two processes (a launcher and the agent) and both
    keep the file open: copying the new version failed with "WinError 32 ... being used by another process". This one
    and the process that launched it are never touched (the installer may be the installed program itself).
    """
    find = find or processes_running_from
    terminate = terminate or terminate_process
    mine = {os.getpid(), os.getppid()}
    targets = set(find(paths.exe))
    try:
        targets.add(int(paths.pid.read_text(encoding="ascii").strip()))
    except (OSError, ValueError):
        pass
    for pid in sorted(targets - mine):
        if pid in set(find(paths.exe)) or _is_agent(pid):
            terminate(pid)


def _is_agent(pid: int) -> bool:
    """The pid file may be old: the pid is stopped only if it is still the agent."""
    if os.name != "nt":
        return False
    listing = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True,
                             text=True, creationflags=NO_WINDOW).stdout
    return EXE_NAME.lower() in listing.lower()


PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000


def _kernel32():
    import ctypes  # noqa: PLC0415 - solo en Windows
    from ctypes import wintypes  # noqa: PLC0415
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.K32EnumProcesses.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD)]
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return ctypes, wintypes, kernel32


def processes_running_from(exe: Path) -> list[int]:
    """Processes whose program is exactly this file (any user's own process; none outside Windows)."""
    if os.name != "nt":
        return []
    ctypes, wintypes, kernel32 = _kernel32()
    size = 4096
    while True:
        pids = (wintypes.DWORD * size)()
        needed = wintypes.DWORD()
        if not kernel32.K32EnumProcesses(pids, ctypes.sizeof(pids), ctypes.byref(needed)):
            return []
        if needed.value < ctypes.sizeof(pids):
            break
        size *= 2
    # Compared as files, not as text: the same folder can be written with a short name (C:\Users\RUNNER~1).
    target_name = os.path.normcase(exe.name)
    found = []
    for pid in pids[:needed.value // ctypes.sizeof(wintypes.DWORD)]:
        if not pid:
            continue
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            name = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(name))
            if (kernel32.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(length))
                    and os.path.normcase(os.path.basename(name.value)) == target_name
                    and _same_file(name.value, exe)):
                found.append(int(pid))
        finally:
            kernel32.CloseHandle(handle)
    return found


def _same_file(path: str, exe: Path) -> bool:
    try:
        return os.path.samefile(path, exe)
    except OSError:
        return False


def terminate_process(pid: int, wait_ms: int = 5000) -> None:
    """Ends the process and waits until it is really gone (only then Windows releases its program file)."""
    if os.name != "nt":
        return
    _ctypes, _wintypes, kernel32 = _kernel32()
    handle = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 1)
        kernel32.WaitForSingleObject(handle, wait_ms)
    finally:
        kernel32.CloseHandle(handle)


def schedule_folder_removal(folder: Path) -> None:
    subprocess.Popen(f'cmd /c timeout /t 3 /nobreak > nul & rmdir /s /q "{folder}"', shell=True,
                     creationflags=NO_WINDOW | DETACHED, close_fds=True)


def current_executable() -> Path:
    return Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).resolve()
