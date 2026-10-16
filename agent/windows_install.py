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
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

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
        shutil.copy2(source_exe, paths.exe)
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


def stop_running_agent(paths: Paths) -> None:
    """Detiene el agente si está corriendo; comprueba que el PID sea de verdad el agente antes de tocarlo."""
    try:
        pid = int(paths.pid.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return
    if pid == os.getpid():
        return
    listing = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True,
                             text=True, creationflags=NO_WINDOW).stdout
    if EXE_NAME.lower() in listing.lower():
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=NO_WINDOW)


def schedule_folder_removal(folder: Path) -> None:
    subprocess.Popen(f'cmd /c timeout /t 3 /nobreak > nul & rmdir /s /q "{folder}"', shell=True,
                     creationflags=NO_WINDOW | DETACHED, close_fds=True)


def current_executable() -> Path:
    return Path(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).resolve()
