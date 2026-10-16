"""Punto de entrada del programa para Windows (WiFiSenseAgente.exe, empaquetado con PyInstaller).

* Sin argumentos (doble clic): abre la ventana de instalación.
* ``run``: el agente en segundo plano (lo usa el inicio de Windows). Como no tiene ventana, escribe lo que hace en
  %LOCALAPPDATA%\\WiFiSense\\agente.log, y nunca corre dos veces a la vez.
* ``uninstall``: lo que ejecuta Windows al elegir Desinstalar.
* Cualquier otro comando del agente (``scan``, ``pair``…) funciona igual que con Python.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from agent import wifisense_agent as agent
    from agent import windows_install as setup
except ImportError:  # pragma: no cover - dentro del .exe los módulos están sueltos
    import wifisense_agent as agent
    import windows_install as setup

MAX_LOG_BYTES = 1_000_000
MUTEX_NAME = "Local\\WiFiSenseAgente"
ERROR_ALREADY_EXISTS = 183


def open_log(path: Path):
    """Archivo de registro pequeño: cuando pasa de 1 MB se guarda como .1 y empieza de nuevo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
        path.replace(path.with_suffix(".log.1"))
    return open(path, "a", encoding="utf-8", buffering=1)


def already_running() -> bool:
    """Un mutex con nombre de Windows: si otro agente ya lo creó, este se cierra."""
    if os.name != "nt":
        return False
    import ctypes  # noqa: PLC0415
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW(None, False, MUTEX_NAME)
    return kernel32.GetLastError() == ERROR_ALREADY_EXISTS


def background(args: list[str], paths: setup.Paths) -> int:
    if already_running():
        return 0
    log = open_log(paths.log)
    sys.stdout = sys.stderr = log
    paths.pid.write_text(str(os.getpid()), encoding="ascii")
    try:
        return agent.main(args)
    finally:
        paths.pid.unlink(missing_ok=True)


def gui():
    """La ventana se carga solo cuando hace falta (tkinter no se necesita para medir)."""
    try:
        from agent import installer_gui  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        import installer_gui  # noqa: PLC0415
    return installer_gui


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    paths = setup.Paths.for_user()
    if not args:
        gui().open_installer()
        return 0
    if args[0] == "uninstall":
        gui().confirm_uninstall()
        return 0
    if args[0] == "run" and sys.stdout is None:  # sin consola: inicio de Windows o lanzado por el instalador
        return background(args, paths)
    return agent.main(args)


if __name__ == "__main__":
    sys.exit(main())
