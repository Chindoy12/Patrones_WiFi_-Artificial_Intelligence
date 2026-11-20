"""Entry point of the Windows program (WiFiSenseAgente.exe, packaged with PyInstaller).

* No arguments (double click): opens the installation window.
* ``run``: the agent in the background (what Windows startup uses). As it has no window, it writes what it does to
  %LOCALAPPDATA%\\WiFiSense\\agente.log, and it never runs twice at the same time.
* ``uninstall``: what Windows runs when Uninstall is chosen.
* Any other command of the agent (``scan``, ``pair``...) works the same as with Python.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from agent import wifisense_agent as agent
    from agent import windows_install as setup
except ImportError:  # pragma: no cover - inside the .exe the modules are loose
    import wifisense_agent as agent
    import windows_install as setup

MAX_LOG_BYTES = 1_000_000
MUTEX_NAME = "Local\\WiFiSenseAgente"
ERROR_ALREADY_EXISTS = 183


def open_log(path: Path):
    """A small log file: when it grows past 1 MB it is kept as .1 and starts again."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
        path.replace(path.with_suffix(".log.1"))
    return open(path, "a", encoding="utf-8", buffering=1)


def already_running() -> bool:
    """A named Windows mutex: if another agent already created it, this one exits."""
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
    """The window is loaded only when needed (measuring does not need tkinter)."""
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
    if args[0] == "run" and sys.stdout is None:  # no console: Windows startup or launched by the installer
        return background(args, paths)
    return agent.main(args)


if __name__ == "__main__":
    sys.exit(main())
