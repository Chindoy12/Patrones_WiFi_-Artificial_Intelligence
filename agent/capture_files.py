"""Temporary files of the captures and their retention policy.

pktmon writes what it captures to a file (.etl) that is then converted to .pcapng to be counted. Those files:
  * live in a folder of the user who runs the agent (on Windows inside %LOCALAPPDATA%, which is already private to
    each user; on Linux with permissions 700), never in a shared folder;
  * keep at most 128 bytes of each packet (headers, not content);
  * are deleted as soon as the count ends, whether it went well or not (TempCapture is a context manager);
  * if the agent closed in the middle of a capture, the leftovers older than an hour are deleted on start (purge_old).
They are never sent to the server nor can they be downloaded from the page: the server only receives the counts.
"""
from __future__ import annotations

import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Optional

RETENTION_SECONDS = 3600
IS_WINDOWS = os.name == "nt"


def captures_dir(base: Optional[Path] = None) -> Path:
    """Folder of the temporary captures, created only for this user."""
    if base is None:
        root = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else os.environ.get("XDG_CACHE_HOME")
        base = Path(root or Path.home() / ".cache") / "WiFiSense"
    folder = base / "capturas"
    folder.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        os.chmod(folder, 0o700)
    return folder


def purge_old(folder: Path, now: Optional[float] = None, max_age: int = RETENTION_SECONDS) -> int:
    """Deletes what was left of interrupted captures (older than ``max_age`` seconds). Returns how many it deleted."""
    now = time.time() if now is None else now
    removed = 0
    for entry in folder.iterdir() if folder.exists() else ():
        try:
            if now - entry.stat().st_mtime < max_age:
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink()
            removed += 1
        except OSError:
            continue
    return removed


class TempCapture:
    """A folder for a single capture, deleted entirely when the ``with`` block ends, even after an error."""

    def __init__(self, folder: Path):
        self.path = folder / f"captura-{int(time.time())}-{secrets.token_hex(4)}"

    def __enter__(self) -> "TempCapture":
        self.path.mkdir(mode=0o700)
        return self

    def file(self, name: str) -> Path:
        return self.path / name

    def __exit__(self, *_exc) -> None:
        shutil.rmtree(self.path, ignore_errors=True)

    @property
    def removed(self) -> bool:
        return not self.path.exists()
