from __future__ import annotations

import subprocess
from dataclasses import dataclass

from core.platform_utils import find_executable


@dataclass(frozen=True)
class NmapInfo:
    path: str | None
    version: str | None
    available: bool
    error: str | None = None


def detect_nmap() -> NmapInfo:
    path = find_executable("nmap")
    if not path:
        return NmapInfo(path=None, version=None, available=False, error="Nmap was not found in PATH.")
    try:
        completed = subprocess.run(
            [path, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except OSError as exc:
        return NmapInfo(path=path, version=None, available=False, error=str(exc))
    except subprocess.TimeoutExpired:
        return NmapInfo(path=path, version=None, available=False, error="Nmap version check timed out.")
    first_line = (completed.stdout or completed.stderr).splitlines()[0:1]
    return NmapInfo(
        path=path,
        version=first_line[0] if first_line else "Unknown Nmap version",
        available=completed.returncode == 0,
        error=None if completed.returncode == 0 else completed.stderr.strip(),
    )
