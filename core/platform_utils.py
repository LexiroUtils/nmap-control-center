from __future__ import annotations

import os
import platform
import shutil
import sys


def platform_name() -> str:
    return platform.system() or sys.platform


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def is_elevated() -> bool:
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def default_data_root() -> str:
    return "data"
