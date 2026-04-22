from __future__ import annotations

import shutil
from pathlib import Path

from core.models import ScanConfig
from core.profiles import ProfileStore


def test_profile_save_load_delete() -> None:
    tmp_path = Path(__file__).resolve().parent / "_tmp" / "profiles"
    if tmp_path.exists():
        shutil.rmtree(tmp_path)
    tmp_path.mkdir(parents=True)
    store = ProfileStore(tmp_path)
    config = ScanConfig()
    config.targets.targets = ["example.com"]
    config.port_scan.ports = "80,443"

    path = store.save("web scan", config)
    assert path.exists()
    assert store.list_profiles() == ["web-scan"]

    loaded = store.load("web scan")
    assert loaded.targets.targets == ["example.com"]
    assert loaded.port_scan.ports == "80,443"

    store.delete("web scan")
    assert store.list_profiles() == []
