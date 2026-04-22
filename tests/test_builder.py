from __future__ import annotations

import shutil
from pathlib import Path

from core.builder import CommandBuilder
from core.models import ScanConfig


def tmp_dir(name: str) -> Path:
    path = Path(__file__).resolve().parent / "_tmp" / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


def test_builder_creates_argument_list() -> None:
    tmp_path = tmp_dir("builder")
    config = ScanConfig()
    config.targets.targets = ["example.com"]
    config.port_scan.scan_types = ["-sS"]
    config.port_scan.ports = "22,80,443"
    config.service.service_detection = True
    config.os.os_detection = True
    config.scripts.categories = ["safe", "vuln"]
    config.timing.template = 4
    config.output.xml = True

    plan = CommandBuilder("nmap").build(config, tmp_path)

    assert plan.argv[0] == "nmap"
    assert "-sS" in plan.args
    assert ["-p", "22,80,443"][0] in plan.args
    assert "-sV" in plan.args
    assert "-O" in plan.args
    assert "--script" in plan.args
    assert "safe,vuln" in plan.args
    assert "-T4" in plan.args
    assert "example.com" in plan.args
    assert plan.requires_privilege is True
    assert "nmap" in plan.preview()


def test_raw_mode_uses_raw_args_and_targets() -> None:
    tmp_path = tmp_dir("raw")
    config = ScanConfig(raw_args=["-sV", "-p", "80"])
    config.targets.targets = ["192.168.1.1"]

    plan = CommandBuilder("nmap").build(config, tmp_path)

    assert plan.argv[:4] == ["nmap", "-sV", "-p", "80"]
    assert "192.168.1.1" in plan.argv


def test_evasion_adds_warning() -> None:
    tmp_path = tmp_dir("evasion")
    config = ScanConfig()
    config.targets.targets = ["10.0.0.1"]
    config.evasion.fragment_packets = True

    plan = CommandBuilder("nmap").build(config, tmp_path)

    assert "-f" in plan.args
    assert plan.requires_privilege is True
    assert any("Evasion" in warning for warning in plan.warnings)
