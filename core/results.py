from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from core.models import ScanRunMetadata


class ResultStore:
    def __init__(self, root: Path | str = "data/results") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create_run_dir(self, label: str = "scan") -> Path:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in label)[:60].strip("-") or "scan"
        path = self.root / f"{stamp}_{safe}"
        path.mkdir(parents=True, exist_ok=False)
        return path

    def save_metadata(self, run_dir: Path, metadata: ScanRunMetadata) -> Path:
        path = run_dir / "metadata.json"
        path.write_text(json.dumps(asdict(metadata), indent=2, sort_keys=True), encoding="utf-8")
        return path

    def save_command(self, run_dir: Path, preview: str) -> Path:
        path = run_dir / "command.txt"
        path.write_text(preview + "\n", encoding="utf-8")
        return path

    def list_runs(self) -> list[Path]:
        return sorted([path for path in self.root.iterdir() if path.is_dir()], reverse=True)

    def load_metadata(self, run_dir: Path) -> dict:
        path = run_dir / "metadata.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"error": "metadata.json is corrupted"}

    def find_text_outputs(self, run_dir: Path) -> list[Path]:
        return sorted(path for path in run_dir.iterdir() if path.suffix.lower() in {".nmap", ".gnmap", ".txt", ".log"})

    def find_xml_outputs(self, run_dir: Path) -> list[Path]:
        return sorted(path for path in run_dir.iterdir() if path.suffix.lower() == ".xml")
