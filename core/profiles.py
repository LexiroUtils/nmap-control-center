from __future__ import annotations

import json
from pathlib import Path

from core.models import ScanConfig
from core.validators import ValidationError, safe_profile_name


class ProfileStore:
    def __init__(self, root: Path | str = "data/profiles") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def list_profiles(self) -> list[str]:
        return sorted(path.stem for path in self.root.glob("*.json"))

    def path_for(self, name: str) -> Path:
        return self.root / f"{safe_profile_name(name)}.json"

    def save(self, name: str, config: ScanConfig) -> Path:
        path = self.path_for(name)
        data = config.to_dict()
        data["name"] = name
        path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def load(self, name: str) -> ScanConfig:
        path = self.path_for(name)
        if not path.exists():
            raise ValidationError(f"Profile not found: {name}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValidationError(f"Profile is corrupted: {path}") from exc
        return ScanConfig.from_dict(data)

    def delete(self, name: str) -> None:
        path = self.path_for(name)
        if not path.exists():
            raise ValidationError(f"Profile not found: {name}")
        path.unlink()
