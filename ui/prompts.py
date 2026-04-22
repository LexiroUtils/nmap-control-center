from __future__ import annotations

import shlex
from typing import Iterable

from rich.prompt import Confirm, IntPrompt, Prompt

from core.validators import ValidationError


def ask_text(label: str, default: str | None = None, allow_blank: bool = False) -> str | None:
    while True:
        value = Prompt.ask(label, default=default or "")
        value = value.strip()
        if value or allow_blank:
            return value or None
        print("Value required.")


def ask_int(label: str, low: int | None = None, high: int | None = None, default: int | None = None) -> int | None:
    while True:
        raw_default = str(default) if default is not None else ""
        raw = Prompt.ask(label, default=raw_default).strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            print("Enter a number.")
            continue
        if low is not None and value < low:
            print(f"Minimum is {low}.")
            continue
        if high is not None and value > high:
            print(f"Maximum is {high}.")
            continue
        return value


def ask_yes(label: str, default: bool = False) -> bool:
    return Confirm.ask(label, default=default)


def choose(label: str, options: list[tuple[str, str]], allow_back: bool = True) -> str:
    for key, desc in options:
        print(f"{key}) {desc}")
    if allow_back:
        print("b) Back")
    valid = {key for key, _ in options}
    if allow_back:
        valid.add("b")
    while True:
        value = Prompt.ask(label).strip()
        if value in valid:
            return value
        print("Choose one of: " + ", ".join(sorted(valid)))


def csv_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def raw_args(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def pick_many(label: str, valid_values: Iterable[str]) -> list[str]:
    valid = set(valid_values)
    text = Prompt.ask(label + " (comma separated)", default="")
    items = csv_values(text)
    bad = [item for item in items if item not in valid]
    if bad:
        raise ValidationError("Unknown values: " + ", ".join(bad))
    return items
