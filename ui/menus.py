from __future__ import annotations

from rich.table import Table

MAIN_MENU = [
    ("1", "Target Management"),
    ("2", "Host Discovery"),
    ("3", "Port Scanning"),
    ("4", "Service / Version Detection"),
    ("5", "OS Detection"),
    ("6", "NSE Scripts"),
    ("7", "Timing / Performance"),
    ("8", "Evasion / Packet Options"),
    ("9", "DNS / Resolution"),
    ("10", "Output / Logging"),
    ("11", "Profiles / Presets"),
    ("12", "Results Browser"),
    ("13", "Raw Command Mode"),
    ("14", "Scan Builder Summary"),
    ("15", "Run Scan"),
    ("16", "Help"),
    ("17", "Reset Configuration"),
    ("0", "Exit"),
]


def menu_table(title: str, items: list[tuple[str, str]]) -> Table:
    table = Table(title=title, show_header=False, border_style="bright_black")
    table.add_column("Key", style="green", width=5, no_wrap=True)
    table.add_column("Action", style="white")
    for key, action in items:
        table.add_row(key, action)
    return table
