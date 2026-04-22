from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def section(title: str, body: str) -> Panel:
    return Panel(body, title=f"[cyan]{title}[/cyan]", border_style="bright_black")


def key_value_table(title: str, values: dict[str, str]) -> Table:
    table = Table(title=title, show_header=False, box=None, pad_edge=False)
    table.add_column("Key", style="green", no_wrap=True)
    table.add_column("Value", style="white")
    for key, value in values.items():
        table.add_row(key, value)
    return table


def muted(text: str) -> Text:
    return Text(text, style="bright_black")
