from __future__ import annotations

from rich.align import Align
from rich.panel import Panel
from rich.text import Text


def banner() -> Panel:
    title = Text()
    title.append("NMAP CONTROL CENTER\n", style="bold cyan")
    title.append("by lexiro", style="green")
    return Panel(
        Align.center(title),
        border_style="cyan",
        subtitle="[bright_black]professional Nmap front-end[/bright_black]",
        padding=(1, 2),
    )
