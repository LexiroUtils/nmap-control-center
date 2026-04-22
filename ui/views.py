from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from core.models import CommandPlan
from ui.formatting import console, key_value_table


def show_plan(summary: dict[str, str], plan: CommandPlan) -> None:
    console.print(key_value_table("Scan Builder Summary", summary))
    console.print(Panel(plan.preview(), title="[cyan]Generated Command[/cyan]", border_style="green"))
    if plan.warnings:
        console.print(Panel("\n".join(plan.warnings), title="[yellow]Warnings[/yellow]", border_style="yellow"))


def show_runs(runs: list[Path]) -> None:
    table = Table(title="Saved Scan Runs")
    table.add_column("#", style="green", width=4)
    table.add_column("Run")
    for idx, path in enumerate(runs, start=1):
        table.add_row(str(idx), path.name)
    console.print(table)


def show_file(path: Path, max_chars: int = 20000) -> None:
    if not path.exists():
        console.print(f"[red]Missing file:[/red] {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[truncated]"
    console.print(Panel(text or "(empty)", title=str(path), border_style="bright_black"))
