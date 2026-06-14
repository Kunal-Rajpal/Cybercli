# cybercli/core/progress_utils.py
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.console import Console
import time

console = Console()

def show_progress_banner(stage: str, percent: int):
    """
    Show a hacking-style progress banner.
    stage: Current stage (Recon, Scan, Exploit, etc.)
    percent: Completion percentage (0-100)
    """
    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(f"[green]CyberCLI — {stage}", total=100)
        progress.update(task, completed=percent)
        time.sleep(1.5)  # keep visible shortly

