"""Terminal UI (TUI) for computer-audit security & bloat audit.

Keyboard-driven, full-screen interface built on Rich. Runs in the venv on any
non-mobile OS. Every action is shown before it runs — dry-run by default.

Keys:
  1  Bloat audit        2  Threat scan
  3  Full audit         4  Removal plan (dry-run)
  a  Apply removal       q  Quit
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.bloat_auditor import BloatAuditor  # noqa: E402
from core.threat_scanner import ThreatScanner  # noqa: E402
from core.removal_engine import RemovalEngine  # noqa: E402
from core.audit_cmd import _asdict  # noqa: E402

console = Console()


def _banner() -> str:
    return (
        "computer-audit  ·  Security & Bloat Audit TUI\n"
        "Non-mobile OS only  ·  Dry-run by default  ·  Confirmation gate before any change\n"
    )


def _print_report(title: str, report: dict) -> None:
    console.print(Panel.fit(f"[bold]{title}[/bold]", border_style="cyan"))
    console.print(f"[dim]{report.get('summary','')}[/dim]\n")
    items = report.get("items", [])
    if items:
        tbl = Table(show_header=True, header_style="bold magenta")
        tbl.add_column("ID", style="dim")
        tbl.add_column("Category")
        tbl.add_column("Name")
        tbl.add_column("Risk")
        tbl.add_column("Detail")
        for it in items[:50]:
            tbl.add_row(
                str(it.get("id", "")),
                str(it.get("category", "")),
                str(it.get("name", "")),
                str(it.get("risk", "")),
                str(it.get("detail", ""))[:80],
            )
        console.print(tbl)
        if len(items) > 50:
            console.print(f"[dim]... and {len(items) - 50} more items[/dim]")


def main() -> int:
    while True:
        console.clear()
        console.print(_banner())
        console.print("1. Bloat / AI-bloat audit")
        console.print("2. Threat / trojan triage scan")
        console.print("3. Full audit (bloat + threat)")
        console.print("4. Removal plan (dry-run)")
        console.print("a. Apply removal (requires confirmation)")
        console.print("q. Quit")
        choice = console.input("\nSelect: ").strip().lower()

        if choice == "1":
            report = _asdict(BloatAuditor().audit())
            _print_report("Bloat / AI-Bloat Audit", report)
            Path("reports").mkdir(exist_ok=True)
            Path("reports/bloat-tui.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            console.print("\n[dim]Saved to reports/bloat-tui.json[/dim]")
            console.input("\nPress Enter to continue...")
        elif choice == "2":
            report = _asdict(ThreatScanner().scan())
            _print_report("Threat / Trojan Triage", report)
            Path("reports").mkdir(exist_ok=True)
            Path("reports/threat-tui.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            console.print("\n[dim]Saved to reports/threat-tui.json[/dim]")
            console.input("\nPress Enter to continue...")
        elif choice == "3":
            b = _asdict(BloatAuditor().audit())
            t = _asdict(ThreatScanner().scan())
            _print_report("Bloat Audit", b)
            console.print()
            _print_report("Threat Scan", t)
            Path("reports").mkdir(exist_ok=True)
            Path("reports/full-tui.json").write_text(
                json.dumps({"bloat": b, "threat": t}, indent=2), encoding="utf-8"
            )
            console.print("\n[dim]Saved to reports/full-tui.json[/dim]")
            console.input("\nPress Enter to continue...")
        elif choice == "4":
            bloat_report = _asdict(BloatAuditor().audit())
            engine = RemovalEngine(dry_run=True)
            planned = engine.plan_from_bloat(bloat_report)
            console.print(Panel.fit("Removal Plan — DRY RUN (nothing will change)", border_style="yellow"))
            console.print(engine.preview(planned))
            console.input("\nPress Enter to continue...")
        elif choice == "a":
            if not Confirm.ask("This will disable/remove bloat items. Continue?"):
                continue
            bloat_report = _asdict(BloatAuditor().audit())
            engine = RemovalEngine(dry_run=False)
            planned = engine.plan_from_bloat(bloat_report)
            console.print(engine.preview(planned))
            if Confirm.ask("Confirm execution of all listed actions?"):
                result = engine.apply(planned, confirm=True)
                console.print(f"[green]Applied: {result.applied}, Skipped: {result.skipped}, Failed: {result.failed}[/green]")
                console.print(f"[dim]Log: {result.log_path}[/dim]")
                console.print(f"[dim]SHA256: {engine.hash_log(result.log_path)}[/dim]")
            else:
                console.print("[yellow]Cancelled.[/yellow]")
            console.input("\nPress Enter to continue...")
        elif choice == "q":
            return 0
        else:
            console.print("[red]Invalid choice.[/red]")
            console.input("\nPress Enter to continue...")


if __name__ == "__main__":
    raise SystemExit(main())
