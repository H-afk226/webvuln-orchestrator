"""Command line interface for the orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from src.auth import AuthenticationError, authenticate
from src.config import ScopeViolation, load_config

app = typer.Typer(add_completion=False, help="Web vulnerability scan orchestrator")
console = Console()

RESULTS_DIR = Path("/app/results")


@app.command("targets")
def list_targets() -> None:
    """List configured, in-scope targets."""
    cfg = load_config()
    table = Table(title="Configured targets")
    table.add_column("Name", style="cyan")
    table.add_column("Base URL")
    table.add_column("Stack", style="dim")
    table.add_column("In scope", justify="center")

    for name, t in cfg.targets.items():
        allowed = "yes" if name in cfg.allowlist else "NO"
        table.add_row(name, t.base_url, t.tech, allowed)

    console.print(table)


@app.command("check")
def check_scope(target: str) -> None:
    """Verify a target is in scope without scanning it."""
    cfg = load_config()
    try:
        t = cfg.get(target)
    except ScopeViolation as exc:
        console.print(f"[bold red]REFUSED[/] {exc}")
        raise typer.Exit(code=2)
    console.print(f"[bold green]IN SCOPE[/] {t.name} -> {t.base_url}")


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Target name from config/targets.yml"),
    tools: str = typer.Option("", help="Comma-separated tool names (default: all)"),
    auth: bool = typer.Option(True, help="Authenticate before scanning, if configured"),
) -> None:
    """Run scanners against a target. Scanners are registered in Step 4."""
    cfg = load_config()
    try:
        t = cfg.get(target)
    except ScopeViolation as exc:
        console.print(f"[bold red]REFUSED[/] {exc}")
        raise typer.Exit(code=2)

    from src.scanners import REGISTRY

    selected = [s.strip() for s in tools.split(",") if s.strip()] or list(REGISTRY)
    unknown = [s for s in selected if s not in REGISTRY]
    if unknown:
        console.print(f"[bold red]Unknown tools:[/] {', '.join(unknown)}")
        console.print(f"Available: {', '.join(REGISTRY) or '(none registered yet)'}")
        raise typer.Exit(code=2)

    if not selected:
        console.print("[yellow]No scanners registered yet.[/] Complete Step 4.")
        raise typer.Exit(code=0)

    session = None
    if auth and t.auth:
        try:
            session = authenticate(t)
            console.print(f"[green]authenticated[/] {session.describe()}")
        except AuthenticationError as exc:
            console.print(f"[bold red]auth failed[/] {exc}")
            raise typer.Exit(code=3)
    elif t.auth:
        console.print("[yellow]running unauthenticated[/] (--no-auth)")

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = "auth" if session else "noauth"
    run_dir = RESULTS_DIR / f"{target}-{suffix}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold]Target:[/] {t.name} ({t.base_url})")
    console.print(f"[bold]Output:[/] {run_dir}\n")

    all_results = []
    for tool_name in selected:
        console.print(f"[cyan]running[/] {tool_name} ...")
        scanner = REGISTRY[tool_name](run_dir=run_dir, session=session)
        result = scanner.scan(t)
        all_results.append(result)

        if result.succeeded:
            console.print(
                f"  [green]done[/] {len(result.findings)} findings "
                f"in {result.duration_seconds:.1f}s"
            )
        else:
            console.print(f"  [red]failed[/] {result.error}")

    out = run_dir / "results.json"
    out.write_text(
        json.dumps([json.loads(r.model_dump_json()) for r in all_results], indent=2)
    )
    console.print(f"\n[bold green]Written[/] {out}")


if __name__ == "__main__":
    app()
