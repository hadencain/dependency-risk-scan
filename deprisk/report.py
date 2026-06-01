from datetime import date, timedelta
from rich.console import Console
from rich.table import Table
from rich import box
from packaging.version import Version, InvalidVersion
from deprisk.models import PackageInfo, Vulnerability

_ABANDONED_DAYS = 730
_ABANDONED_DOWNLOADS = 1000

def _is_outdated(pkg: PackageInfo) -> bool:
    if pkg.unavailable or pkg.pinned is None or pkg.latest is None:
        return False
    try:
        return Version(pkg.pinned) < Version(pkg.latest)
    except InvalidVersion:
        return False

def _is_abandoned(pkg: PackageInfo) -> bool:
    if pkg.unavailable or pkg.last_release_date is None or pkg.downloads_last_month is None:
        return False
    cutoff = date.today() - timedelta(days=_ABANDONED_DAYS)
    return pkg.last_release_date < cutoff and pkg.downloads_last_month < _ABANDONED_DOWNLOADS

def render(
    source: str,
    packages: list[PackageInfo],
    vulns: list[Vulnerability],
    console: Console | None = None,
) -> None:
    if console is None:
        console = Console()

    count = len(packages)
    noun = "package" if count == 1 else "packages"
    console.print(f"\n[bold]deprisk[/bold] · {source} · {count} {noun}\n")

    outdated = [p for p in packages if _is_outdated(p)]
    if outdated:
        console.print(f"  [yellow]OUTDATED ({len(outdated)})[/yellow]")
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=True)
        t.add_column("Package")
        t.add_column("Pinned")
        t.add_column("Latest")
        for p in outdated:
            t.add_row(p.name, p.pinned or "", p.latest or "")
        console.print(t)

    abandoned = [p for p in packages if _is_abandoned(p)]
    if abandoned:
        console.print(f"  [yellow]ABANDONED ({len(abandoned)})[/yellow]")
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=True)
        t.add_column("Package")
        t.add_column("Last Release")
        t.add_column("Downloads/mo")
        for p in abandoned:
            t.add_row(p.name, str(p.last_release_date), str(p.downloads_last_month))
        console.print(t)

    if vulns:
        console.print(f"  [red]VULNERABILITIES ({len(vulns)})[/red]")
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=True)
        t.add_column("Package")
        t.add_column("CVE")
        t.add_column("Summary")
        for v in vulns:
            t.add_row(v.package, v.cve_id, v.summary)
        console.print(t)

    if not outdated and not abandoned and not vulns:
        console.print(f"  [green]OK[/green]  {count} {noun} up to date, no known issues\n")

    unavailable = [p for p in packages if p.unavailable]
    if unavailable:
        names = ", ".join(p.name for p in unavailable)
        console.print(f"  [dim]Skipped (not on PyPI): {names}[/dim]\n")

    unpinned = [p for p in packages if not p.unavailable and p.pinned is None]
    if unpinned:
        names = ", ".join(p.name for p in unpinned)
        console.print(f"  [dim]Unpinned (version check skipped): {names}[/dim]\n")
