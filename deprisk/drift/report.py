import json
import os

from rich.console import Console

from deprisk.models import DriftReport

SEVERITY_ORDER: dict[str, int] = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _component_to_dict(c) -> dict:
    return {
        "ecosystem": c.ecosystem,
        "name": c.name,
        "version": c.version,
        "purl": c.purl,
        "source": c.source,
    }


def report_to_dict(report: DriftReport) -> dict:
    return {
        "generated_at": report.generated_at.isoformat(),
        "tool": report.tool,
        "canonical_source": report.canonical_source,
        "canonical_format": report.canonical_format,
        "env_source": report.env_source,
        "subject_commit": report.subject_commit,
        "summary": dict(report.summary),
        "records": [
            {
                "drift_type": r.drift_type.value,
                "severity": r.severity,
                "detail": r.detail,
                "canonical_version": r.canonical_version,
                "installed_version": r.installed_version,
                "component": _component_to_dict(r.component),
            }
            for r in report.records
        ],
    }


def report_to_json(report: DriftReport) -> str:
    return json.dumps(report_to_dict(report), indent=2)


def write_report(report: DriftReport, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(output_dir, f"drift-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_to_json(report))
    return path


def max_severity_rank(report: DriftReport) -> int:
    if not report.records:
        return 0
    return max(SEVERITY_ORDER.get(r.severity, 0) for r in report.records)


def print_summary(report: DriftReport, console: Console | None = None) -> None:
    console = console or Console()
    s = report.summary
    console.print(
        f"\n[bold]drift[/bold] · {report.canonical_source} · "
        f"{report.env_source}"
    )
    undeclared = s.get("UNDECLARED", 0)
    mism = s.get("VERSION_MISMATCH", 0)
    missing = s.get("MISSING", 0)
    if undeclared:
        console.print(f"  [red]UNDECLARED (shadow) {undeclared}[/red]")
    if mism:
        console.print(f"  [yellow]VERSION_MISMATCH {mism}[/yellow]")
    if missing:
        console.print(f"  [yellow]MISSING {missing}[/yellow]")
    if not (undeclared or mism or missing):
        console.print("  [green]OK[/green]  no drift detected")
    console.print()
