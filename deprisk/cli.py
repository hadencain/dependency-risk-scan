import argparse
import importlib.metadata
import sys

from deprisk.github import fetch_requirements
from deprisk.resolver import parse_requirements
from deprisk.pypi import fetch_pypi_data
from deprisk.osv import fetch_vulnerabilities
from deprisk.report import render

from deprisk.sbom.discover import discover_canonical
from deprisk.env.introspect import introspect_environment, env_descriptor
from deprisk.env.freeze import load_env_file, file_env_descriptor
from deprisk.drift.engine import compare
from deprisk.drift.report import (
    write_report, print_summary, max_severity_rank, SEVERITY_ORDER,
)

_SUBCOMMANDS = {"scan", "drift", "daemon"}


def _tool_version() -> str:
    try:
        return f"deprisk {importlib.metadata.version('deprisk')}"
    except importlib.metadata.PackageNotFoundError:
        return "deprisk"


def run_scan(source: str, path: str, graph: str | None) -> None:
    source_label = source
    if source.startswith("https://github.com/"):
        content = fetch_requirements(source, path=path)
        if content is None:
            print(f"Error: requirements.txt not found at {source}", file=sys.stderr)
            sys.exit(1)
            return
    elif source.startswith("https://"):
        print(f"Error: only GitHub URLs are supported (got {source})", file=sys.stderr)
        sys.exit(1)
        return
    else:
        try:
            raw = open(source, "rb").read()
            if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
                content = raw.decode("utf-16")
            else:
                content = raw.decode("utf-8-sig")
        except FileNotFoundError:
            print(f"Error: file not found: {source}", file=sys.stderr)
            sys.exit(1)
            return

    packages_raw = parse_requirements(content)
    packages = [fetch_pypi_data(name, version) for name, version in packages_raw]
    vulns = fetch_vulnerabilities(packages_raw)
    render(source_label, packages, vulns)

    if graph:
        from deprisk.graph import build
        from deprisk.html import export as export_html
        graph_data = build(packages_raw, packages, vulns)
        with open(graph, "w", encoding="utf-8") as f:
            f.write(export_html(graph_data, source_label))
        print(f"Dependency graph written to {graph}")


def run_drift(
    canonical: str,
    path: str | None,
    env_file: str | None,
    output: str | None,
    fail_on: str,
    tool: str,
) -> int:
    try:
        canon_doc = discover_canonical(canonical, path=path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if env_file:
        installed = load_env_file(env_file)
        env_source = file_env_descriptor(env_file)
    else:
        installed = introspect_environment()
        env_source = env_descriptor()

    report = compare(
        canon_doc, installed,
        canonical_source=canonical, env_source=env_source, tool=tool,
    )
    print_summary(report)
    if output:
        path_written = write_report(report, output)
        print(f"Drift report written to {path_written}")

    if fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["high"])
    return 1 if max_severity_rank(report) >= threshold else 0


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in _SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["scan"] + argv

    parser = argparse.ArgumentParser(
        prog="deprisk", description="Dependency risk + SBOM drift monitor.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Audit dependencies for risk signals")
    p_scan.add_argument("source")
    p_scan.add_argument("--path", default="requirements.txt")
    p_scan.add_argument("--graph", metavar="FILE", default=None)

    p_drift = sub.add_parser("drift", help="Compare canonical SBOM vs installed env")
    p_drift.add_argument("canonical", help="Repo URL, SBOM file, or directory")
    p_drift.add_argument("--path", default=None,
                         help="Path within repo/dir to SBOM or requirements file")
    p_drift.add_argument("--env-file", default=None,
                         help="Compare against a freeze/SBOM file instead of live env")
    p_drift.add_argument("--output", metavar="DIR", default=None,
                         help="Directory to write the timestamped JSON report")
    p_drift.add_argument("--fail-on", default="high",
                         choices=["none", "low", "medium", "high"],
                         help="Minimum severity that causes a non-zero exit")

    _add_daemon_parser(sub)  # defined in Task 11

    args = parser.parse_args(argv)
    tool = _tool_version()

    if args.command == "scan":
        run_scan(args.source, args.path, args.graph)
    elif args.command == "drift":
        code = run_drift(args.canonical, args.path, args.env_file,
                         args.output, args.fail_on, tool)
        sys.exit(code)
    elif args.command == "daemon":
        run_daemon_command(args, tool)  # defined in Task 11


# --- Task 11 stubs (replaced when daemon is implemented) ---

def _add_daemon_parser(sub):
    pass


def run_daemon_command(args, tool):
    raise NotImplementedError


if __name__ == "__main__":
    main()
