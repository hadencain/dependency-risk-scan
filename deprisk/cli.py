import argparse
import sys
from deprisk.github import fetch_requirements
from deprisk.resolver import parse_requirements
from deprisk.pypi import fetch_pypi_data
from deprisk.osv import fetch_vulnerabilities
from deprisk.report import render

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="deprisk",
        description="Audit Python dependencies for risk signals.",
    )
    parser.add_argument("source", help="Path to requirements.txt or GitHub repo URL")
    parser.add_argument(
        "--path",
        default="requirements.txt",
        help="Path within the repo to requirements.txt (GitHub URLs only)",
    )
    args = parser.parse_args(argv)

    if args.source.startswith("https://"):
        content = fetch_requirements(args.source, path=args.path)
        if content is None:
            print(f"Error: requirements.txt not found at {args.source}")
            sys.exit(1)
            return
        source_label = args.source
    else:
        try:
            with open(args.source) as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.source}")
            sys.exit(1)
            return
        source_label = args.source

    packages_raw = parse_requirements(content)
    packages = [fetch_pypi_data(name, version) for name, version in packages_raw]
    vulns = fetch_vulnerabilities(packages_raw)
    render(source_label, packages, vulns)

if __name__ == "__main__":
    main()
