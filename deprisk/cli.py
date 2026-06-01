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
    source_label = args.source

    if args.source.startswith("https://github.com/"):
        content = fetch_requirements(args.source, path=args.path)
        if content is None:
            print(f"Error: requirements.txt not found at {args.source}", file=sys.stderr)
            sys.exit(1)
            return
    elif args.source.startswith("https://"):
        print(f"Error: only GitHub URLs are supported (got {args.source})", file=sys.stderr)
        sys.exit(1)
        return
    else:
        try:
            raw = open(args.source, "rb").read()
            if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
                content = raw.decode("utf-16")
            else:
                content = raw.decode("utf-8-sig")
        except FileNotFoundError:
            print(f"Error: file not found: {args.source}", file=sys.stderr)
            sys.exit(1)
            return

    packages_raw = parse_requirements(content)
    packages = [fetch_pypi_data(name, version) for name, version in packages_raw]
    vulns = fetch_vulnerabilities(packages_raw)
    render(source_label, packages, vulns)

if __name__ == "__main__":
    main()
