# dependencyRisk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `deprisk`, an installable CLI tool that audits Python dependencies for outdated packages, abandoned libraries, and known vulnerabilities, from a local `requirements.txt` or GitHub repo URL.

**Architecture:** Modular Python package with one file per concern — `resolver`, `github`, `pypi`, `osv`, `report` — wired together by `cli.py`. All HTTP calls are synchronous. Data flows one direction: parse input → fetch data → render report. Shared dataclasses live in `models.py`.

**Tech Stack:** Python 3.10+, requests, rich, packaging, pytest

---

## File Map

| File | Responsibility |
|------|----------------|
| `pyproject.toml` | Package config, `deprisk` CLI entry point |
| `deprisk/__init__.py` | Empty package marker |
| `deprisk/models.py` | `PackageInfo` and `Vulnerability` dataclasses |
| `deprisk/resolver.py` | Parse `requirements.txt` text → `list[tuple[str, str \| None]]` |
| `deprisk/github.py` | Normalize GitHub URL, fetch raw `requirements.txt` |
| `deprisk/pypi.py` | PyPI JSON API + PyPI Stats → `PackageInfo` |
| `deprisk/osv.py` | OSV.dev batch API → `list[Vulnerability]` |
| `deprisk/report.py` | Render terminal report using `rich` |
| `deprisk/cli.py` | argparse entry point, orchestrates pipeline |
| `tests/test_models.py` | Tests for dataclasses |
| `tests/test_resolver.py` | Tests for requirements parsing |
| `tests/test_github.py` | Tests for URL normalization and fetching |
| `tests/test_pypi.py` | Tests for PyPI data fetching |
| `tests/test_osv.py` | Tests for OSV vulnerability lookup |
| `tests/test_report.py` | Tests for terminal rendering |
| `tests/test_cli.py` | Tests for CLI orchestration |

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `deprisk/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "deprisk"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "requests",
    "rich",
    "packaging",
]

[project.scripts]
deprisk = "deprisk.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create empty package markers**

Create `deprisk/__init__.py` (empty file) and `tests/__init__.py` (empty file).

- [ ] **Step 3: Install and verify**

```bash
pip install -e .
pip install pytest
```

Expected: no errors. `deprisk` is now a registered command (will fail with module error until cli.py exists — that's fine).

- [ ] **Step 4: Commit**

```bash
git init
git add pyproject.toml deprisk/__init__.py tests/__init__.py
git commit -m "chore: scaffold deprisk package"
```

---

### Task 2: models.py — shared dataclasses

**Files:**
- Create: `deprisk/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from datetime import date
from deprisk.models import PackageInfo, Vulnerability

def test_package_info_defaults():
    pkg = PackageInfo(name="requests", pinned="2.28.0")
    assert pkg.latest is None
    assert pkg.last_release_date is None
    assert pkg.downloads_last_month is None
    assert pkg.unavailable is False

def test_vulnerability_fields():
    v = Vulnerability(package="flask", cve_id="CVE-2023-1234", summary="Open redirect")
    assert v.package == "flask"
    assert v.cve_id == "CVE-2023-1234"
    assert v.summary == "Open redirect"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_models.py -v
```

Expected: `ImportError: cannot import name 'PackageInfo'`

- [ ] **Step 3: Write `deprisk/models.py`**

```python
from dataclasses import dataclass
from datetime import date

@dataclass
class PackageInfo:
    name: str
    pinned: str | None
    latest: str | None = None
    last_release_date: date | None = None
    downloads_last_month: int | None = None
    unavailable: bool = False

@dataclass
class Vulnerability:
    package: str
    cve_id: str
    summary: str
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_models.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/models.py tests/test_models.py
git commit -m "feat: add PackageInfo and Vulnerability dataclasses"
```

---

### Task 3: resolver.py — parse requirements.txt

**Files:**
- Create: `deprisk/resolver.py`
- Create: `tests/test_resolver.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_resolver.py
from deprisk.resolver import parse_requirements

def test_pinned_package():
    assert parse_requirements("requests==2.28.0\n") == [("requests", "2.28.0")]

def test_unpinned_package():
    assert parse_requirements("flask>=2.0\n") == [("flask", None)]

def test_bare_package():
    assert parse_requirements("numpy\n") == [("numpy", None)]

def test_skips_comments_and_blanks():
    content = "# comment\n\nrequests==2.28.0\n"
    assert parse_requirements(content) == [("requests", "2.28.0")]

def test_package_with_extras():
    assert parse_requirements("requests[security]==2.28.0\n") == [("requests", "2.28.0")]

def test_skips_options_lines():
    content = "-r other.txt\nrequests==2.28.0\n"
    assert parse_requirements(content) == [("requests", "2.28.0")]

def test_multiple_packages():
    content = "requests==2.28.0\nflask\nnumpy>=1.24\n"
    assert parse_requirements(content) == [
        ("requests", "2.28.0"),
        ("flask", None),
        ("numpy", None),
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_resolver.py -v
```

Expected: `ImportError: cannot import name 'parse_requirements'`

- [ ] **Step 3: Write `deprisk/resolver.py`**

```python
from packaging.requirements import Requirement, InvalidRequirement

def parse_requirements(content: str) -> list[tuple[str, str | None]]:
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        pinned = None
        for spec in req.specifier:
            if spec.operator == "==":
                pinned = spec.version
                break
        results.append((req.name, pinned))
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_resolver.py -v
```

Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/resolver.py tests/test_resolver.py
git commit -m "feat: implement requirements.txt parser"
```

---

### Task 4: github.py — fetch requirements from GitHub URL

**Files:**
- Create: `deprisk/github.py`
- Create: `tests/test_github.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_github.py
from unittest.mock import patch, Mock
from deprisk.github import normalize_github_url, fetch_requirements

def test_normalize_default_path():
    url = normalize_github_url("https://github.com/owner/repo")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/requirements.txt"

def test_normalize_custom_path():
    url = normalize_github_url("https://github.com/owner/repo", path="subdir/reqs.txt")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/subdir/reqs.txt"

def test_normalize_strips_trailing_slash():
    url = normalize_github_url("https://github.com/owner/repo/")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/requirements.txt"

def test_fetch_requirements_success():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "requests==2.28.0\n"
    with patch("deprisk.github.requests.get", return_value=mock_response):
        result = fetch_requirements("https://github.com/owner/repo")
    assert result == "requests==2.28.0\n"

def test_fetch_requirements_not_found():
    mock_response = Mock()
    mock_response.status_code = 404
    with patch("deprisk.github.requests.get", return_value=mock_response):
        result = fetch_requirements("https://github.com/owner/repo")
    assert result is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_github.py -v
```

Expected: `ImportError: cannot import name 'normalize_github_url'`

- [ ] **Step 3: Write `deprisk/github.py`**

```python
import requests

def normalize_github_url(url: str, path: str = "requirements.txt") -> str:
    url = url.rstrip("/")
    parts = url.replace("https://github.com/", "")
    return f"https://raw.githubusercontent.com/{parts}/HEAD/{path}"

def fetch_requirements(url: str, path: str = "requirements.txt") -> str | None:
    raw_url = normalize_github_url(url, path)
    response = requests.get(raw_url, timeout=10)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.text
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_github.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/github.py tests/test_github.py
git commit -m "feat: implement GitHub URL fetcher"
```

---

### Task 5: pypi.py — version and download data

**Files:**
- Create: `deprisk/pypi.py`
- Create: `tests/test_pypi.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pypi.py
from datetime import date
from unittest.mock import patch, Mock
from deprisk.pypi import fetch_pypi_data
from deprisk.models import PackageInfo

PYPI_RESPONSE = {
    "info": {"version": "2.32.3"},
    "releases": {
        "2.32.3": [{"upload_time": "2024-05-20T10:00:00"}],
        "2.28.0": [{"upload_time": "2022-01-15T10:00:00"}],
    },
}

STATS_RESPONSE = {
    "data": {"last_month": 5000000}
}

def _mock_get(url, **kwargs):
    mock = Mock()
    if "pypi.org" in url:
        mock.status_code = 200
        mock.json.return_value = PYPI_RESPONSE
    elif "pypistats.org" in url:
        mock.status_code = 200
        mock.json.return_value = STATS_RESPONSE
    return mock

def test_returns_latest_version():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.latest == "2.32.3"

def test_returns_download_count():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.downloads_last_month == 5000000

def test_returns_last_release_date():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.last_release_date == date(2024, 5, 20)

def test_unpinned_package():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", None)
    assert result.pinned is None
    assert result.latest == "2.32.3"

def test_unavailable_package():
    mock = Mock()
    mock.status_code = 404
    with patch("deprisk.pypi.requests.get", return_value=mock):
        result = fetch_pypi_data("private-lib", "1.0.0")
    assert result.unavailable is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_pypi.py -v
```

Expected: `ImportError: cannot import name 'fetch_pypi_data'`

- [ ] **Step 3: Write `deprisk/pypi.py`**

```python
from datetime import datetime
import requests
from deprisk.models import PackageInfo

def fetch_pypi_data(name: str, pinned: str | None) -> PackageInfo:
    try:
        pypi_resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        if pypi_resp.status_code == 404:
            return PackageInfo(name=name, pinned=pinned, unavailable=True)
        pypi_resp.raise_for_status()
        data = pypi_resp.json()
    except Exception:
        return PackageInfo(name=name, pinned=pinned, unavailable=True)

    latest = data["info"]["version"]

    latest_date = None
    for release_files in data["releases"].values():
        for f in release_files:
            dt = datetime.fromisoformat(f["upload_time"]).date()
            if latest_date is None or dt > latest_date:
                latest_date = dt

    downloads = None
    try:
        stats_resp = requests.get(
            f"https://pypistats.org/api/packages/{name}/recent", timeout=10
        )
        if stats_resp.status_code == 200:
            downloads = stats_resp.json()["data"]["last_month"]
    except Exception:
        pass

    return PackageInfo(
        name=name,
        pinned=pinned,
        latest=latest,
        last_release_date=latest_date,
        downloads_last_month=downloads,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_pypi.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/pypi.py tests/test_pypi.py
git commit -m "feat: implement PyPI version and download fetcher"
```

---

### Task 6: osv.py — vulnerability lookup

**Files:**
- Create: `deprisk/osv.py`
- Create: `tests/test_osv.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_osv.py
from unittest.mock import patch, Mock
from deprisk.osv import fetch_vulnerabilities
from deprisk.models import Vulnerability

OSV_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2023-001",
                    "aliases": ["CVE-2023-1234"],
                    "summary": "Open redirect vulnerability",
                }
            ]
        },
        {"vulns": []},
    ]
}

def test_returns_cve_from_aliases():
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = OSV_RESPONSE
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("flask", "2.2.0"), ("requests", "2.28.0")])
    assert len(result) == 1
    assert result[0].package == "flask"
    assert result[0].cve_id == "CVE-2023-1234"
    assert result[0].summary == "Open redirect vulnerability"

def test_falls_back_to_osv_id_when_no_cve():
    response = {
        "results": [
            {
                "vulns": [
                    {"id": "PYSEC-2023-999", "aliases": [], "summary": "Some vuln"}
                ]
            }
        ]
    }
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = response
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("flask", "2.2.0")])
    assert result[0].cve_id == "PYSEC-2023-999"

def test_returns_empty_list_when_no_vulns():
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {"results": [{"vulns": []}]}
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("requests", "2.32.3")])
    assert result == []

def test_returns_empty_list_on_network_error():
    with patch("deprisk.osv.requests.post", side_effect=Exception("network error")):
        result = fetch_vulnerabilities([("flask", "2.2.0")])
    assert result == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_osv.py -v
```

Expected: `ImportError: cannot import name 'fetch_vulnerabilities'`

- [ ] **Step 3: Write `deprisk/osv.py`**

```python
import requests
from deprisk.models import Vulnerability

def fetch_vulnerabilities(packages: list[tuple[str, str | None]]) -> list[Vulnerability]:
    queries = []
    for name, version in packages:
        query: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
        if version:
            query["version"] = version
        queries.append(query)

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=15,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except Exception:
        return []

    vulns = []
    for i, result in enumerate(results):
        pkg_name = packages[i][0]
        for v in result.get("vulns", []):
            cve_id = next(
                (a for a in v.get("aliases", []) if a.startswith("CVE-")),
                v["id"],
            )
            vulns.append(Vulnerability(
                package=pkg_name,
                cve_id=cve_id,
                summary=v.get("summary", ""),
            ))
    return vulns
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_osv.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/osv.py tests/test_osv.py
git commit -m "feat: implement OSV.dev vulnerability batch lookup"
```

---

### Task 7: report.py — terminal rendering

**Files:**
- Create: `deprisk/report.py`
- Create: `tests/test_report.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_report.py
from datetime import date
from io import StringIO
from rich.console import Console
from deprisk.report import render
from deprisk.models import PackageInfo, Vulnerability

def _render_to_string(packages, vulns, source="requirements.txt"):
    console = Console(file=StringIO(), highlight=False, no_color=True)
    render(source, packages, vulns, console=console)
    return console.file.getvalue()

def test_outdated_section_appears():
    packages = [PackageInfo(name="requests", pinned="2.28.0", latest="2.32.3")]
    output = _render_to_string(packages, [])
    assert "OUTDATED" in output
    assert "requests" in output
    assert "2.28.0" in output
    assert "2.32.3" in output

def test_abandoned_section_appears():
    packages = [PackageInfo(
        name="old-lib",
        pinned="1.0.0",
        latest="1.0.0",
        last_release_date=date(2020, 1, 1),
        downloads_last_month=200,
    )]
    output = _render_to_string(packages, [])
    assert "ABANDONED" in output
    assert "old-lib" in output

def test_not_abandoned_when_downloads_high():
    packages = [PackageInfo(
        name="popular-lib",
        pinned="1.0.0",
        latest="1.0.0",
        last_release_date=date(2020, 1, 1),
        downloads_last_month=50000,
    )]
    output = _render_to_string(packages, [])
    assert "ABANDONED" not in output

def test_vulnerabilities_section_appears():
    packages = [PackageInfo(name="flask", pinned="2.2.0", latest="3.1.0")]
    vulns = [Vulnerability(package="flask", cve_id="CVE-2023-1234", summary="Open redirect")]
    output = _render_to_string(packages, vulns)
    assert "VULNERABILITIES" in output
    assert "CVE-2023-1234" in output

def test_ok_shown_when_no_issues():
    packages = [PackageInfo(name="requests", pinned="2.32.3", latest="2.32.3")]
    output = _render_to_string(packages, [])
    assert "OK" in output

def test_header_shows_package_count():
    packages = [PackageInfo(name="requests", pinned="2.32.3", latest="2.32.3")]
    output = _render_to_string(packages, [])
    assert "1 package" in output
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_report.py -v
```

Expected: `ImportError: cannot import name 'render'`

- [ ] **Step 3: Write `deprisk/report.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_report.py -v
```

Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add deprisk/report.py tests/test_report.py
git commit -m "feat: implement terminal report renderer"
```

---

### Task 8: cli.py — entry point and orchestration

**Files:**
- Create: `deprisk/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli.py
from unittest.mock import patch, Mock
from deprisk.cli import main
from deprisk.models import PackageInfo, Vulnerability

REQUIREMENTS_CONTENT = "requests==2.28.0\n"
PACKAGE = PackageInfo(name="requests", pinned="2.28.0", latest="2.32.3")
VULNS: list[Vulnerability] = []

def test_cli_local_file(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(REQUIREMENTS_CONTENT)

    with patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render") as mock_render:
        main([str(req_file)])

    mock_render.assert_called_once()
    _, packages, vulns = mock_render.call_args[0]
    assert packages == [PACKAGE]
    assert vulns == VULNS

def test_cli_github_url():
    with patch("deprisk.cli.fetch_requirements", return_value=REQUIREMENTS_CONTENT), \
         patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render") as mock_render:
        main(["https://github.com/owner/repo"])

    mock_render.assert_called_once()

def test_cli_github_url_not_found():
    with patch("deprisk.cli.fetch_requirements", return_value=None), \
         patch("sys.exit") as mock_exit:
        main(["https://github.com/owner/repo"])
    mock_exit.assert_called_with(1)

def test_cli_github_custom_path():
    with patch("deprisk.cli.fetch_requirements", return_value=REQUIREMENTS_CONTENT) as mock_fetch, \
         patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render"):
        main(["https://github.com/owner/repo", "--path", "subdir/reqs.txt"])

    mock_fetch.assert_called_with("https://github.com/owner/repo", path="subdir/reqs.txt")

def test_cli_missing_local_file():
    with patch("sys.exit") as mock_exit:
        main(["/nonexistent/requirements.txt"])
    mock_exit.assert_called_with(1)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cli.py -v
```

Expected: `ImportError: cannot import name 'main'`

- [ ] **Step 3: Write `deprisk/cli.py`**

```python
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
        source_label = args.source
    else:
        try:
            with open(args.source) as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.source}")
            sys.exit(1)
        source_label = args.source

    packages_raw = parse_requirements(content)
    packages = [fetch_pypi_data(name, version) for name, version in packages_raw]
    vulns = fetch_vulnerabilities(packages_raw)
    render(source_label, packages, vulns)

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all tests**

```bash
pytest tests/ -v
```

Expected: all tests pass

- [ ] **Step 5: Smoke test against a real requirements.txt**

```bash
python -c "print('requests==2.28.0\nflask\nnumpy>=1.24')" > /tmp/test_reqs.txt
deprisk /tmp/test_reqs.txt
```

Expected: terminal report showing OUTDATED section for `requests` (2.28.0 < current), unpinned note for `flask` and `numpy`.

- [ ] **Step 6: Commit**

```bash
git add deprisk/cli.py tests/test_cli.py
git commit -m "feat: implement CLI entry point and pipeline orchestration"
```
