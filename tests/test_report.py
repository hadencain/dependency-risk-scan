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
