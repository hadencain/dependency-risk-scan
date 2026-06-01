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
