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
