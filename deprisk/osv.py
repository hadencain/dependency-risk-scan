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
    for (pkg_name, _), result in zip(packages, results):
        for v in result.get("vulns", []):
            cve_id = next(
                (a for a in v.get("aliases", []) if a.startswith("CVE-")),
                v.get("id", "UNKNOWN"),
            )
            vulns.append(Vulnerability(
                package=pkg_name,
                cve_id=cve_id,
                summary=v.get("summary", ""),
            ))
    return vulns
