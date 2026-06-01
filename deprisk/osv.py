import requests
from deprisk.models import Vulnerability


def fetch_vulnerabilities(packages: list[tuple[str, str | None]]) -> list[Vulnerability]:
    vulns = []
    for name, version in packages:
        try:
            query: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
            if version:
                query["version"] = version
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json=query,
                timeout=10,
            )
            resp.raise_for_status()
            for v in resp.json().get("vulns", []):
                cve_id = next(
                    (a for a in v.get("aliases", []) if a.startswith("CVE-")),
                    v.get("id", "UNKNOWN"),
                )
                vulns.append(Vulnerability(
                    package=name,
                    cve_id=cve_id,
                    summary=v.get("summary") or v.get("details", "")[:120],
                ))
        except Exception:
            continue
    return vulns
