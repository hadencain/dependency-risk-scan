from dataclasses import dataclass, field
from datetime import date, timedelta

from packaging.requirements import Requirement, InvalidRequirement
from packaging.version import Version, InvalidVersion

from deprisk.models import PackageInfo, Vulnerability
from deprisk.pypi import fetch_pypi_data
from deprisk.osv import fetch_vulnerabilities

_MAX_NODES = 80
_ABANDONED_DAYS = 730
_ABANDONED_DOWNLOADS = 1000


@dataclass
class _Node:
    id: str
    label: str
    pinned: str | None
    latest: str | None
    risk: str  # vuln | outdated | abandoned | ok | unknown
    is_direct: bool
    cves: list[str] = field(default_factory=list)


def _classify(pkg: PackageInfo, vuln_set: set[str]) -> str:
    if pkg.unavailable:
        return "unknown"
    if pkg.name.lower() in vuln_set:
        return "vuln"
    if pkg.pinned and pkg.latest:
        try:
            if Version(pkg.pinned) < Version(pkg.latest):
                return "outdated"
        except InvalidVersion:
            pass
    if pkg.last_release_date and pkg.downloads_last_month is not None:
        cutoff = date.today() - timedelta(days=_ABANDONED_DAYS)
        if pkg.last_release_date < cutoff and pkg.downloads_last_month < _ABANDONED_DOWNLOADS:
            return "abandoned"
    return "ok"


def _parse_deps(requires_dist: list[str]) -> list[str]:
    names = []
    for raw in requires_dist:
        if "extra ==" in raw or "extra==" in raw:
            continue
        try:
            req = Requirement(raw)
            if req.marker and "extra" in str(req.marker):
                continue
            names.append(req.name.lower())
        except (InvalidRequirement, Exception):
            continue
    return names


def build(
    packages_raw: list[tuple[str, str | None]],
    packages: list[PackageInfo],
    vulns: list[Vulnerability],
) -> dict:
    vuln_set = {v.package.lower() for v in vulns}
    vuln_cves: dict[str, list[str]] = {}
    for v in vulns:
        vuln_cves.setdefault(v.package.lower(), []).append(v.cve_id)

    pkg_map: dict[str, PackageInfo] = {p.name.lower(): p for p in packages}
    nodes: dict[str, _Node] = {}
    edges: list[dict] = []
    direct_names: set[str] = {name.lower() for name, _ in packages_raw}

    nodes["__root__"] = _Node(
        id="__root__", label="requirements.txt",
        pinned=None, latest=None, risk="root", is_direct=False,
    )

    for pkg in packages:
        k = pkg.name.lower()
        nodes[k] = _Node(
            id=k, label=pkg.name, pinned=pkg.pinned, latest=pkg.latest,
            risk=_classify(pkg, vuln_set), is_direct=True,
            cves=vuln_cves.get(k, []),
        )
        edges.append({"from": "__root__", "to": k})

    # BFS into transitive deps
    queue = [k for k in direct_names if k in pkg_map]
    seen: set[str] = set(direct_names) | {"__root__"}
    trans_names: list[str] = []

    while queue and len(nodes) < _MAX_NODES:
        current = queue.pop(0)
        pkg = pkg_map.get(current)
        if not pkg or pkg.unavailable:
            continue
        for dep in _parse_deps(pkg.requires_dist):
            if dep in seen or len(nodes) >= _MAX_NODES:
                continue
            seen.add(dep)
            trans_names.append(dep)
            nodes[dep] = _Node(
                id=dep, label=dep, pinned=None, latest=None,
                risk="unknown", is_direct=False,
            )
            edges.append({"from": current, "to": dep})
            queue.append(dep)

    if trans_names:
        for name in trans_names:
            trans_pkg = fetch_pypi_data(name, None)
            pkg_map[name] = trans_pkg
            nodes[name].label = trans_pkg.name or name
            nodes[name].latest = trans_pkg.latest

        checkable = [
            (pkg_map[n].name, None)
            for n in trans_names
            if n in pkg_map and not pkg_map[n].unavailable
        ]
        if checkable:
            trans_vulns = fetch_vulnerabilities(checkable)
            trans_vuln_set = {v.package.lower() for v in trans_vulns}
            trans_vuln_cves: dict[str, list[str]] = {}
            for v in trans_vulns:
                trans_vuln_cves.setdefault(v.package.lower(), []).append(v.cve_id)
            for name in trans_names:
                pkg = pkg_map.get(name)
                if pkg:
                    nodes[name].risk = _classify(pkg, trans_vuln_set)
                    nodes[name].cves = trans_vuln_cves.get(name, [])

    return {
        "nodes": [
            {
                "id": n.id,
                "label": n.label,
                "risk": n.risk,
                "pinned": n.pinned,
                "latest": n.latest,
                "is_direct": n.is_direct,
                "cves": n.cves,
            }
            for n in nodes.values()
        ],
        "edges": edges,
        "truncated": len(nodes) >= _MAX_NODES,
    }
