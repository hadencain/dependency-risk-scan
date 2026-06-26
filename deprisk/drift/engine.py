from datetime import datetime, timezone

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from deprisk.models import (
    Component, DriftRecord, DriftReport, DriftType, SBOMDocument,
)

SEVERITY: dict[DriftType, str] = {
    DriftType.UNDECLARED: "high",
    DriftType.MISSING: "medium",
    DriftType.VERSION_MISMATCH: "medium",
}


def _key(c: Component) -> tuple[str, str]:
    return (c.ecosystem.lower(), canonicalize_name(c.name))


def _versions_equal(a: str | None, b: str | None) -> bool:
    if a == b:
        return True
    if a is None or b is None:
        return False
    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return a == b


def compare(
    canonical: SBOMDocument,
    installed: list[Component],
    canonical_source: str,
    env_source: str,
    tool: str,
    now: datetime | None = None,
) -> DriftReport:
    """Diff a canonical SBOM against installed components into a DriftReport."""
    now = now or datetime.now(timezone.utc)
    canon_map = {_key(c): c for c in canonical.components}
    inst_map = {_key(c): c for c in installed}
    records: list[DriftRecord] = []
    summary = {t.value: 0 for t in DriftType}

    for key, inst in inst_map.items():
        canon = canon_map.get(key)
        if canon is None:
            records.append(DriftRecord(
                component=inst,
                drift_type=DriftType.UNDECLARED,
                severity=SEVERITY[DriftType.UNDECLARED],
                detail=f"{inst.name}=={inst.version} installed but absent from canonical SBOM",
                installed_version=inst.version,
            ))
            summary[DriftType.UNDECLARED.value] += 1
        elif not _versions_equal(canon.version, inst.version):
            records.append(DriftRecord(
                component=inst,
                drift_type=DriftType.VERSION_MISMATCH,
                severity=SEVERITY[DriftType.VERSION_MISMATCH],
                detail=f"{inst.name}: canonical {canon.version}, installed {inst.version}",
                canonical_version=canon.version,
                installed_version=inst.version,
            ))
            summary[DriftType.VERSION_MISMATCH.value] += 1
        else:
            summary[DriftType.MATCH.value] += 1

    for key, canon in canon_map.items():
        if key not in inst_map:
            records.append(DriftRecord(
                component=canon,
                drift_type=DriftType.MISSING,
                severity=SEVERITY[DriftType.MISSING],
                detail=f"{canon.name}=={canon.version} declared but not installed",
                canonical_version=canon.version,
            ))
            summary[DriftType.MISSING.value] += 1

    records.sort(key=lambda r: (r.drift_type.value, r.component.ecosystem.lower(), canonicalize_name(r.component.name)))

    canonical_format = (
        f"{canonical.format}-{canonical.spec_version}"
        if canonical.spec_version else canonical.format
    )
    return DriftReport(
        generated_at=now,
        tool=tool,
        canonical_source=canonical_source,
        canonical_format=canonical_format,
        env_source=env_source,
        records=records,
        summary=summary,
        subject_commit=canonical.subject_commit,
    )
