from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum


@dataclass
class PackageInfo:
    name: str
    pinned: str | None
    latest: str | None = None
    last_release_date: date | None = None
    downloads_last_month: int | None = None
    unavailable: bool = False
    requires_dist: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    package: str
    cve_id: str
    summary: str


@dataclass
class Component:
    ecosystem: str
    name: str
    version: str | None = None
    purl: str | None = None
    source: str = ""


@dataclass
class SBOMDocument:
    format: str
    spec_version: str
    components: list["Component"] = field(default_factory=list)
    serial: str | None = None
    timestamp: datetime | None = None
    tool: str = ""
    subject_repo: str | None = None
    subject_commit: str | None = None


class DriftType(str, Enum):
    UNDECLARED = "UNDECLARED"
    MISSING = "MISSING"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    MATCH = "MATCH"


@dataclass
class DriftRecord:
    component: "Component"
    drift_type: DriftType
    severity: str
    detail: str
    canonical_version: str | None = None
    installed_version: str | None = None


@dataclass
class DriftReport:
    generated_at: datetime
    tool: str
    canonical_source: str
    canonical_format: str
    env_source: str
    records: list["DriftRecord"] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    subject_commit: str | None = None
