from dataclasses import dataclass, field
from datetime import date


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
