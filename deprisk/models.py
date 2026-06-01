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
