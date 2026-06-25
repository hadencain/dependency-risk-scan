import json
from datetime import datetime

from deprisk.models import Component, SBOMDocument


def _ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    return purl[4:].split("/", 1)[0] or None


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def ingest_cyclonedx(text: str) -> SBOMDocument:
    """Parse a CycloneDX JSON document into an SBOMDocument."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX document (missing bomFormat=CycloneDX)")

    metadata = data.get("metadata", {})
    components = []
    for c in data.get("components", []):
        name = c.get("name")
        if not name:
            continue
        purl = c.get("purl")
        components.append(Component(
            ecosystem=_ecosystem_from_purl(purl) or "pypi",
            name=name,
            version=c.get("version"),
            purl=purl,
            source="cyclonedx",
        ))

    return SBOMDocument(
        format="cyclonedx",
        spec_version=data.get("specVersion", ""),
        components=components,
        serial=data.get("serialNumber"),
        timestamp=_parse_timestamp(metadata.get("timestamp")),
    )
