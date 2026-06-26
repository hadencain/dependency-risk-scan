import json
from datetime import datetime, timezone

from packaging.utils import canonicalize_name

from deprisk.models import Component, SBOMDocument
from deprisk.resolver import parse_requirements


def generate_from_requirements(content: str, tool: str = "deprisk") -> SBOMDocument:
    """Build an SBOMDocument from requirements.txt content."""
    components = []
    for name, pinned in parse_requirements(content):
        key = canonicalize_name(name)
        purl = f"pkg:pypi/{key}@{pinned}" if pinned else f"pkg:pypi/{key}"
        components.append(Component(
            ecosystem="pypi", name=name, version=pinned,
            purl=purl, source="manifest",
        ))
    return SBOMDocument(
        format="generated-from-manifests", spec_version="", components=components, tool=tool,
    )


def to_cyclonedx(doc: SBOMDocument) -> str:
    """Emit a minimal CycloneDX 1.5 JSON document."""
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": doc.tool or "deprisk"}],
        },
        "components": [
            {
                "type": "library",
                "name": c.name,
                **({"version": c.version} if c.version else {}),
                **({"purl": c.purl} if c.purl else {}),
            }
            for c in doc.components
        ],
    }
    return json.dumps(payload, indent=2)
