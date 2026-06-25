from packaging.requirements import InvalidRequirement, Requirement

from deprisk.models import Component
from deprisk.sbom.ingest import ingest_cyclonedx


def parse_freeze(text: str) -> list[Component]:
    """Parse `pip freeze` output into components, skipping editable/option lines."""
    components = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-") or "@" in line:
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        version = None
        for spec in req.specifier:
            if spec.operator == "==":
                version = spec.version
                break
        components.append(Component(
            ecosystem="pypi", name=req.name, version=version,
            purl=f"pkg:pypi/{req.name.lower()}@{version}" if version else None,
            source="freeze-file",
        ))
    return components


def load_env_file(path: str) -> list[Component]:
    """Load production components from a file: CycloneDX JSON or pip-freeze text."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        doc = ingest_cyclonedx(text)
    except ValueError:
        return parse_freeze(text)
    for c in doc.components:
        c.source = "prod-sbom"
    return doc.components


def file_env_descriptor(path: str) -> str:
    return f"file:{path}"
