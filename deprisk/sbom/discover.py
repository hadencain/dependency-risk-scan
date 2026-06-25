import os

from deprisk.github import fetch_file
from deprisk.models import SBOMDocument
from deprisk.sbom.generate import generate_from_requirements
from deprisk.sbom.ingest import ingest_cyclonedx

SBOM_CANDIDATES = ["bom.json", "sbom.json", "cyclonedx.json"]


def _from_text(text: str) -> SBOMDocument:
    """Ingest as CycloneDX if possible, else treat as a requirements manifest."""
    try:
        return ingest_cyclonedx(text)
    except ValueError:
        return generate_from_requirements(text)


def _discover_github(url: str, path: str | None) -> SBOMDocument:
    candidates = [path] if path else SBOM_CANDIDATES + ["requirements.txt"]
    for candidate in candidates:
        text = fetch_file(url, candidate)
        if text is not None:
            doc = _from_text(text)
            doc.subject_repo = url
            return doc
    raise FileNotFoundError(f"No SBOM or requirements found in {url}")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _discover_local(source: str, path: str | None) -> SBOMDocument:
    if path:
        target = os.path.join(source, path) if os.path.isdir(source) else path
        return _from_text(_read(target))
    if os.path.isfile(source):
        return _from_text(_read(source))
    if os.path.isdir(source):
        for candidate in SBOM_CANDIDATES + ["requirements.txt"]:
            target = os.path.join(source, candidate)
            if os.path.isfile(target):
                return _from_text(_read(target))
    raise FileNotFoundError(f"No SBOM or requirements found at {source}")


def discover_canonical(source: str, path: str | None = None) -> SBOMDocument:
    """Resolve the canonical SBOM: ingest if a committed SBOM exists, else generate."""
    if source.startswith("https://github.com/"):
        return _discover_github(source, path)
    return _discover_local(source, path)
