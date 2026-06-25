import json
import pytest
from deprisk.sbom.ingest import ingest_cyclonedx

CDX = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:abc",
    "metadata": {"timestamp": "2026-06-20T10:00:00Z"},
    "components": [
        {"type": "library", "name": "requests", "version": "2.31.0",
         "purl": "pkg:pypi/requests@2.31.0"},
        {"type": "library", "name": "flask", "version": "3.0.0"},
    ],
})


def test_ingest_parses_components():
    doc = ingest_cyclonedx(CDX)
    assert doc.format == "cyclonedx"
    assert doc.spec_version == "1.5"
    assert doc.serial == "urn:uuid:abc"
    assert doc.timestamp.year == 2026
    names = {c.name for c in doc.components}
    assert names == {"requests", "flask"}
    req = next(c for c in doc.components if c.name == "requests")
    assert req.ecosystem == "pypi"
    assert req.version == "2.31.0"
    assert req.source == "cyclonedx"


def test_ingest_component_without_purl_defaults_pypi():
    doc = ingest_cyclonedx(CDX)
    flask = next(c for c in doc.components if c.name == "flask")
    assert flask.ecosystem == "pypi"


def test_ingest_rejects_non_cyclonedx():
    with pytest.raises(ValueError):
        ingest_cyclonedx(json.dumps({"bomFormat": "SPDX"}))


def test_ingest_rejects_bad_json():
    with pytest.raises(ValueError):
        ingest_cyclonedx("{not json")


def test_ingest_skips_nameless_component():
    doc = ingest_cyclonedx(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [{"type": "library", "version": "1.0"}],
    }))
    assert doc.components == []
