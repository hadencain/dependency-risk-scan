import json
from deprisk.sbom.generate import generate_from_requirements, to_cyclonedx
from deprisk.sbom.ingest import ingest_cyclonedx

REQS = "requests==2.31.0\nflask>=3.0\n# comment\n\n-e .\n"


def test_generate_parses_pinned_and_unpinned():
    doc = generate_from_requirements(REQS)
    by_name = {c.name: c for c in doc.components}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].purl == "pkg:pypi/requests@2.31.0"
    assert by_name["flask"].version is None
    assert by_name["flask"].purl == "pkg:pypi/flask"
    assert doc.format == "generated-from-manifests"


def test_to_cyclonedx_is_valid_cyclonedx():
    doc = generate_from_requirements("requests==2.31.0\n")
    text = to_cyclonedx(doc)
    data = json.loads(text)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert data["components"][0]["name"] == "requests"
    assert data["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


def test_generate_emit_roundtrips_through_ingest():
    doc = generate_from_requirements("requests==2.31.0\n")
    reingested = ingest_cyclonedx(to_cyclonedx(doc))
    assert reingested.components[0].name == "requests"
    assert reingested.components[0].version == "2.31.0"
