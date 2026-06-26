import json
import pytest
from unittest.mock import patch
from deprisk.sbom.discover import discover_canonical

CDX = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [{"type": "library", "name": "requests", "version": "2.31.0"}],
})


def test_discover_local_cyclonedx_file(tmp_path):
    f = tmp_path / "bom.json"
    f.write_text(CDX)
    doc = discover_canonical(str(f))
    assert doc.format == "cyclonedx"
    assert doc.components[0].name == "requests"


def test_discover_local_requirements_generates(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("flask==3.0.0\n")
    doc = discover_canonical(str(f))
    assert doc.format == "generated-from-manifests"
    assert doc.components[0].name == "flask"


def test_discover_local_dir_prefers_sbom(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    (tmp_path / "bom.json").write_text(CDX)
    doc = discover_canonical(str(tmp_path))
    assert doc.format == "cyclonedx"


def test_discover_local_dir_falls_back_to_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    doc = discover_canonical(str(tmp_path))
    assert doc.format == "generated-from-manifests"


def test_discover_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        discover_canonical(str(tmp_path))


def test_discover_github_ingests_sbom():
    def fake_fetch(url, path):
        return CDX if path == "bom.json" else None
    with patch("deprisk.sbom.discover.fetch_file", side_effect=fake_fetch):
        doc = discover_canonical("https://github.com/owner/repo")
    assert doc.format == "cyclonedx"
    assert doc.subject_repo == "https://github.com/owner/repo"


def test_discover_github_generates_when_no_sbom():
    def fake_fetch(url, path):
        return "flask==3.0.0\n" if path == "requirements.txt" else None
    with patch("deprisk.sbom.discover.fetch_file", side_effect=fake_fetch):
        doc = discover_canonical("https://github.com/owner/repo")
    assert doc.format == "generated-from-manifests"
