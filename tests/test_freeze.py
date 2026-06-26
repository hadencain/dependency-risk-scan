import json
from deprisk.env.freeze import parse_freeze, load_env_file, file_env_descriptor

FREEZE = """\
# editable install below
-e git+https://example.com/x.git#egg=x
requests==2.31.0
Flask==3.0.0
weird @ file:///tmp/weird-1.0.tar.gz
-r other.txt
"""

CDX = json.dumps({
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [{"type": "library", "name": "django", "version": "5.0",
                    "purl": "pkg:pypi/django@5.0"}],
})


def test_parse_freeze_extracts_pinned():
    comps = {c.name: c for c in parse_freeze(FREEZE)}
    assert comps["requests"].version == "2.31.0"
    assert comps["Flask"].version == "3.0.0"
    assert comps["requests"].source == "freeze-file"


def test_parse_freeze_skips_editable_and_options_but_keeps_direct_refs():
    comps = {c.name: c for c in parse_freeze(FREEZE)}
    names = set(comps.keys())
    assert "x" not in names        # editable (-e) still skipped
    assert "other.txt" not in names # option line (-r) still skipped
    # direct-reference installs (name @ url) must now be kept
    assert "weird" in names
    assert comps["weird"].version is None


def test_load_env_file_freeze(tmp_path):
    f = tmp_path / "frozen.txt"
    f.write_text(FREEZE)
    names = {c.name for c in load_env_file(str(f))}
    assert "requests" in names


def test_load_env_file_cyclonedx(tmp_path):
    f = tmp_path / "prod-bom.json"
    f.write_text(CDX)
    comps = load_env_file(str(f))
    assert comps[0].name == "django"
    assert comps[0].source == "prod-sbom"


def test_file_env_descriptor():
    assert file_env_descriptor("/a/b.txt") == "file:/a/b.txt"
