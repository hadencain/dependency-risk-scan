from datetime import datetime, timezone
from deprisk.models import Component, SBOMDocument, DriftType
from deprisk.drift.engine import compare

NOW = datetime(2026, 6, 25, tzinfo=timezone.utc)


def _canon(*comps):
    return SBOMDocument(format="cyclonedx", spec_version="1.5",
                        components=list(comps))


def _run(canonical, installed):
    return compare(canonical, installed,
                   canonical_source="repo", env_source="live", tool="deprisk",
                   now=NOW)


def test_undeclared_dependency_flagged_high():
    canonical = _canon(Component("pypi", "requests", "2.31.0"))
    installed = [Component("pypi", "requests", "2.31.0"),
                 Component("pypi", "evil", "1.0")]
    report = _run(canonical, installed)
    undeclared = [r for r in report.records if r.drift_type is DriftType.UNDECLARED]
    assert len(undeclared) == 1
    assert undeclared[0].component.name == "evil"
    assert undeclared[0].severity == "high"
    assert report.summary["UNDECLARED"] == 1
    assert report.summary["MATCH"] == 1


def test_missing_dependency_flagged_medium():
    canonical = _canon(Component("pypi", "requests", "2.31.0"),
                       Component("pypi", "flask", "3.0.0"))
    installed = [Component("pypi", "requests", "2.31.0")]
    report = _run(canonical, installed)
    missing = [r for r in report.records if r.drift_type is DriftType.MISSING]
    assert len(missing) == 1
    assert missing[0].component.name == "flask"
    assert missing[0].severity == "medium"


def test_version_mismatch_flagged():
    canonical = _canon(Component("pypi", "requests", "2.31.0"))
    installed = [Component("pypi", "requests", "2.28.0")]
    report = _run(canonical, installed)
    mism = [r for r in report.records if r.drift_type is DriftType.VERSION_MISMATCH]
    assert len(mism) == 1
    assert mism[0].canonical_version == "2.31.0"
    assert mism[0].installed_version == "2.28.0"


def test_name_normalization_matches():
    canonical = _canon(Component("pypi", "Foo_Bar", "1.0"))
    installed = [Component("pypi", "foo-bar", "1.0")]
    report = _run(canonical, installed)
    assert report.summary["MATCH"] == 1
    assert report.records == []


def test_equivalent_versions_match():
    canonical = _canon(Component("pypi", "x", "1.0"))
    installed = [Component("pypi", "x", "1.0.0")]
    report = _run(canonical, installed)
    assert report.summary["MATCH"] == 1


def test_empty_canonical_all_undeclared():
    report = _run(_canon(), [Component("pypi", "a", "1.0")])
    assert report.summary["UNDECLARED"] == 1


def test_empty_installed_all_missing():
    report = _run(_canon(Component("pypi", "a", "1.0")), [])
    assert report.summary["MISSING"] == 1


def test_both_empty_no_records():
    report = _run(_canon(), [])
    assert report.records == []
    assert report.canonical_format == "cyclonedx-1.5"
    assert report.generated_at == NOW
