from datetime import datetime, timezone
from deprisk.models import (
    Component, SBOMDocument, DriftType, DriftRecord, DriftReport,
)


def test_component_defaults():
    c = Component(ecosystem="pypi", name="requests")
    assert c.version is None
    assert c.purl is None
    assert c.source == ""


def test_sbom_document_holds_components():
    doc = SBOMDocument(format="cyclonedx", spec_version="1.5",
                       components=[Component("pypi", "flask", "3.0.0")])
    assert doc.components[0].name == "flask"
    assert doc.serial is None


def test_drift_type_values():
    assert DriftType.UNDECLARED.value == "UNDECLARED"
    assert DriftType.MATCH.value == "MATCH"


def test_drift_report_holds_records():
    rec = DriftRecord(
        component=Component("pypi", "evil", "1.0"),
        drift_type=DriftType.UNDECLARED,
        severity="high",
        detail="shadow dep",
        installed_version="1.0",
    )
    report = DriftReport(
        generated_at=datetime(2026, 6, 25, tzinfo=timezone.utc),
        tool="deprisk 0.1.0",
        canonical_source="https://github.com/owner/repo",
        canonical_format="cyclonedx-1.5",
        env_source="live:python3.14@host",
        records=[rec],
        summary={"UNDECLARED": 1},
    )
    assert report.records[0].drift_type is DriftType.UNDECLARED
    assert report.summary["UNDECLARED"] == 1
