import json
from datetime import datetime, timezone
from deprisk.models import Component, DriftRecord, DriftReport, DriftType
from deprisk.drift.report import (
    report_to_dict, report_to_json, write_report, max_severity_rank,
)

NOW = datetime(2026, 6, 25, 12, 30, 45, tzinfo=timezone.utc)


def _report(records):
    summary = {t.value: 0 for t in DriftType}
    for r in records:
        summary[r.drift_type.value] += 1
    return DriftReport(
        generated_at=NOW, tool="deprisk 0.1.0",
        canonical_source="https://github.com/owner/repo",
        canonical_format="cyclonedx-1.5", env_source="live:python3.14@host",
        records=records, summary=summary, subject_commit="abc123",
    )


def _undeclared():
    return DriftRecord(
        component=Component("pypi", "evil", "1.0", source="live-env"),
        drift_type=DriftType.UNDECLARED, severity="high",
        detail="shadow", installed_version="1.0",
    )


def test_report_to_dict_has_audit_metadata():
    d = report_to_dict(_report([_undeclared()]))
    assert d["generated_at"] == "2026-06-25T12:30:45+00:00"
    assert d["tool"] == "deprisk 0.1.0"
    assert d["canonical_source"] == "https://github.com/owner/repo"
    assert d["canonical_format"] == "cyclonedx-1.5"
    assert d["env_source"] == "live:python3.14@host"
    assert d["subject_commit"] == "abc123"
    assert d["summary"]["UNDECLARED"] == 1
    assert d["records"][0]["drift_type"] == "UNDECLARED"
    assert d["records"][0]["component"]["name"] == "evil"


def test_report_to_json_roundtrips():
    text = report_to_json(_report([_undeclared()]))
    assert json.loads(text)["records"][0]["severity"] == "high"


def test_write_report_creates_timestamped_file(tmp_path):
    path = write_report(_report([_undeclared()]), str(tmp_path))
    assert path.endswith("drift-20260625T123045Z.json")
    with open(path) as f:
        assert json.load(f)["summary"]["UNDECLARED"] == 1


def test_max_severity_rank():
    assert max_severity_rank(_report([_undeclared()])) == 3
    assert max_severity_rank(_report([])) == 0
