import json
import os
from unittest.mock import patch
from deprisk.models import Component, SBOMDocument
from deprisk.cli import main, run_drift


def _canon():
    return SBOMDocument(format="cyclonedx", spec_version="1.5",
                        components=[Component("pypi", "requests", "2.31.0")])


def test_run_drift_clean_returns_zero(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, str(tmp_path), "high", "deprisk")
    assert code == 0
    files = list(tmp_path.glob("drift-*.json"))
    assert len(files) == 1


def test_run_drift_undeclared_fails(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0"),
                 Component("pypi", "evil", "9.9")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, str(tmp_path), "high", "deprisk")
    assert code == 1
    data = json.loads(list(tmp_path.glob("drift-*.json"))[0].read_text())
    assert data["summary"]["UNDECLARED"] == 1


def test_run_drift_fail_on_none_never_fails():
    installed = [Component("pypi", "evil", "9.9")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, None, "none", "deprisk")
    assert code == 0


def test_run_drift_uses_env_file(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.load_env_file", return_value=installed) as mock_load, \
         patch("deprisk.cli.introspect_environment") as mock_live:
        run_drift("repo", None, "frozen.txt", None, "high", "deprisk")
    mock_load.assert_called_once_with("frozen.txt")
    mock_live.assert_not_called()


def test_main_drift_dispatch(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.introspect_environment", return_value=installed), \
         patch("sys.exit") as mock_exit:
        main(["drift", "repo", "--output", str(tmp_path)])
    mock_exit.assert_called_with(0)


def test_run_drift_commit_arg_sets_subject_commit(tmp_path):
    """Explicit --commit value appears as subject_commit in the report."""
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        run_drift("repo", None, None, str(tmp_path), "high", "deprisk",
                  commit="abc123")
    data = json.loads(list(tmp_path.glob("drift-*.json"))[0].read_text())
    assert data["subject_commit"] == "abc123"


def test_run_drift_falls_back_to_github_sha(tmp_path):
    """When commit=None, $GITHUB_SHA is used."""
    installed = [Component("pypi", "requests", "2.31.0")]
    os.environ["GITHUB_SHA"] = "envsha456"
    try:
        with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
             patch("deprisk.cli.introspect_environment", return_value=installed):
            run_drift("repo", None, None, str(tmp_path), "high", "deprisk",
                      commit=None)
        data = json.loads(list(tmp_path.glob("drift-*.json"))[0].read_text())
        assert data["subject_commit"] == "envsha456"
    finally:
        del os.environ["GITHUB_SHA"]


def test_run_drift_no_commit_no_env_subject_commit_null(tmp_path):
    """When neither --commit nor $GITHUB_SHA is set, subject_commit is null."""
    installed = [Component("pypi", "requests", "2.31.0")]
    saved = os.environ.pop("GITHUB_SHA", None)
    try:
        with patch("deprisk.cli.discover_canonical", return_value=_canon()), \
             patch("deprisk.cli.introspect_environment", return_value=installed):
            run_drift("repo", None, None, str(tmp_path), "high", "deprisk",
                      commit=None)
        data = json.loads(list(tmp_path.glob("drift-*.json"))[0].read_text())
        assert data["subject_commit"] is None
    finally:
        if saved is not None:
            os.environ["GITHUB_SHA"] = saved
