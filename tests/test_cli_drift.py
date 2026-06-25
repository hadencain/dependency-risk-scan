import json
from unittest.mock import patch
from deprisk.models import Component, SBOMDocument
from deprisk.cli import main, run_drift

CANON = SBOMDocument(format="cyclonedx", spec_version="1.5",
                     components=[Component("pypi", "requests", "2.31.0")])


def test_run_drift_clean_returns_zero(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=CANON), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, str(tmp_path), "high", "deprisk")
    assert code == 0
    files = list(tmp_path.glob("drift-*.json"))
    assert len(files) == 1


def test_run_drift_undeclared_fails(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0"),
                 Component("pypi", "evil", "9.9")]
    with patch("deprisk.cli.discover_canonical", return_value=CANON), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, str(tmp_path), "high", "deprisk")
    assert code == 1
    data = json.loads(list(tmp_path.glob("drift-*.json"))[0].read_text())
    assert data["summary"]["UNDECLARED"] == 1


def test_run_drift_fail_on_none_never_fails():
    installed = [Component("pypi", "evil", "9.9")]
    with patch("deprisk.cli.discover_canonical", return_value=CANON), \
         patch("deprisk.cli.introspect_environment", return_value=installed):
        code = run_drift("repo", None, None, None, "none", "deprisk")
    assert code == 0


def test_run_drift_uses_env_file(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=CANON), \
         patch("deprisk.cli.load_env_file", return_value=installed) as mock_load, \
         patch("deprisk.cli.introspect_environment") as mock_live:
        run_drift("repo", None, "frozen.txt", None, "high", "deprisk")
    mock_load.assert_called_once_with("frozen.txt")
    mock_live.assert_not_called()


def test_main_drift_dispatch(tmp_path):
    installed = [Component("pypi", "requests", "2.31.0")]
    with patch("deprisk.cli.discover_canonical", return_value=CANON), \
         patch("deprisk.cli.introspect_environment", return_value=installed), \
         patch("sys.exit") as mock_exit:
        main(["drift", "repo", "--output", str(tmp_path)])
    mock_exit.assert_called_with(0)
