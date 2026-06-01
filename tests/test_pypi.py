from datetime import date
from unittest.mock import patch, Mock
from deprisk.pypi import fetch_pypi_data
from deprisk.models import PackageInfo

PYPI_RESPONSE = {
    "info": {"version": "2.32.3"},
    "releases": {
        "2.32.3": [{"upload_time": "2024-05-20T10:00:00"}],
        "2.28.0": [{"upload_time": "2022-01-15T10:00:00"}],
    },
}

STATS_RESPONSE = {
    "data": {"last_month": 5000000}
}

def _mock_get(url, **kwargs):
    mock = Mock()
    if "pypi.org" in url:
        mock.status_code = 200
        mock.json.return_value = PYPI_RESPONSE
    elif "pypistats.org" in url:
        mock.status_code = 200
        mock.json.return_value = STATS_RESPONSE
    return mock

def test_returns_latest_version():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.latest == "2.32.3"

def test_returns_download_count():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.downloads_last_month == 5000000

def test_returns_last_release_date():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", "2.28.0")
    assert result.last_release_date == date(2024, 5, 20)

def test_unpinned_package():
    with patch("deprisk.pypi.requests.get", side_effect=_mock_get):
        result = fetch_pypi_data("requests", None)
    assert result.pinned is None
    assert result.latest == "2.32.3"

def test_unavailable_package():
    mock = Mock()
    mock.status_code = 404
    with patch("deprisk.pypi.requests.get", return_value=mock):
        result = fetch_pypi_data("private-lib", "1.0.0")
    assert result.unavailable is True
