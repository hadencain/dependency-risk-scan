from unittest.mock import patch, Mock, call
from deprisk.osv import fetch_vulnerabilities
from deprisk.models import Vulnerability


def _mock_post(url, json=None, **kwargs):
    name = json.get("package", {}).get("name", "")
    mock = Mock()
    mock.status_code = 200
    if name == "flask":
        mock.json.return_value = {
            "vulns": [
                {
                    "id": "PYSEC-2023-001",
                    "aliases": ["CVE-2023-1234"],
                    "summary": "Open redirect vulnerability",
                }
            ]
        }
    else:
        mock.json.return_value = {"vulns": []}
    return mock


def test_returns_cve_from_aliases():
    with patch("deprisk.osv.requests.post", side_effect=_mock_post):
        result = fetch_vulnerabilities([("flask", "2.2.0"), ("requests", "2.28.0")])
    assert len(result) == 1
    assert result[0].package == "flask"
    assert result[0].cve_id == "CVE-2023-1234"
    assert result[0].summary == "Open redirect vulnerability"


def test_falls_back_to_osv_id_when_no_cve():
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {
        "vulns": [{"id": "PYSEC-2023-999", "aliases": [], "summary": "Some vuln"}]
    }
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("flask", "2.2.0")])
    assert result[0].cve_id == "PYSEC-2023-999"


def test_returns_empty_list_when_no_vulns():
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {"vulns": []}
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("requests", "2.32.3")])
    assert result == []


def test_returns_empty_list_on_network_error():
    with patch("deprisk.osv.requests.post", side_effect=Exception("network error")):
        result = fetch_vulnerabilities([("flask", "2.2.0")])
    assert result == []


def test_uses_details_fallback_when_no_summary():
    mock = Mock()
    mock.status_code = 200
    mock.json.return_value = {
        "vulns": [
            {
                "id": "PYSEC-2023-001",
                "aliases": ["CVE-2023-1234"],
                "summary": "",
                "details": "A long detailed description of the vulnerability that exceeds one hundred and twenty characters in total length.",
            }
        ]
    }
    with patch("deprisk.osv.requests.post", return_value=mock):
        result = fetch_vulnerabilities([("flask", "2.2.0")])
    assert result[0].summary != ""
    assert len(result[0].summary) <= 120
