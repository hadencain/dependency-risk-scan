from unittest.mock import patch, Mock
from deprisk.github import normalize_github_url, fetch_requirements


def test_normalize_default_path():
    url = normalize_github_url("https://github.com/owner/repo")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/requirements.txt"


def test_normalize_custom_path():
    url = normalize_github_url("https://github.com/owner/repo", path="subdir/reqs.txt")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/subdir/reqs.txt"


def test_normalize_strips_trailing_slash():
    url = normalize_github_url("https://github.com/owner/repo/")
    assert url == "https://raw.githubusercontent.com/owner/repo/HEAD/requirements.txt"


def test_fetch_requirements_success():
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.text = "requests==2.28.0\n"
    with patch("deprisk.github.requests.get", return_value=mock_response):
        result = fetch_requirements("https://github.com/owner/repo")
    assert result == "requests==2.28.0\n"


def test_fetch_requirements_not_found():
    mock_response = Mock()
    mock_response.status_code = 404
    with patch("deprisk.github.requests.get", return_value=mock_response):
        result = fetch_requirements("https://github.com/owner/repo")
    assert result is None
