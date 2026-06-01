from unittest.mock import patch, Mock
from deprisk.cli import main
from deprisk.models import PackageInfo, Vulnerability

REQUIREMENTS_CONTENT = "requests==2.28.0\n"
PACKAGE = PackageInfo(name="requests", pinned="2.28.0", latest="2.32.3")
VULNS: list[Vulnerability] = []

def test_cli_local_file(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(REQUIREMENTS_CONTENT)

    with patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render") as mock_render:
        main([str(req_file)])

    mock_render.assert_called_once()
    _, packages, vulns = mock_render.call_args[0]
    assert packages == [PACKAGE]
    assert vulns == VULNS

def test_cli_github_url():
    with patch("deprisk.cli.fetch_requirements", return_value=REQUIREMENTS_CONTENT), \
         patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render") as mock_render:
        main(["https://github.com/owner/repo"])

    mock_render.assert_called_once()

def test_cli_github_url_not_found():
    with patch("deprisk.cli.fetch_requirements", return_value=None), \
         patch("sys.exit") as mock_exit:
        main(["https://github.com/owner/repo"])
    mock_exit.assert_called_with(1)

def test_cli_github_custom_path():
    with patch("deprisk.cli.fetch_requirements", return_value=REQUIREMENTS_CONTENT) as mock_fetch, \
         patch("deprisk.cli.fetch_pypi_data", return_value=PACKAGE), \
         patch("deprisk.cli.fetch_vulnerabilities", return_value=VULNS), \
         patch("deprisk.cli.render"):
        main(["https://github.com/owner/repo", "--path", "subdir/reqs.txt"])

    mock_fetch.assert_called_with("https://github.com/owner/repo", path="subdir/reqs.txt")

def test_cli_missing_local_file():
    with patch("sys.exit") as mock_exit:
        main(["/nonexistent/requirements.txt"])
    mock_exit.assert_called_with(1)
