import requests


def normalize_github_url(url: str, path: str = "requirements.txt") -> str:
    if not url.startswith("https://github.com/"):
        raise ValueError(f"Invalid GitHub URL: {url}")
    url = url.rstrip("/")
    parts = url.replace("https://github.com/", "")
    return f"https://raw.githubusercontent.com/{parts}/HEAD/{path}"


def fetch_requirements(url: str, path: str = "requirements.txt") -> str | None:
    raw_url = normalize_github_url(url, path)
    response = requests.get(raw_url, timeout=10)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.text
