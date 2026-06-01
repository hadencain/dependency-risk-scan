# deprisk

Audit Python dependencies for risk signals — from a local `requirements.txt` or any public GitHub repo.

```
deprisk · requirements.txt · 24 packages

  OUTDATED (3)
  Package    Pinned    Latest
  ─────────────────────────────
  requests   2.28.0    2.34.2
  flask      2.2.0     3.1.3

  VULNERABILITIES (2)
  Package    CVE             Summary
  ──────────────────────────────────────────────────────────
  flask      CVE-2023-30861  Session cookie not marked HttpOnly

  OK  19 packages up to date, no known issues
```

## Install

Requires Python 3.10+.

```bash
pip install .
```

Or from a clone:

```bash
git clone https://github.com/your-username/dependencyRisk
cd dependencyRisk
pip install .
```

## Usage

**Local file:**
```bash
deprisk requirements.txt
```

**GitHub repo** (fetches `requirements.txt` from the default branch):
```bash
deprisk https://github.com/owner/repo
```

**GitHub repo, non-root path:**
```bash
deprisk https://github.com/owner/repo --path backend/requirements.txt
```

## What it checks

| Signal | Criteria |
|--------|----------|
| **Outdated** | Pinned version < latest on PyPI |
| **Abandoned** | Last release > 2 years ago AND < 1,000 downloads/month |
| **Vulnerabilities** | Known CVEs via [OSV.dev](https://osv.dev) |

Unpinned packages (no `==` specifier) are noted but not compared for outdated. Packages not found on PyPI are skipped with a note.

## Data sources

All free, no API keys required.

- [PyPI JSON API](https://pypi.org/pypi/{package}/json) — version and release dates
- [PyPI Stats](https://pypistats.org) — monthly download counts
- [OSV.dev](https://osv.dev) — vulnerability database (batch query, one call per run)

## Development

```bash
pip install -e .
pip install pytest
pytest
```
