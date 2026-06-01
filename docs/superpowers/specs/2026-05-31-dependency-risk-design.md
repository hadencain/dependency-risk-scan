# dependencyRisk — Design Spec
2026-05-31

## Purpose

CLI tool (`deprisk`) that reviews Python project dependencies from a local `requirements.txt` or a GitHub repo URL. Reports three risk signals: outdated packages, abandoned libraries, and known vulnerabilities. Terminal output only, no files saved.

---

## Invocation

```bash
# local file
deprisk requirements.txt

# github repo (default branch, root requirements.txt)
deprisk https://github.com/owner/repo

# github repo, non-root path
deprisk https://github.com/owner/repo --path path/to/requirements.txt
```

GitHub URLs are normalized to raw content automatically:
`https://github.com/owner/repo` → `https://raw.githubusercontent.com/owner/repo/HEAD/requirements.txt`

---

## File Layout

```
dependencyRisk/
├── pyproject.toml
├── deprisk/
│   ├── __init__.py
│   ├── cli.py          # argparse entry point, orchestrates pipeline
│   ├── resolver.py     # parse requirements.txt → list of (name, pinned_version|None)
│   ├── github.py       # fetch raw requirements.txt from a GitHub URL
│   ├── pypi.py         # PyPI JSON API + PyPI Stats → version, release date, downloads
│   ├── osv.py          # OSV.dev batch API → CVEs per package
│   └── report.py       # terminal rendering via rich
```

---

## Data Flow

1. `cli.py` receives input (path or URL)
2. If URL → `github.py` fetches raw `requirements.txt` content
3. `resolver.py` parses content → `list[tuple[str, str | None]]` (name, pinned version or None)
4. `pypi.py` fetches PyPI JSON for each package (one request per package)
5. `pypi.py` fetches PyPI Stats for each package (one request per package)
6. `osv.py` sends one batch POST to OSV.dev with all packages
7. `report.py` renders results to terminal

Steps 4–6 run sequentially. Network errors per package mark that package `[data unavailable]` and skip it — the run continues.

---

## Risk Signals

### Outdated
- Pinned version < latest version on PyPI (compared via `packaging.version`)
- Unpinned packages (no `==` specifier) are noted but not flagged as outdated

### Abandoned
- Last release on PyPI > 2 years ago **AND** PyPI Stats `last_month` downloads < 1,000
- Both conditions required — a low-traffic but actively maintained package is not flagged

### Vulnerabilities
- Matched via OSV.dev batch query
- Reports CVE ID and summary per match

---

## Terminal Report Format

```
deprisk · requirements.txt · 24 packages

  OUTDATED (6)
  ┌─────────────────────┬──────────┬──────────┐
  │ Package             │ Pinned   │ Latest   │
  ├─────────────────────┼──────────┼──────────┤
  │ requests            │ 2.28.0   │ 2.32.3   │
  └─────────────────────┴──────────┴──────────┘

  ABANDONED (2)
  ┌─────────────────────┬──────────────────┬────────────────┐
  │ Package             │ Last Release     │ Downloads/mo   │
  ├─────────────────────┼──────────────────┼────────────────┤
  │ old-lib             │ 2021-03-14       │ 412            │
  └─────────────────────┴──────────────────┴────────────────┘

  VULNERABILITIES (3)
  ┌─────────────────────┬──────────────┬────────────────────────────────────┐
  │ Package             │ CVE          │ Summary                            │
  ├─────────────────────┼──────────────┼────────────────────────────────────┤
  │ flask               │ CVE-2023-XXX │ Open redirect in url_for()         │
  └─────────────────────┴──────────────┴────────────────────────────────────┘

  OK  16 packages up to date, no known issues
```

Colors: red for vulnerabilities, yellow for outdated/abandoned, green for OK line.

---

## Dependencies

| Package | Use |
|---------|-----|
| `requests` | HTTP calls to PyPI, PyPI Stats, OSV.dev, GitHub raw |
| `rich` | Terminal tables and color |
| `packaging` | Version comparison |

---

## Data Sources

| Source | Endpoint | Auth |
|--------|----------|------|
| PyPI JSON | `https://pypi.org/pypi/{package}/json` | none |
| PyPI Stats | `https://pypistats.org/api/packages/{package}/recent` | none |
| OSV.dev | `https://api.osv.dev/v1/querybatch` | none |

OSV batch accepts up to 1,000 packages per POST — one call covers the entire requirements file.

---

## Edge Cases

- Private/internal packages not on PyPI → skipped with a note
- Packages without a pinned version → noted, not compared for outdated
- Network error on any individual package → marked `[data unavailable]`, run continues
- GitHub URL pointing to a non-existent file → clear error message, exit 1
