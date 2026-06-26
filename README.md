# deprisk

Audit Python dependencies for risk signals and SBOM drift monitoring — from a local `requirements.txt` or any public GitHub repo.

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

**Local file (audit):**
```bash
deprisk scan requirements.txt
```

Or via the compatibility shim (also works):
```bash
deprisk requirements.txt
```

**GitHub repo** (fetches `requirements.txt` from the default branch):
```bash
deprisk scan https://github.com/owner/repo
```

**GitHub repo, non-root path:**
```bash
deprisk scan https://github.com/owner/repo --path backend/requirements.txt
```

## What it checks

| Signal | Criteria |
|--------|----------|
| **Outdated** | Pinned version < latest on PyPI |
| **Abandoned** | Last release > 2 years ago AND < 1,000 downloads/month |
| **Vulnerabilities** | Known CVEs via [OSV.dev](https://osv.dev) |

Unpinned packages (no `==` specifier) are noted but not compared for outdated. Packages not found on PyPI are skipped with a note.

## SBOM drift monitoring

Detect shadow / undeclared dependencies by comparing a canonical SBOM against
the packages actually installed in an environment.

**One-shot drift check** (live environment vs canonical SBOM in a repo):
```bash
deprisk drift https://github.com/owner/repo --output ./drift-reports
```

If the repo commits a CycloneDX SBOM (`bom.json`, `sbom.json`, `cyclonedx.json`)
it is used as canonical truth; otherwise one is generated from `requirements.txt`.

**Compare against a captured snapshot** (CI artifact / remote host):
```bash
pip freeze > prod-freeze.txt
deprisk drift ./bom.json --env-file prod-freeze.txt --output ./drift-reports
```

**Scheduled daemon** (CI/CD):
```bash
deprisk daemon https://github.com/owner/repo --interval 3600 --output ./drift-reports
```

Both `deprisk drift` and `deprisk daemon` accept `--commit <sha>` (falling back to `$GITHUB_SHA`) to record canonical provenance in the report's `subject_commit` field.

Drift reports are timestamped JSON written to `--output`, carrying audit metadata
(generated_at, tool version, canonical source + commit, env source, drift counts)
suitable as ISO 27001 / SOC2 evidence.

`deprisk drift` exits non-zero when drift at or above `--fail-on` severity is found
(default `high`, i.e. any undeclared/shadow dependency), gating CI builds. Use
`--fail-on none` to report without failing.

| Drift type | Meaning | Severity |
|------------|---------|----------|
| `UNDECLARED` | Installed but not in canonical SBOM (shadow dep) | high |
| `MISSING` | In canonical SBOM but not installed | medium |
| `VERSION_MISMATCH` | Installed version differs from canonical | medium |

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
