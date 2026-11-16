# Dataset card: GitHub reviewed security advisories (OSV format)

## Source
- **Name:** GitHub Advisory Database, reviewed advisories
- **Link:** https://github.com/github/advisory-database
- **Folders downloaded:** `advisories/github-reviewed/2024/01`, `2024/02`, `2024/03`
- **Commit ID downloaded:** 0ce9a25476dc602011009d9d0b9072359497054f
- **Licence:** CC BY 4.0 (Creative Commons Attribution 4.0 International), https://creativecommons.org/licenses/by/4.0/. It allows free use, including for education, if you credit the source. Credit: GitHub Advisory Database, https://github.com/github/advisory-database.
- **Date collected:** 16 November 2026

## Format and size
- One JSON file per advisory, in the OSV schema (nested: `affected` has `ranges`, which have `events`).
- **Records:** 938 files, 938 records read, 0 unreadable.
- **Folder size:** 2.86 MB (3,005,006 bytes)
- Stored in `data/raw/` exactly as downloaded. Never edited.

## What one record represents
One security advisory: a vulnerability in one or more software packages, with its ID, summary, severity, affected package versions and references.

## Personal data
Advisories describe software, not people. No names, phone numbers or ID numbers.

## Quality check (counts, 938 records)
Produced by `scripts/quality_check.py`. Full output: `data/quality_report.txt`. Nothing is fixed here; cleaning happens in Phase IV.

| Check | Count |
|-------|-------|
| Duplicate advisory ids | 0 |
| Withdrawn advisories | 51 |
| No aliases at all (so no CVE id) | 126 |
| No CVSS vector (empty `severity`) | 87 |
| No severity label (`database_specific.severity`) | 0 |
| No CWE id | 83 |
| Affected entries without a version range | 17 |
| Advisories affecting more than one package | 333 |
| Empty summary / no references / bad published date | 0 / 0 / 0 |

Other facts:
- Severity labels: MODERATE 443, HIGH 316, CRITICAL 105, LOW 74.
- CVSS vector types: CVSS_V3 850, CVSS_V4 131 (two different formats).
- Version-range events: introduced 1,716, fixed 1,545, last_affected 159.
- Advisories per ecosystem: Maven 202, PyPI 189, Go 173, Packagist 151, npm 105, crates.io 55, RubyGems 37, NuGet 30, others 10.
