# Changelog

## [2025-12-04] – 0.2.0 - Branch scanning and dependency submission

- Branch scanning:
  - Fetch SBOM diffs for non‑default branches via Dependency Review API.
  - Added `--branch-scan`, `--branch-limit`, and `--diff-base` CLI flags.
- Dependency Submission integration:
  - Automatically submits dependency snapshots for branches being scanned, if not already present, using Component Detection.
  - Language-aware sparse checkout.
  - Use a pre-downloaded binary (`--component-detection-bin`) or an auto-downloaded release.
- Search and matching:
  - Refactored search to de-duplicate logic and include branch diffs (added/updated packages only).
  - Malware matching enhanced to enumerate packages from diffs; matches annotated with branch.
  - CLI and CSV outputs include branch context; CSV adds a `branch` column.
- CLI and UX improvements:
  - Argument validation updated: `--sync-sboms` requires `--sbom-cache`.
  - Malware-only mode: allow `--sync-malware` without `--sbom-cache` (requires `--malware-cache`).
  - JSON/CLI/CSV interaction clarified and documented.
  - Added examples for malware-only sync and branch scanning.
- Advisory sync robustness:
  - GraphQL advisory sync now implements adaptive retries with exponential backoff and `Retry-After` support; respects `--quiet`.

## [2025-10-06] - 0.1.0 - Initial public release

- Initial release, with: SBOM sync; malware sync; malware matching; CLI, file based and interactive PURL searching. SARIF, CSV and JSON outputs supported.
