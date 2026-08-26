# Changelog

## [Unreleased]

Added:

- Continuous integration: GitHub Actions workflow that restores packages, builds and tests on every push to `main` and every pull request.
- Unit tests using Node's built-in test runner (no new dependencies) covering the shipped fixtures: SBOM and advisory cache loading, branch diffs, malware matching and the advisory date cutoff, the ignore file, PURL search, and the documented offline CLI invocations.
- [TESTING.md](TESTING.md) documenting how to run the tests and what they cover.

Fixed:

- Corrected the example test output in the README, which named a repository that is not in the fixtures and omitted the branch match.

## [2025-12-09] – 0.2.0 - Branch scanning and dependency submission

Added:

- Branch scanning:
  - Fetch SBOM diffs for non‑default branches via Dependency Review API.
  - Added `--branch-scan`, `--branch-limit`, and `--diff-base` CLI flags.
- Dependency Submission integration:
  - Automatically submits dependency snapshots for branches being scanned, if not already present, using Component Detection.
  - Language-aware sparse checkout.
  - Use a pre-downloaded binary (`--component-detection-bin`) or an auto-downloaded release.
  - Allows forcing submission, even if a snapshot already exists.
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
  - GraphQL advisory sync implements adaptive retries with exponential backoff and `Retry-After` support.

Fixed:

- Added `--ghes` flag to ensure proper API URL construction for GitHub Enterprise Server instances.

## [2025-10-06] - 0.1.0 - Initial public release

- Initial release, with: SBOM sync; malware sync; malware matching; CLI, file based and interactive PURL searching. SARIF, CSV and JSON outputs supported.
