# GitHub SBOM toolkit

Enumerate Dependency Graph SBOMs from all repositories in a GitHub Enterprise (all orgs) or a single organization.

Search collected SBOMs by PURL, save all results to disk, sync malware security advisories, and match SBOM packages against those advisories.

## Features

- Enumerate orgs in an Enterprise and repos in each org
- Fetch SBOM per repo with concurrency + optional delay and retry/throttle handling
- Search for packages by exact PURL or prefix (use trailing `/*`)
- Serialize/load SBOMs to/from JSON files
- Sync malware security advisories from the GitHub Advisory Database
- Version-aware matching of SBOM packages vs. malware advisories
- Works with GitHub.com, GitHub Enterprise Server, GitHub Enterprise Managed Users and GitHub Enterprise Cloud with Data Residency (custom base URL)

## Auth Requirements

Token needs scopes: `repo`, `read:org`, and `security_events` (for dependency graph SBOM API). For public-only scanning you may omit `repo`.

## Usage

Example:

```bash
node dist/cli.js --enterprise my-enterprise --out sboms --purl pkg:npm/lodash@4.17.21
```

Search multiple purls:

```bash
node dist/cli.js --org my-org --purl pkg:npm/react@18.2.0 --purl 'pkg:npm/express/*'
```

Using GitHub Enterprise Server:

```bash
node dist/cli.js --enterprise ent --base-url https://github.internal/api/v3 --token $GHES_TOKEN
```

Sync malware advisories and run match (after collecting SBOMs):

```bash
node dist/cli.js --org my-org --sync-malware --match-malware --malware-cache malware-cache
```

Load previously serialized SBOMs and just perform malware match (no new SBOM calls):

```bash
node dist/cli.js --load sboms --sync-malware --match-malware --malware-cache malware-cache
```

### Offline Fixture Test

The repo ships with a minimal test fixture to validate end-to-end malware matching without making network calls.

1. Build the project:

```bash
npm install
npm run build
```

1. Run the test harness script:

```bash
node dist/test-fixture-match.js
```

You should see output similar to:

```text
Matches:
chalk-org/chalk-repo => pkg:npm/chalk@5.6.1 matched advisory GHSA-test-chalk-561 range =5.6.1
```

Alternatively, you can exercise the CLI purely offline using the fixtures:

```bash
node dist/cli.js --load fixtures/sboms --malware-cache fixtures/malware-cache --match-malware
```

No token is required for purely offline use, where the SBOMs and malware cache are preloaded from disk.

### Incremental Mode

Skip re-fetching SBOMs for repositories whose `pushed_at` timestamp has not advanced since a previous run.

1. First collection (also serialize SBOMs):

```bash
node dist/cli.js --org my-org --out sboms
```

1. Subsequent incremental run comparing to previous baseline:

```bash
node dist/cli.js --org my-org --out sboms --baseline sboms --incremental
```

Summary output will include `Skipped: <n>` showing how many repos reused the baseline SBOM.

Notes:

- Uses `pushed_at` from the existing org repository listing; no extra API calls.
- A push to any branch updates `pushed_at` (may cause a fetch even if default branch unchanged).
- Future enhancement: store ETag and use conditional requests, or fetch default branch HEAD SHA.

## Build

```bash
npm install
npm run build
```

## Notes

- Rate limiting and secondary limits are automatically retried (up to 2 times) via Octokit throttling plugin.

## License

MIT License
