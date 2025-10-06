# GitHub SBOM toolkit

Enumerate Dependency Graph SBOMs from all repositories in a GitHub Enterprise (all orgs) or a single organization.

Search collected SBOMs by PURL, cache them for offline analysis, sync malware security advisories, and match SBOM packages against those advisories.

Supports human-readable, JSON, CSV and SARIF output. SARIF alerts can be uploaded to GitHub Code Scanning.

> [!NOTE]
> This is an _unofficial_ tool created by Field Security Specialists, and is not officially supported by GitHub.

## 🚀 Features

- Enumerate organizations in an Enterprise and repositories in each organization
- Fetch SBOM per repository with concurrency + optional delay and retry/throttle handling
  - Optional progress bar while fetching SBOMs
  - Option to suppress secondary rate limit warnings, and full quiet mode to suppress informative messages
  - Adaptive backoff: each secondary rate limit hit increases the SBOM fetch delay by 10% to reduce future throttling
- Offline caching of SBOMs and security advisories with incremental updates
- Matching:
  - Version-aware matching of SBOM packages against malware advisories
    - Optional suppression of "unbounded" malware advisories that state all versions are affected (e.g. vulnerable range '*', '>=0')
  - Search for packages by exact PURL, semver/range, or wildcard (trailing `/*` after the package name path segment)
  - Interactive REPL for ad‑hoc PURL queries (history, graceful Ctrl+C handling)
  - YAML ignore file support to suppress specific advisory IDs or PURLs globally or scoped to an org / repo
  - Reason tracing: every search match shows which query matched; every malware match shows which advisory triggered it
- Output:
  - Human-readable console output
  - JSON or CSV output (to stdout or file) with both search and malware matches
  - Optional SARIF 2.1.0 output per repository for malware matches with optional Code Scanning upload
- Works with GitHub.com, GitHub Enterprise Server, GitHub Enterprise Managed Users and GitHub Enterprise Cloud with Data Residency (custom base URL)

## Usage

### Quick Start

Collect SBOMs for all repositories in an organization (writes JSON files into `sboms/`) then perform a PURL search:

```bash
npm run start -- --sync-sboms --org my-org --sbom-cache sboms --purl pkg:npm/lodash@4.17.21
```

Search multiple PURLs (exact, wildcard, and a semver range). The `pkg:` prefix is optional; it will be auto-added:

```bash
npm run start -- --sbom-cache sboms \
  --purl npm/react@18.2.0 \
  --purl 'npm/express/*' \
  --purl 'npm/chalk@>=5.0.0 <6.0.0'
```

Using GitHub Enterprise Server:

```bash
npm run start -- --sync-sboms --enterprise ent --base-url https://github.internal/api/v3 --sbom-cache sboms --token $GHES_TOKEN
```

### 🔑 Authentication

A GitHub token with appropriate scope is required when performing network operations such as `--sync-sboms`, `--sync-malware` and `--upload-sarif`.

A fine-grained PAT needs scope `Read-only` on `Contents`. To upload SARIF you need `Read and write` on `Code scanning alerts`. If necessary you can use a Classic PAT, or a token from a GitHub App with `repo`, `read:org`, and `security_events` (write) scopes. You may find generating a token with the [`gh` CLI](https://cli.github.com/) is convenient.

It can be provided in the `GITHUB_TOKEN` environment variable, or with the `--token` argument.

Offline operations (pure searches, matches using pre-cached data) need no token.

### Supplying PURL Queries from a File

Provide a file containing one or more PURL (or PURL + semver range) queries, one per line. Blank lines and lines starting with `#` are ignored.

Example file `queries.txt`:

```text
# Exact PURL
pkg:npm/chalk@5.6.1

# Version range (semver caret)
pkg:npm/chalk@^5.0.0

# Version range (inequalities)
pkg:npm/chalk@>=5.0.0 <6.0.0

```

Run with (e.g. offline SBOMs):

```bash
npm run start -- --sbom-cache sboms --purl-file queries.txt
```

### SBOM Caching Workflow

1. First collection (populates cache progressively as it runs):

```bash
npm run start -- --sync-sboms --org my-org --sbom-cache sboms
```

2. Later offline search (no API calls; uses previously written per‑repo JSON):

```bash
npm run start -- --sbom-cache sboms --purl pkg:npm/react@18.2.0
```

### Malware Advisory Sync & Matching

Sync malware advisories and then match against SBOM packages in one run:

```bash
npm run start -- --sync-sboms --org my-org --sbom-cache sboms --sync-malware --malware-cache malware-cache --match-malware
```

Use already cached SBOMs (offline) while updating advisories:

```bash
npm run start -- --sbom-cache sboms --sync-malware --malware-cache malware-cache --match-malware
```

Offline match with already-cached malware advisories (no network calls):

```bash
npm run start -- --sbom-cache sboms --malware-cache malware-cache --match-malware
```

Write malware matches (and optionally search results later) to a JSON file using `--output-file`:

```bash
npm run start -- --sbom-cache sboms --malware-cache malware-cache --match-malware --output-file report.json
```

If you also perform a search in the same invocation (add `--purl` or `--purl-file`), the JSON file will contain both `malwareMatches` and `search` top-level keys.

#### Ignoring Matches

Provide a YAML ignore file via `--ignore-file` to suppress specific matches (before SARIF generation / JSON output). Structure:

```yaml
# Ignore specific advisory IDs everywhere
advisories:
  - GHSA-aaaa-bbbb-cccc

# Ignore by PURL (optional semver/range component after @). If version/range omitted, all versions are ignored.
purls:
  - pkg:npm/lodash               # any version
  - pkg:npm/react@>=18.0.0 <18.3.0

# Scoped ignores (org OR org/repo). Applied only within those scopes.
scoped:
  - scope: my-org
    advisories: [GHSA-1111-2222-3333]
  - scope: my-org/my-repo
    purls:
      - pkg:maven/com.example/app@1.2.3
```

Rules precedence:

1. Scoped repo block
2. Scoped org block
3. Global advisories / purls

The first matching rule suppresses the finding; output logs will show how many were ignored. Ignored items are fully removed from SARIF and JSON/CSV outputs.

##### Ignoring "Unbounded" Malware Advisories

Some malware advisories list a vulnerable version range that effectively covers every possible version of a package (examples: `*`, `>=0`, `0`, `0.0.0`, `>=0.0.0`). These can create low‑signal noise, such as from name-shadowing attacks against a private package.

Use the flag:

```bash
--ignore-unbounded-malware
```

When enabled, any malware match whose `vulnerableVersionRange` normalizes to one of those unbounded patterns is filtered out before JSON / SARIF / CSV output. A summary line (to stderr) reports how many were removed.

Heuristics currently treated as unbounded:

- `*`
- `>= 0`, `> 0`
- `0`, `0.0.0`, `>= 0.0.0`

#### Advisory Date Cutoff

Use `--malware-cutoff` to exclude older advisories from matching. An advisory will be skipped if **both** its `publishedAt` and `updatedAt` timestamps are strictly earlier than the cutoff.

Accepted formats:

- Plain date: `YYYY-MM-DD` (interpreted as `YYYY-MM-DDT00:00:00.000Z`)
- Full ISO timestamp: e.g. `2025-09-29T15:30:00Z`

Examples:

```bash
# Ignore advisories published & last updated entirely before Sept 29 2025
npm run start -- --sbom-cache sboms --malware-cache malware-cache --match-malware --malware-cutoff 2025-09-29

# Using a precise timestamp (keep advisories updated later that day UTC)
npm run start -- --sbom-cache sboms --malware-cache malware-cache --match-malware --malware-cutoff 2025-09-29T12:00:00Z
```

Rationale: This lets you focus on newly introduced / recently changed malware advisories (e.g., during incremental monitoring) without re-reporting older historical matches. Advisories updated after the cutoff remain eligible even if originally published earlier.

### Progress bar & log noise suppression

When collecting a large number of SBOMs you can enable a lightweight progress bar:

```bash
npm run start -- --sync-sboms --org my-org --sbom-cache sboms --progress
```

Secondary rate limit warnings (which can visually disrupt the bar) are automatically silenced.

Behaviour details:

- The bar shows overall completion across all organizations (if using `--enterprise`) once repository counts are enumerated
- Rendering is throttled (~12 fps) to avoid excessive stdout writes
- Standard error messages (e.g., hard failures) still appear
- Suppression only hides the secondary rate-limit informational warnings; primary rate limit retries still log once

To reduce general log noise, you can use either `--quiet` to suppress non-error console output while retaining progress bar, human readable results and machine-readable JSON, or just `--suppress-secondary-rate-limit-logs` to suppress warnings of hitting the rate limits.

### Output modes

JSON only to stdout:

```bash
npm run start -- --sbom-cache sboms --purl pkg:npm/chalk@5.6.1 --json
```

Human + JSON (JSON written to file; stdout remains readable):

```bash
npm run start -- --sbom-cache sboms --purl pkg:npm/chalk@5.6.1 \
  --json --cli --output-file search-results.json
```

If you specify `--cli --json`, you must also supply `--output-file` to avoid corrupted mixed stdout.

Output lines and JSON output append a reason context:

- Search matches: `{query: <original query string>}`
- Malware matches: `{advisory: <GHSA-ID>}`

This makes it clear which input (user query or specific advisory) caused each result.

#### SARIF Output & Code Scanning Upload

Generate SARIF 2.1.0 files (one per repository with matches) for malware matches:

```bash
npm run start -- --sbom-cache sboms --malware-cache malware-cache --match-malware --sarif-dir sarif-out
```

Each file is named `<owner>_<repo>.sarif` and contains rules (one per advisory GHSA) and results (one per matched package).

Upload those SARIF files to GitHub Code Scanning (creates alerts in each affected repository):

```bash
npm run start -- --sbom-cache sboms --malware-cache malware-cache \
  --match-malware --sarif-dir sarif-out --upload-sarif --token $GITHUB_TOKEN
```

Notes:

- `--upload-sarif` requires `--sarif-dir` and `--match-malware`
- A token with appropriate repo/org scope and access is required for uploads
- The tool attempts to resolve the default branch commit SHA for each repo; if it cannot, that repo's upload is skipped
- SARIF upload merges are handled by GitHub; repeated uploads for the same commit replace earlier results for the same tool

### Self-signed / Internal Certificates

If your GitHub Enterprise Server instance or a TLS-intercepting proxy uses a self‑signed or private CA certificate, supply a PEM bundle so REST (Octokit), GraphQL advisory sync, and SARIF uploads trust it:

```bash
npm run start -- --sync-sboms --enterprise ent \
  --base-url https://ghe.internal/api/v3 \
  --ca-bundle /path/to/internal-ca.pem \
  --sbom-cache sboms --token $GITHUB_TOKEN
```

The PEM file may contain multiple concatenated certs. If it cannot be read, a warning is emitted and the system default trust store is used.

### Interactive mode

Enter an interactive prompt (arrow key history, Ctrl+C handling) after initial collection/load:

```bash
npm run start -- --sbom-cache sboms --interactive
```

Then type one PURL query per line. Entering a blank line or using Ctrl+C on a blank line exits. Ctrl+C on a non-blank line clears the line.

## Argument Reference

| Arg | Purpose |
|------|---------|
| `--sbom-cache <dir>` | Directory holding per-repo SBOM JSON files (required for offline mode; used as write target when syncing) |
| `--sync-sboms` | Perform API calls to (re)collect SBOMs; without it the CLI runs offline loading cached SBOMs. Requires a GitHub token |
| `--enterprise <slug>` / `--org <login>` | Scope selection (mutually exclusive when syncing) |
| `--purl <purl>` | Add a PURL/range/wildcard query (repeatable) |
| `--purl-file <file>` | File with one query per line |
| `--json` | Emit search JSON to stdout (unless overridden by `--output-file`) |
| `--cli` | Also emit human-readable output when producing JSON (requires `--output-file`) |
| `--output-file <file>` | Write search JSON payload to file; required when using both `--json` and `--cli` |
| `--interactive` | Enter interactive search prompt after initial processing |
| `--sync-malware` | Fetch & cache malware advisories (MALWARE classification). Requires a GitHub token |
| `--match-malware` | Match current SBOM set against cached advisories |
| `--malware-cache <dir>` | Advisory cache directory (required with malware operations) |
| `--malware-cutoff <ISO-date>` | Ignore advisories whose publishedAt AND updatedAt are both before this date/time (e.g. `2025-09-29` or full timestamp) |
| `--ignore-file <path>` | YAML ignore file (advisories / purls / scoped blocks) to filter malware matches before output |
| `--ignore-unbounded-malware` | Ignore matches whose advisory vulnerable version range covers all versions (e.g. `*`, `>=0`, `0.0.0`) |
| `--sarif-dir <dir>` | Write SARIF 2.1.0 files per repository (with malware matches) |
| `--upload-sarif` | Upload generated SARIF to Code Scanning (requires --match-malware & --sarif-dir and a GitHub token) |
| `--concurrency <n>` | Parallel SBOM fetches (default 5) |
| `--sbom-delay <ms>` | Delay between SBOM fetch (dependency-graph/sbom) requests (default 5000) |
| `--light-delay <ms>` | Delay between lightweight metadata calls (listing repos, commit head checks) (default 500) |
| `--base-url <url>` | GitHub Enterprise Server REST base URL (ends with /api/v3) |
| `--progress` | Show a dynamic progress bar during SBOM collection |
| `--suppress-secondary-rate-limit-logs` | Hide secondary rate limit warning lines (automatically applied with `--progress`) |
| `--quiet` | Suppress all non-error and non-result output (progress bar, JSON and human readable output still show) |
| `--ca-bundle <path>` | Path to a PEM file containing one or more additional CA certificates (self‑signed / internal PKI) |

## Build & test

## 🏗️ Build

```bash
npm install
npm run build
```

## 🧪 Test

The repo ships with a minimal test fixture to validate end-to-end malware matching without making network calls.

1. Build the project:

```bash
npm install
npm run build
```

2. Run the test harness script:

```bash
node dist/test-fixture-match.js
```

You should see output similar to:

```text
Matches:
chalk-org/chalk-repo => pkg:npm/chalk@5.6.1 matched advisory GHSA-test-chalk-561 range =5.6.1
```

Alternatively, you can exercise the CLI purely offline using the fixtures (no token required):

```bash
npm run start -- --sbom-cache fixtures/sboms --malware-cache fixtures/malware-cache --match-malware
```

## 🚦 Rate Limiting

Standard & secondary rate limits trigger an automatic retry (up to 2 times).

You can tune concurrency and increase the delay to reduce the chance of hitting rate limits.

Each time a secondary rate limit is hit, the delay between fetching SBOMs is increased by 10%, to provide a way to adaptively respond to that rate limit.

## Limitations & future work

- Only malware advisories are synchronised from the GitHub Advisory Database, by design
  - future work could allow synchronising from other compatible vulnerability databases to match additional ecosystems to those in the GHADB
- Semver matching is used for all ecosystems, which may not work correctly
- There is no continuous running mode - it runs as a one-off at the command line
  - future work could allow running in a Docker container in this manner 

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 🆘 Support

> [!NOTE]
> This is an _unofficial_ tool created by Field Security Specialists, and is not officially supported by GitHub.

See [SUPPORT.md](SUPPORT.md) for support options.

## 📜 Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for our Code of Conduct.

## 🛡️ Privacy

See [PRIVACY.md](PRIVACY.md) for the privacy notice.
