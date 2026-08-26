# Testing

All tests run offline against the fixtures in `fixtures/`, so no GitHub token or network access is required.

## Running the tests

```bash
npm install
npm run build
npm test
```

`npm test` runs against the compiled output in `dist/`, so `npm run build` must be run first (or again, after changing anything in `src/`).

The same three steps run in CI (`.github/workflows/ci.yml`) on every push to `main` and on every pull request.

## What is covered

`npm test` runs two kinds of test:

### Unit tests

Node's built-in test runner (`node --test`) runs the `src/*.test.ts` files, so no test framework dependency is needed:

| File | Covers |
| ---- | ------ |
| `src/fixtures.test.ts` | Loading the SBOM and malware advisory fixtures, branch diff revival, malware matching (including the advisory date cutoff), the `ignore.example.yml` ignore file, and PURL search (exact, semver range and wildcard queries) |
| `src/cli.test.ts` | Running the built CLI offline against the fixtures, as documented in the [README](README.md): malware matching, JSON search output, and the no-match case |

### Fixture harness scripts

These are also runnable on their own, and print their results for inspection:

| Script | Covers |
| ------ | ------ |
| `node dist/test-fixture-match.js` | End-to-end malware matching against `fixtures/` |
| `node dist/test-branch-search.js` | PURL search over a synthetic repository SBOM with branch dependency diffs |

## Adding tests

Add a new `src/<name>.test.ts` file using `node:test` and `node:assert/strict`, then add the compiled path (`dist/<name>.test.js`) to the `test` script in `package.json`. Test files are listed explicitly rather than globbed so the runner behaves the same on every supported Node version and platform.

## Fixtures

| Fixture | Contents |
| ------- | -------- |
| `fixtures/sboms/advanced-security/test-sbom-repo/sbom.json` | An SPDX SBOM with `chalk@5.6.1` and `left-pad@1.3.0`, plus a dependency review diff adding `chalk@5.6.1` on a `test` branch |
| `fixtures/malware-cache/malware-advisories.json` | A single fake malware advisory, `GHSA-test-chalk-561`, covering npm `chalk` version `=5.6.1` |

Matching these two fixtures produces two matches: one on the default branch and one on the `test` branch.

## End-to-end testing

Unit tests do not cover the GitHub API paths. Before submitting changes that touch collection, sync or upload, also run the CLI against a test organization and Enterprise and check the results are as expected, as described in [CONTRIBUTING.md](CONTRIBUTING.md).
