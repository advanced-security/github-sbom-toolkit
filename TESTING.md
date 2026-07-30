# Testing

This project uses Node's built-in test runner ([`node:test`](https://nodejs.org/api/test.html)), so no extra test framework dependency is required.

## Running the tests

```bash
npm install
npm test
```

`npm test` builds the project (via the `pretest` script) and then runs every compiled `*.test.js` file under `dist/` with `node --test`.

To run the TypeScript test files directly without a full build (useful while iterating), use `tsx`:

```bash
npx tsx --test src/**/*.test.ts
```

## Test layout

Test files live next to the code they exercise and are named `*.test.ts`:

| File | Covers |
| --- | --- |
| `src/malwareMatcher.test.ts` | Matching SBOM packages against malware advisories (incl. branch diffs, date cutoffs) and SARIF generation |
| `src/ignore.test.ts` | The YAML ignore-file matcher (`IgnoreMatcher`): global/scoped advisory and PURL ignores |
| `src/serialization.test.ts` | Reading/writing cached SBOMs, including the flattened layout and `branchDiffs` Map (de)serialization |
| `src/sbomCollector.test.ts` | End-to-end offline collection and PURL search, including dependency review branch diffs |

Tests use the fixtures in [`fixtures/`](fixtures) (a sample SBOM and a malware advisory cache) so they run entirely offline, with no GitHub token or network access required.

## Adding tests

* Prefer pure, offline-testable logic (parsing, matching, serialization) over code that talks to the GitHub API.
* Use `node:assert/strict` for assertions and `node:test`'s `test()` function; see the existing `*.test.ts` files for examples.
* Write any temporary files under a fresh `fs.mkdtempSync` directory (or `tmp-*` directory) and clean it up in a `finally` block, so tests don't leave state behind or interfere with each other.

## Continuous Integration

Every push and pull request to `main` runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml), which installs dependencies, builds the project, and runs the test suite across the Node.js versions listed in `engines` in `package.json`. This includes Dependabot pull requests, so a dependency update that breaks the build or tests will be caught before merging.
