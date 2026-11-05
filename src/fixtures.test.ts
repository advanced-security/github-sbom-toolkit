import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { IgnoreMatcher } from "./ignore.js";
import { MalwareAdvisoryNode, MalwareAdvisorySync } from "./malwareAdvisories.js";
import { matchMalware } from "./malwareMatcher.js";
import { SbomCollector } from "./sbomCollector.js";
import { readAll } from "./serialization.js";
import { RepositorySbom } from "./types.js";

// Tests run from the compiled output in `dist`, so the repository root is one level up
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const sbomFixtureDir = path.join(repoRoot, "fixtures", "sboms");
const malwareFixtureDir = path.join(repoRoot, "fixtures", "malware-cache");

const FIXTURE_REPO = "advanced-security/test-sbom-repo";
const FIXTURE_GHSA = "GHSA-test-chalk-561";

/** Load the advisory cache the same way the CLI does (offline, no token required) */
function loadFixtureAdvisories(): MalwareAdvisoryNode[] {
  return new MalwareAdvisorySync({ token: "", cacheDir: malwareFixtureDir, quiet: true }).getAdvisories();
}

function fixtureMatches() {
  return matchMalware(loadFixtureAdvisories(), readAll(sbomFixtureDir));
}

describe("SBOM fixture", () => {
  it("loads the shipped SBOM from the fixture cache", () => {
    const sboms = readAll(sbomFixtureDir);
    assert.equal(sboms.length, 1);
    assert.equal(sboms[0].repo, FIXTURE_REPO);
    assert.equal(sboms[0].org, "advanced-security");
    assert.deepEqual(sboms[0].packages.map(p => p.name).sort(), ["chalk", "left-pad"]);
  });

  it("revives branch diffs as a Map keyed by head branch", () => {
    const diffs = readAll(sbomFixtureDir)[0].branchDiffs;
    if (!(diffs instanceof Map)) throw new Error("branchDiffs should be revived as a Map");
    const diff = diffs.get("test");
    if (!diff) throw new Error("expected a diff for the 'test' branch");
    assert.equal(diff.base, "main");
    assert.deepEqual(diff.changes.map(c => `${c.changeType}:${c.packageURL}`), ["added:pkg:npm/chalk@5.6.1"]);
  });
});

describe("malware advisory fixture", () => {
  it("loads the shipped advisory from the fixture cache", () => {
    const advisories = loadFixtureAdvisories();
    assert.equal(advisories.length, 1);
    assert.equal(advisories[0].ghsaId, FIXTURE_GHSA);
    assert.deepEqual(
      advisories[0].vulnerabilities.map(v => `${v.ecosystem}:${v.name}:${v.vulnerableVersionRange}`),
      ["NPM:chalk:=5.6.1"]
    );
  });
});

describe("malware matching", () => {
  it("matches chalk 5.6.1 on the default branch and on the 'test' branch", () => {
    const matches = fixtureMatches();
    assert.equal(matches.length, 2);
    for (const match of matches) {
      assert.equal(match.repo, FIXTURE_REPO);
      assert.equal(match.purl, "pkg:npm/chalk@5.6.1");
      assert.equal(match.advisoryGhsaId, FIXTURE_GHSA);
      assert.equal(match.vulnerableVersionRange, "=5.6.1");
    }
    assert.deepEqual(matches.map(m => m.branch), [undefined, "test"]);
  });

  it("does not match a package outside the vulnerable version range", () => {
    const sboms: RepositorySbom[] = [{
      repo: FIXTURE_REPO,
      org: "advanced-security",
      retrievedAt: new Date().toISOString(),
      packages: [{ name: "chalk", version: "5.6.2", purl: "pkg:npm/chalk@5.6.2" }]
    }];
    assert.deepEqual(matchMalware(loadFixtureAdvisories(), sboms), []);
  });

  it("honours the advisory date cutoff", () => {
    const advisories = loadFixtureAdvisories();
    const sboms = readAll(sbomFixtureDir);
    // The fixture advisory was both published and updated on 2025-09-29
    assert.equal(matchMalware(advisories, sboms, { advisoryDateCutoff: "2025-09-29" }).length, 2);
    assert.equal(matchMalware(advisories, sboms, { advisoryDateCutoff: "2025-09-30" }).length, 0);
  });
});

describe("ignore file", () => {
  it("parses the shipped ignore.example.yml", () => {
    const matcher = IgnoreMatcher.load("ignore.example.yml", { cwd: repoRoot });
    if (!matcher) throw new Error("expected ignore.example.yml to parse");
    // The example file does not reference the fixture advisory, so nothing is filtered out
    const { kept, ignored } = matcher.filter(fixtureMatches());
    assert.equal(kept.length, 2);
    assert.equal(ignored.length, 0);
  });

  it("filters matches for an ignored advisory", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-toolkit-ignore-"));
    try {
      const ignoreFile = path.join(dir, "ignore.yml");
      fs.writeFileSync(ignoreFile, `advisories:\n  - ${FIXTURE_GHSA}\n`, "utf8");
      const matcher = IgnoreMatcher.load(ignoreFile);
      if (!matcher) throw new Error("expected the ignore file to parse");
      const { kept, ignored } = matcher.filter(fixtureMatches());
      assert.equal(kept.length, 0);
      assert.equal(ignored.length, 2);
      assert.deepEqual(new Set(ignored.map(i => i.ignoreReason)), new Set([`advisory:${FIXTURE_GHSA}`]));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("PURL search", () => {
  let collector: SbomCollector;

  before(async () => {
    collector = new SbomCollector({ token: undefined, loadFromDir: sbomFixtureDir, syncSboms: false, quiet: true });
    await collector.collect();
  });

  it("loads the fixture SBOM offline", () => {
    assert.deepEqual(collector.getAllSboms().map(s => s.repo), [FIXTURE_REPO]);
  });

  it("matches an exact PURL on the default branch and on branch diffs", () => {
    const results = collector.searchByPurlsWithReasons(["pkg:npm/chalk@5.6.1"]);
    assert.deepEqual(results.get(FIXTURE_REPO)?.map(e => e.purl), ["pkg:npm/chalk@5.6.1", "pkg:npm/chalk@5.6.1@test"]);
  });

  it("matches a semver range, adding the 'pkg:' prefix when it is omitted", () => {
    const entries = collector.searchByPurlsWithReasons(["npm/chalk@>=5.0.0 <6.0.0"]).get(FIXTURE_REPO);
    assert.deepEqual(entries?.map(e => e.purl), ["pkg:npm/chalk@5.6.1", "pkg:npm/chalk@5.6.1@test"]);
    assert.deepEqual(new Set(entries?.map(e => e.reason)), new Set(["pkg:npm/chalk@>=5.0.0 <6.0.0"]));
  });

  it("matches a wildcard query", () => {
    const results = collector.searchByPurlsWithReasons(["pkg:npm/left-pad@*"]);
    assert.deepEqual(results.get(FIXTURE_REPO)?.map(e => e.purl), ["pkg:npm/left-pad@1.3.0"]);
  });

  it("returns no results for a package that is not in the SBOM", () => {
    assert.equal(collector.searchByPurlsWithReasons(["pkg:npm/not-in-the-sbom@1.0.0"]).size, 0);
  });
});
