import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { IgnoreMatcher } from "./ignore.js";
import type { MalwareMatch } from "./malwareMatcher.js";

function makeMatch(overrides: Partial<MalwareMatch> = {}): MalwareMatch {
  return {
    repo: "my-org/my-repo",
    purl: "pkg:npm/lodash@4.17.21",
    packageName: "lodash",
    ecosystem: "NPM",
    version: "4.17.21",
    advisoryGhsaId: "GHSA-1111-2222-3333",
    advisoryPermalink: "https://github.com/advisories/GHSA-1111-2222-3333",
    vulnerableVersionRange: "=4.17.21",
    advisoryUpdatedAt: new Date().toISOString(),
    reason: "GHSA-1111-2222-3333",
    ...overrides
  };
}

function writeIgnoreFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ignore-test-"));
  const filePath = path.join(dir, "ignore.yml");
  fs.writeFileSync(filePath, contents, "utf8");
  return filePath;
}

test("IgnoreMatcher.load returns undefined when the file does not exist", () => {
  const matcher = IgnoreMatcher.load(path.join(os.tmpdir(), "does-not-exist-ignore.yml"));
  assert.equal(matcher, undefined);
});

test("global advisory ignore suppresses matches regardless of package", () => {
  const filePath = writeIgnoreFile(`advisories:\n  - GHSA-1111-2222-3333\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  const result = matcher.shouldIgnore(makeMatch());
  assert.equal(result.ignored, true);
  assert.equal(result.reason, "advisory:GHSA-1111-2222-3333");
});

test("global purl ignore without version constraint matches any version", () => {
  const filePath = writeIgnoreFile(`purls:\n  - pkg:npm/lodash\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  assert.equal(matcher.shouldIgnore(makeMatch({ purl: "pkg:npm/lodash@1.0.0" })).ignored, true);
  assert.equal(matcher.shouldIgnore(makeMatch({ purl: "pkg:npm/other@1.0.0", packageName: "other" })).ignored, false);
});

test("global purl ignore with a semver range only matches versions in range", () => {
  const filePath = writeIgnoreFile(`purls:\n  - "pkg:npm/react@>=18.0.0 <18.3.0"\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  const inRange = makeMatch({ purl: "pkg:npm/react@18.2.0", packageName: "react", version: "18.2.0" });
  const outOfRange = makeMatch({ purl: "pkg:npm/react@18.3.0", packageName: "react", version: "18.3.0" });
  assert.equal(matcher.shouldIgnore(inRange).ignored, true);
  assert.equal(matcher.shouldIgnore(outOfRange).ignored, false);
});

test("scoped ignore only applies within the declared repo", () => {
  const filePath = writeIgnoreFile(`scoped:\n  - scope: my-org/my-repo\n    advisories: [GHSA-1111-2222-3333]\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  assert.equal(matcher.shouldIgnore(makeMatch({ repo: "my-org/my-repo" })).ignored, true);
  assert.equal(matcher.shouldIgnore(makeMatch({ repo: "my-org/other-repo" })).ignored, false);
});

test("scoped ignore for an org applies to all repos in that org", () => {
  const filePath = writeIgnoreFile(`scoped:\n  - scope: my-org\n    advisories: [GHSA-1111-2222-3333]\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  assert.equal(matcher.shouldIgnore(makeMatch({ repo: "my-org/any-repo" })).ignored, true);
  assert.equal(matcher.shouldIgnore(makeMatch({ repo: "other-org/any-repo" })).ignored, false);
});

test("filter partitions matches into kept and ignored with a reason attached", () => {
  const filePath = writeIgnoreFile(`advisories:\n  - GHSA-1111-2222-3333\n`);
  const matcher = IgnoreMatcher.load(filePath);
  assert.ok(matcher);
  const kept = makeMatch({ advisoryGhsaId: "GHSA-9999-9999-9999" });
  const ignored = makeMatch();
  const result = matcher.filter([kept, ignored]);
  assert.equal(result.kept.length, 1);
  assert.equal(result.ignored.length, 1);
  assert.equal(result.kept[0].advisoryGhsaId, "GHSA-9999-9999-9999");
  assert.equal(result.ignored[0].ignoreReason, "advisory:GHSA-1111-2222-3333");
});
