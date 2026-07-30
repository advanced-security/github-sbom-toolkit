import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { writeAll, writeOne, readAll } from "./serialization.js";
import type { RepositorySbom } from "./types.js";

function makeSbom(overrides: Partial<RepositorySbom> = {}): RepositorySbom {
  return {
    repo: "my-org/my-repo",
    org: "my-org",
    retrievedAt: new Date().toISOString(),
    packages: [{ name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21" }],
    ...overrides
  };
}

test("writeAll/readAll roundtrip preserves packages in the default hierarchical layout", () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "serialization-test-"));
  try {
    const sbom = makeSbom();
    writeAll([sbom], { outDir });

    assert.ok(fs.existsSync(path.join(outDir, "my-org/my-repo/sbom.json")));

    const readBack = readAll(outDir);
    assert.equal(readBack.length, 1);
    assert.equal(readBack[0].repo, "my-org/my-repo");
    assert.equal(readBack[0].packages[0].purl, "pkg:npm/lodash@4.17.21");
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("writeAll/readAll roundtrip works with the flattened layout", () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "serialization-flat-test-"));
  try {
    const sbom = makeSbom({ repo: "my-org/my-repo" });
    writeAll([sbom], { outDir, flatten: true });

    assert.ok(fs.existsSync(path.join(outDir, "my-org-my-repo.json")));

    const readBack = readAll(outDir, { flatten: true });
    assert.equal(readBack.length, 1);
    assert.equal(readBack[0].repo, "my-org/my-repo");
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("readAll ignores malformed JSON files when logParseErrors is not set", () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "serialization-malformed-test-"));
  try {
    const repoDir = path.join(outDir, "my-org", "broken-repo");
    fs.mkdirSync(repoDir, { recursive: true });
    fs.writeFileSync(path.join(repoDir, "sbom.json"), "{ not valid json", "utf8");

    const readBack = readAll(outDir);
    assert.equal(readBack.length, 0);
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test("readAll throws when the directory does not exist", () => {
  assert.throws(() => readAll(path.join(os.tmpdir(), "does-not-exist-dir-xyz")));
});

test("branchDiffs are converted between Map and array form across a write/read roundtrip", () => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "serialization-branchdiffs-test-"));
  try {
    const branchDiffs = new Map();
    branchDiffs.set("feature-x", {
      base: "main",
      head: "feature-x",
      retrievedAt: new Date().toISOString(),
      changes: [{ changeType: "added", name: "lodash", ecosystem: "npm", version: "4.17.21" }]
    });
    const sbom = makeSbom({ branchDiffs });

    writeOne(sbom, { outDir });
    const raw = JSON.parse(fs.readFileSync(path.join(outDir, "my-org/my-repo/sbom.json"), "utf8"));
    assert.ok(Array.isArray(raw.branchDiffs), "branchDiffs should be serialized as an array");

    const [readBack] = readAll(outDir);
    assert.ok(readBack.branchDiffs instanceof Map, "branchDiffs should be revived as a Map");
    assert.equal(readBack.branchDiffs?.get("feature-x")?.head, "feature-x");
  } finally {
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});
