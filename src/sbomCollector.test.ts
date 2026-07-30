import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import { SbomCollector } from "./sbomCollector.js";

// This test harness validates that branch SBOMs and dependency review diffs
// participate in search results. It constructs a synthetic repo SBOM object,
// writes it to a temp cache directory, then performs searches.

async function buildCollector(tempRoot: string): Promise<{ org: string; repo: string; collector: SbomCollector }> {
  const org = "example-org";
  const repo = "demo-repo";
  const repoDir = path.join(tempRoot, org, repo);
  fs.rmSync(tempRoot, { recursive: true, force: true });
  fs.mkdirSync(repoDir, { recursive: true });

  const basePackages = [
    { name: "chalk", version: "5.6.1", purl: "pkg:npm/chalk@5.6.1" },
    { name: "react", version: "18.2.0", purl: "pkg:npm/react@18.2.0" }
  ];
  const diffChanges = [
    { changeType: "added", name: "lodash", ecosystem: "npm", purl: "pkg:npm/lodash@4.17.21", version: "4.17.21" },
    { changeType: "updated", name: "react", ecosystem: "npm", purl: "pkg:npm/react@18.3.0", version: "18.3.0" },
    { changeType: "removed", name: "chalk", ecosystem: "npm", purl: "pkg:npm/chalk@5.6.1", version: "5.6.1" },
    { changeType: "removed", name: "react", ecosystem: "npm", purl: "pkg:npm/react@18.2.0", version: "18.2.0" }
  ];

  const synthetic = {
    repo: `${org}/${repo}`,
    org: org,
    retrievedAt: new Date().toISOString(),
    packages: basePackages,
    branchDiffs: [
      {
        latestCommitDate: new Date().toISOString(),
        base: "main",
        head: "feature-x",
        retrievedAt: new Date().toISOString(),
        changes: diffChanges
      }
    ]
  };

  fs.writeFileSync(path.join(repoDir, "sbom.json"), JSON.stringify(synthetic, null, 2), "utf8");

  const collector = new SbomCollector({
    token: undefined,
    org,
    loadFromDir: tempRoot,
    syncSboms: false,
    quiet: true
  });
  await collector.collect();

  return { org, repo, collector };
}

test("SbomCollector search includes both base packages and branch diff changes", async () => {
  const tempRoot = path.join(process.cwd(), "tmp-branch-search-cache");
  try {
    const { org, repo, collector } = await buildCollector(tempRoot);

    const queries = [
      "pkg:npm/react@>=18.2.0 <19.0.0", // should match base & branch updated version
      "pkg:npm/lodash@4.17.21",          // should match added in branch diff
      "pkg:npm/chalk@5.6.1"              // base only
    ];

    const results = collector.searchByPurlsWithReasons(queries);
    assert.ok(results.size > 0, "expected search results from branch data");

    const entries = results.get(`${org}/${repo}`);
    assert.ok(entries, "expected entries for the synthetic repo");
    assert.ok(entries.length >= 4, `expected at least 4 matches, got ${entries?.length}`);

    const purls = entries.map(e => e.purl);
    assert.ok(purls.includes("pkg:npm/chalk@5.6.1"));
    assert.ok(purls.includes("pkg:npm/react@18.2.0"));
    assert.ok(purls.some(p => p.startsWith("pkg:npm/lodash@4.17.21")));
    assert.ok(purls.some(p => p.startsWith("pkg:npm/react@18.3.0")));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
