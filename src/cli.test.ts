import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

// Tests run from the compiled output in `dist`, so the repository root is one level up
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const cli = fileURLToPath(new URL("./cli.js", import.meta.url));

const FIXTURE_REPO = "advanced-security/test-sbom-repo";

/** Run the built CLI offline against the fixtures, from the repository root */
function runCli(args: string[]) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    // No token is provided: these invocations must work entirely offline
    env: { ...process.env, GITHUB_TOKEN: "", GH_TOKEN: "" }
  });
  assert.equal(result.status, 0, `CLI exited with ${result.status}\n${result.stderr}`);
  return result;
}

describe("CLI against the fixtures", () => {
  it("matches malware advisories offline, as documented in the README", () => {
    const { stdout } = runCli([
      "--sbom-cache", path.join("fixtures", "sboms"),
      "--malware-cache", path.join("fixtures", "malware-cache"),
      "--match-malware"
    ]);
    const matchLines = stdout.split("\n").filter(line => line.includes("GHSA-test-chalk-561"));
    assert.equal(matchLines.length, 2);
    assert.match(matchLines[0], /^advanced-security\/test-sbom-repo :: pkg:npm\/chalk@5\.6\.1 => GHSA-test-chalk-561 \(=5\.6\.1\)/);
    assert.match(matchLines[1], /\[branch: test\]/);
  });

  it("searches by PURL and emits JSON", () => {
    const { stdout } = runCli([
      "--sbom-cache", path.join("fixtures", "sboms"),
      "--purl", "pkg:npm/chalk@5.6.1",
      "--json"
    ]);
    const payload = JSON.parse(stdout) as { search: { repo: string; matches: { purl: string; reason: string }[] }[] };
    assert.equal(payload.search.length, 1);
    assert.equal(payload.search[0].repo, FIXTURE_REPO);
    assert.deepEqual(payload.search[0].matches.map(m => m.purl), ["pkg:npm/chalk@5.6.1", "pkg:npm/chalk@5.6.1@test"]);
  });

  it("reports no matches for a package that is not in the SBOM", () => {
    const { stdout } = runCli([
      "--sbom-cache", path.join("fixtures", "sboms"),
      "--purl", "pkg:npm/not-in-the-sbom@1.0.0"
    ]);
    assert.match(stdout, /No matches\./);
  });
});
