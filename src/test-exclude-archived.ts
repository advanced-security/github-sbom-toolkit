import { SbomCollector } from "./sbomCollector.js";

type RequestArgs = { org?: string; owner?: string; repo?: string; per_page?: number; page?: number };

function makeMockOctokit() {
  return {
    async request(route: string, _args: RequestArgs) {
      if (route === "GET /orgs/{org}/repos") {
        return {
          data: [
            { name: "active-repo", archived: false, default_branch: "main", pushed_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
            { name: "archived-repo", archived: true, default_branch: "main", pushed_at: "2025-01-01T00:00:00Z", updated_at: "2025-01-01T00:00:00Z" }
          ]
        };
      }
      if (route === "GET /repos/{owner}/{repo}/dependency-graph/sbom") {
        return {
          data: {
            sbom: {
              packages: [
                { name: "chalk", version: "5.6.1", purl: "pkg:npm/chalk@5.6.1" }
              ]
            }
          },
          headers: {}
        };
      }
      throw new Error(`Unexpected route in test mock: ${route}`);
    }
  };
}

async function collectWithExcludeArchived(excludeArchived: boolean) {
  const collector = new SbomCollector({
    token: undefined,
    org: "example-org",
    syncSboms: true,
    quiet: true,
    lightDelayMs: 0,
    delayMsBetweenRepos: 0,
    excludeArchived
  });

  (collector as unknown as { octokit: ReturnType<typeof makeMockOctokit> }).octokit = makeMockOctokit();
  const sboms = await collector.collect();
  return { sboms, summary: collector.getSummary() };
}

async function main() {
  const included = await collectWithExcludeArchived(false);
  const excluded = await collectWithExcludeArchived(true);

  if (included.summary.repositoryCount !== 2) {
    console.error(`Expected repositoryCount=2 without exclude flag, got ${included.summary.repositoryCount}`);
    process.exit(1);
  }
  if (included.sboms.length !== 2) {
    console.error(`Expected 2 SBOM results without exclude flag, got ${included.sboms.length}`);
    process.exit(1);
  }

  if (excluded.summary.repositoryCount !== 1) {
    console.error(`Expected repositoryCount=1 with exclude flag, got ${excluded.summary.repositoryCount}`);
    process.exit(1);
  }
  if (excluded.sboms.length !== 1) {
    console.error(`Expected 1 SBOM result with exclude flag, got ${excluded.sboms.length}`);
    process.exit(1);
  }
  if (excluded.sboms[0]?.repo !== "example-org/active-repo") {
    console.error(`Expected only active repo in results, got ${excluded.sboms.map(s => s.repo).join(", ")}`);
    process.exit(1);
  }

  process.stdout.write("Exclude archived test passed.\n");
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
