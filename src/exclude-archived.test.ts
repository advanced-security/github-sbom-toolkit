import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createServer, type Server } from "node:http";

import { SbomCollector } from "./sbomCollector.js";

const repositories = [
  { name: "active-repo", archived: false },
  { name: "archived-repo", archived: true }
];
let server: Server;
let baseUrl: string;
let sbomRequests: string[] = [];

before(async () => {
  server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", baseUrl);
    if (requestUrl.pathname === "/api/v3/orgs/example-org/repos") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(repositories));
      return;
    }

    const sbomMatch = requestUrl.pathname.match(/^\/api\/v3\/repos\/example-org\/([^/]+)\/dependency-graph\/sbom$/);
    if (sbomMatch) {
      sbomRequests.push(sbomMatch[1]);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ sbom: { packages: [] } }));
      return;
    }

    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ message: `Unexpected request: ${requestUrl.pathname}` }));
  });

  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected local mock server address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
});

async function collect(excludeArchived: boolean) {
  sbomRequests = [];
  const collector = new SbomCollector({
    token: "test-token",
    baseUrl,
    org: "example-org",
    syncSboms: true,
    quiet: true,
    lightDelayMs: 0,
    delayMsBetweenRepos: 0,
    excludeArchived
  });

  const sboms = await collector.collect();
  return { sboms, summary: collector.getSummary(), sbomRequests: [...sbomRequests] };
}

describe("exclude archived repositories", () => {
  it("collects archived repositories by default", async () => {
    const result = await collect(false);

    assert.equal(result.summary.repositoryCount, 2);
    assert.deepEqual(result.sbomRequests.sort(), ["active-repo", "archived-repo"]);
    assert.deepEqual(result.sboms.map(sbom => sbom.repo).sort(), [
      "example-org/active-repo",
      "example-org/archived-repo"
    ]);
  });

  it("skips archived repositories when enabled", async () => {
    const result = await collect(true);

    assert.equal(result.summary.repositoryCount, 1);
    assert.deepEqual(result.sbomRequests, ["active-repo"]);
    assert.deepEqual(result.sboms.map(sbom => sbom.repo), ["example-org/active-repo"]);
  });
});
