import assert from "node:assert/strict";
import { test, type TestContext } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createOctokit } from "./octokit.js";
import { fetchRepositorySbom } from "./sbomFetch.js";
import { SbomCollector } from "./sbomCollector.js";
import { writeAll } from "./serialization.js";

const api = "https://api.github.com";
const reportPath = "/repos/example/demo/dependency-graph/sbom/fetch-report/job-123";
const downloadUrl = "https://downloads.example/report?signature=temporary";
const document = {
  spdxVersion: "SPDX-2.3",
  SPDXID: "SPDXRef-DOCUMENT",
  name: "example/demo",
  packages: [{
    name: "chalk",
    versionInfo: "5.6.1",
    externalRefs: [{ referenceType: "purl", referenceLocator: "pkg:npm/chalk@5.6.1" }]
  }]
};
const fast = { pollIntervalMs: 1, timeoutMs: 2_000 };

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

function generated(base = api) {
  return json({ sbom_url: `${base}${reportPath}` }, 201);
}

function ready(location = downloadUrl) {
  return new Response(null, { status: 302, headers: { location } });
}

function network(t: TestContext, responses: Response[]) {
  const calls: { url: string; init?: RequestInit }[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    const response = responses.shift();
    assert.ok(response, `Unexpected request: ${input}`);
    return response;
  });
  return calls;
}

function client(baseUrl?: string) {
  return createOctokit({ token: "test-token", baseUrl });
}

test("generates, polls 202, manually follows 302 and downloads raw SPDX without credentials", async t => {
  const calls = network(t, [
    generated(),
    new Response(null, { status: 202 }),
    ready(),
    new Response(JSON.stringify(document), { headers: { "content-type": "application/octet-stream", etag: '"download"' } })
  ]);
  const result = await fetchRepositorySbom(client(), "example", "demo", fast);
  assert.deepEqual(result, { sbom: document, etag: '"download"' });
  assert.deepEqual(calls.map(c => c.url), [
    `${api}/repos/example/demo/dependency-graph/sbom/generate-report`,
    `${api}${reportPath}`, `${api}${reportPath}`, downloadUrl
  ]);
  for (const call of calls.slice(0, 3)) {
    assert.equal(new Headers(call.init?.headers).get("authorization"), "token test-token");
    assert.equal(call.init?.redirect, "manual");
  }
  assert.equal(new Headers(calls[3].init?.headers).get("authorization"), null);
  assert.equal(calls[3].init?.credentials, "omit");
});

test("bounds pending polling, including Retry-After beyond the deadline", async t => {
  const calls = network(t, [generated(), new Response(null, { status: 202, headers: { "retry-after": "3600" } })]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", { ...fast, timeoutMs: 100 }), /timed out/);
  assert.equal(calls.length, 2);
});

test("honors Retry-After before polling again", async t => {
  const calls = network(t, [
    generated(), new Response(null, { status: 202, headers: { "retry-after": "1" } }),
    ready(), json(document)
  ]);
  const started = Date.now();
  await fetchRepositorySbom(client(), "example", "demo", { ...fast, timeoutMs: 5_000 });
  assert.ok(Date.now() - started >= 1_000);
  assert.equal(calls.length, 4);
});

test("bounds a stalled generation request and aborts its signal", async t => {
  let signal: AbortSignal | undefined;
  t.mock.method(globalThis, "fetch", (_input: unknown, init?: RequestInit) => {
    signal = init?.signal ?? undefined;
    return new Promise(() => {});
  });
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", { ...fast, timeoutMs: 100 }), /timed out/);
  assert.equal(signal?.aborted, true);
});

test("bounds a stalled download", async t => {
  let requests = 0;
  t.mock.method(globalThis, "fetch", async () => {
    requests++;
    if (requests === 1) return generated();
    if (requests === 2) return ready();
    return new Promise(() => {});
  });
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", { ...fast, timeoutMs: 150 }), /timed out/);
  assert.equal(requests, 3);
});

for (const alreadyAborted of [false, true]) {
  test(`secondary throttle wait cancels ${alreadyAborted ? "with an already-aborted signal" : "when aborted during the wait"}`, async t => {
    const calls = network(t, [
      new Response(JSON.stringify({ message: "You have exceeded a secondary rate limit" }), {
        status: 403,
        headers: { "content-type": "application/json", "retry-after": "1" }
      }),
      json({})
    ]);
    const controller = new AbortController();
    let hit = false;
    const octokit = createOctokit({
      token: "test-token",
      suppressSecondaryRateLimitLogs: true,
      onSecondaryRateLimitHit: () => {
        hit = true;
        if (alreadyAborted) controller.abort();
        else queueMicrotask(() => controller.abort());
      }
    });
    const started = Date.now();
    // Await Octokit's request itself: a surrounding Promise.race would hide a leaked throttle timer.
    await assert.rejects(octokit.request("GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report", {
      owner: "example", repo: "demo", request: { signal: controller.signal, retries: 0 }
    }), /secondary rate limit/);
    assert.ok(hit);
    assert.ok(Date.now() - started < 1_000, "request must settle before the one-second throttle wait completes");
    assert.equal(calls.length, 1, "an aborted request must not be retried");
  });
}

test("secondary throttle wait still retries requests without an AbortSignal", async t => {
  const calls = network(t, [
    new Response(JSON.stringify({ message: "You have exceeded a secondary rate limit" }), {
      status: 403,
      headers: { "content-type": "application/json", "retry-after": "0.01" }
    }),
    generated()
  ]);
  const octokit = createOctokit({ token: "test-token", suppressSecondaryRateLimitLogs: true });
  const response = await octokit.request("GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report", {
    owner: "example", repo: "demo", request: { retries: 0 }
  });
  assert.equal(response.status, 201);
  assert.equal(calls.length, 2);
});

for (const status of [403, 404, 500]) {
  test(`cloud generation HTTP ${status} is surfaced without synchronous fallback`, async t => {
    const calls = network(t, [json({ message: "generation failed" }, status)]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /generation failed/);
    assert.equal(calls.length, 1);
  });
}

for (const response of [
  () => json({}, 201),
  () => json({ sbom_url: "" }, 201),
  () => json({ sbom_url: `${api}${reportPath}` }, 200),
  () => json({ sbom_url: "https://evil.example/steal-token" }, 201),
  () => json({ sbom_url: `${api}/repos/another/repo/dependency-graph/sbom/fetch-report/job` }, 201),
  () => json({ sbom_url: `https://user:pass@api.github.com${reportPath}` }, 201)
]) {
  test("rejects malformed or untrusted generation response before authenticated polling", async t => {
    const calls = network(t, [response()]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /Invalid SBOM/);
    assert.equal(calls.length, 1);
  });
}

for (const status of [200, 201, 204, 301]) {
  test(`unexpected polling HTTP ${status} is an explicit error`, async t => {
    network(t, [generated(), new Response(null, { status })]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /Unexpected SBOM report status/);
  });
}

for (const status of [403, 404]) {
  test(`polling HTTP ${status} is surfaced without synchronous fallback`, async t => {
    const calls = network(t, [generated(), json({ message: "report not available" }, status)]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /report not available/);
    assert.equal(calls.length, 2);
  });
}

test("rejects missing report Location", async t => {
  network(t, [generated(), new Response(null, { status: 302 })]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /missing Location/);
});

for (const location of ["http://downloads.example/report", "https://user:pass@downloads.example/report"]) {
  test("rejects unsafe download locations", async t => {
    const calls = network(t, [generated(), ready(location)]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /Invalid SBOM download URL/);
    assert.equal(calls.length, 2);
  });
}

test("all download redirect hops remain credential-free", async t => {
  const calls = network(t, [generated(), ready(), ready("https://cdn.example/report"), json({ sbom: document })]);
  assert.deepEqual((await fetchRepositorySbom(client(), "example", "demo", fast)).sbom, document);
  for (const call of calls.slice(2)) {
    assert.equal(new Headers(call.init?.headers).get("authorization"), null);
    assert.equal(call.init?.redirect, "manual");
    assert.equal(call.init?.credentials, "omit");
  }
});

test("rejects insecure download redirect hops", async t => {
  const calls = network(t, [generated(), ready(), ready("http://cdn.example/report")]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /Invalid SBOM download URL/);
  assert.equal(calls.length, 3);
});

test("bounds download redirect loops", async t => {
  const calls = network(t, [generated(), ready(), ...Array.from({ length: 6 }, () => ready())]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /exceeded 5 redirects/);
  assert.equal(calls.length, 8);
});

test("download HTTP errors do not expose signed URLs", async t => {
  network(t, [generated(), ready(), new Response("expired", { status: 403 })]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), { message: "SBOM download failed (HTTP 403)" });
});

for (const data of [{}, { spdxVersion: "SPDX-2.3" }, { spdxVersion: "SPDX-2.3", packages: [null] }]) {
  test("rejects invalid documents instead of treating them as empty successful SBOMs", async t => {
    network(t, [generated(), ready(), json(data)]);
    await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), /Invalid SBOM response/);
  });
}

test("malformed downloaded JSON fails explicitly", async t => {
  network(t, [generated(), ready(), new Response("not JSON")]);
  await assert.rejects(fetchRepositorySbom(client(), "example", "demo", fast), SyntaxError);
});

test("accepts an empty SPDX package list", async t => {
  network(t, [generated(), ready(), json({ ...document, packages: [] })]);
  assert.deepEqual((await fetchRepositorySbom(client(), "example", "demo", fast)).sbom.packages, []);
});

for (const baseUrl of [
  "https://github.internal",
  "github.internal/api/v3",
  "https://github.internal/api",
  "http://github.internal/api/v3"
]) {
  test(`GHES ${baseUrl} retains synchronous fetching without probing cloud endpoints`, async t => {
    const calls = network(t, [json({ sbom: document })]);
    assert.deepEqual((await fetchRepositorySbom(client(baseUrl), "example", "demo", fast)).sbom, document);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `${baseUrl.startsWith("http://") ? "http" : "https"}://github.internal/api/v3/repos/example/demo/dependency-graph/sbom`);
  });
}

test("normalizes binary Octokit GHES responses", async t => {
  network(t, [new Response(JSON.stringify({ sbom: document }), { headers: { "content-type": "application/octet-stream" } })]);
  assert.deepEqual((await fetchRepositorySbom(client("https://github.internal"), "example", "demo", fast)).sbom, document);
});

for (const baseUrl of ["https://github.com", "https://example.ghe.com", "https://api.example.ghe.com"]) {
  test(`${baseUrl} uses the cloud asynchronous flow`, async t => {
    const hostname = new URL(baseUrl).hostname;
    const base = hostname === "ghe.com" || hostname.endsWith(".ghe.com") ? "https://api.example.ghe.com" : api;
    const calls = network(t, [generated(base), ready(), json(document)]);
    await fetchRepositorySbom(client(baseUrl), "example", "demo", fast);
    assert.equal(calls[0].url, `${base}/repos/example/demo/dependency-graph/sbom/generate-report`);
    assert.equal(calls[1].url, `${base}${reportPath}`);
  });
}

test("collection preserves metadata, SPDX PURL search, cache round-trip and incremental skips", async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sbom-fetch-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const meta = { name: "demo", pushed_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-02T00:00:00Z", default_branch: "main" };
  const calls = network(t, [json(meta), generated(), ready(), json(document), json(meta)]);
  const options = { token: "test-token", repo: "example/demo", quiet: true, lightDelayMs: 0, delayMsBetweenRepos: 0 };
  const collector = new SbomCollector({ ...options, syncSboms: true });
  const sboms = await collector.collect();
  assert.equal(sboms.length, 1);
  assert.equal(sboms[0].error, undefined);
  assert.deepEqual(sboms[0].packages, document.packages);
  assert.deepEqual(sboms[0].sbom, document);
  assert.equal(sboms[0].repoPushedAt, meta.pushed_at);
  assert.equal(sboms[0].repoUpdatedAt, meta.updated_at);
  assert.equal(sboms[0].defaultBranch, "main");
  assert.equal(collector.searchByPurlsWithReasons(["pkg:npm/chalk@5.6.1"]).size, 1);
  writeAll(sboms, { outDir: dir });
  const cached = JSON.parse(JSON.stringify(sboms));
  const offline = new SbomCollector({ ...options, token: undefined, loadFromDir: dir });
  assert.deepEqual(await offline.collect(), cached);
  assert.equal(offline.searchByPurlsWithReasons(["pkg:npm/chalk@^5.0.0"]).size, 1);
  const incremental = new SbomCollector({ ...options, loadFromDir: dir, syncSboms: true });
  const reused = await incremental.collect();
  assert.ok(reused.length > 0);
  for (const entry of reused) assert.deepEqual(entry, cached[0]);
  assert.equal(incremental.getSummary().skippedCount, 1);
  assert.equal(calls.length, 5);
});

test("collection records asynchronous errors in the existing repository error/summary shape", async t => {
  network(t, [json({ name: "demo" }), json({ message: "not available" }, 404)]);
  const collector = new SbomCollector({
    token: "test-token", repo: "example/demo", syncSboms: true,
    quiet: true, lightDelayMs: 0, delayMsBetweenRepos: 0
  });
  const sboms = await collector.collect();
  assert.match(sboms[0].error ?? "", /not available/);
  assert.deepEqual(sboms[0].packages, []);
  assert.equal(collector.getSummary().failedCount, 1);
  assert.equal(collector.getSummary().successCount, 0);
});
