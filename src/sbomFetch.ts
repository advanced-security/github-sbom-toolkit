import type { createOctokit } from "./octokit.js";
import type { Sbom } from "./types.js";
import { setTimeout as sleep } from "node:timers/promises";

type Client = ReturnType<typeof createOctokit>;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSbom(data: unknown): Sbom {
  if (data instanceof ArrayBuffer) data = new TextDecoder().decode(data);
  if (ArrayBuffer.isView(data)) data = new TextDecoder().decode(data);
  if (typeof data === "string") data = JSON.parse(data);
  if (isObject(data) && "sbom" in data) data = data.sbom;
  if (!isObject(data) || typeof data.spdxVersion !== "string" ||
      !data.spdxVersion.startsWith("SPDX-") || !Array.isArray(data.packages) ||
      !data.packages.every(isObject)) {
    throw new Error("Invalid SBOM response: expected an SPDX document with a packages array");
  }
  return data as Sbom;
}

async function downloadSbom(location: string, reportUrl: URL, signal: AbortSignal): Promise<{ sbom: Sbom; etag?: string }> {
  let url = new URL(location, reportUrl);
  for (let redirects = 0; redirects <= 5; redirects++) {
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new Error("Invalid SBOM download URL: expected HTTPS without embedded credentials");
    }
    // Never use the authenticated Octokit client for signed download URLs.
    const response = await fetch(url, {
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "manual",
      signal
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      await response.body?.cancel();
      const next = response.headers.get("location");
      if (!next) throw new Error("SBOM download redirect is missing Location");
      url = new URL(next, url);
      continue;
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new Error(`SBOM download failed (HTTP ${response.status})`);
    }
    return { sbom: normalizeSbom(await response.text()), etag: response.headers.get("etag") ?? undefined };
  }
  throw new Error("SBOM download exceeded 5 redirects");
}

export async function fetchRepositorySbom(
  octokit: Client,
  owner: string,
  repo: string,
  { timeoutMs = 120_000, pollIntervalMs = 1_000 } = {}
): Promise<{ sbom: Sbom; etag?: string }> {
  const endpoint = octokit.request.endpoint("GET /repos/{owner}/{repo}/dependency-graph/sbom", { owner, repo });
  const apiUrl = new URL(endpoint.url);
  // GHES (including custom hostnames without --ghes) still documents the synchronous API.
  if (/\/api\/v3\//i.test(apiUrl.pathname)) {
    const response = await octokit.request("GET /repos/{owner}/{repo}/dependency-graph/sbom", {
      owner, repo, headers: { Accept: "application/vnd.github+json" }
    });
    return { sbom: normalizeSbom(response.data), etag: response.headers.etag };
  }

  const controller = new AbortController();
  const timeoutError = new Error(`SBOM generation/download timed out after ${timeoutMs}ms for ${owner}/${repo}`);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(timeoutError);
    }, timeoutMs);
  });
  const request = {
    redirect: "manual" as const,
    signal: controller.signal,
    retries: 0
  };
  const run = async () => {
    const generated = await octokit.request("GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report", {
      owner, repo, headers: { Accept: "application/vnd.github+json" }, request
    });
    const data: unknown = generated.data;
    if (generated.status !== 201 || !isObject(data) || typeof data.sbom_url !== "string" || !data.sbom_url) {
      throw new Error("Invalid SBOM generation response: expected HTTP 201 and sbom_url");
    }
    const reportUrl = new URL(data.sbom_url, apiUrl);
    const reportPrefix = `${apiUrl.pathname}/fetch-report/`;
    if (reportUrl.origin !== apiUrl.origin || reportUrl.username || reportUrl.password ||
        !reportUrl.pathname.toLowerCase().startsWith(reportPrefix.toLowerCase()) || !reportUrl.pathname.slice(reportPrefix.length) ||
        reportUrl.pathname.slice(reportPrefix.length).includes("/")) {
      throw new Error("Invalid SBOM report URL: expected this repository's API fetch-report endpoint");
    }
    while (!controller.signal.aborted) {
      const response = await octokit.request({
        method: "GET",
        url: reportUrl.href, headers: { Accept: "application/vnd.github+json" }, request
      });
      if (response.status === 302) {
        if (!response.headers.location) throw new Error("SBOM report redirect is missing Location");
        return downloadSbom(String(response.headers.location), reportUrl, controller.signal);
      }
      if (response.status !== 202) {
        throw new Error(`Unexpected SBOM report status: HTTP ${response.status}`);
      }
      const retryAfter = String(response.headers["retry-after"] ?? "");
      const seconds = retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : undefined;
      const date = retryAfter && seconds === undefined ? Date.parse(retryAfter) : NaN;
      const delay = seconds !== undefined ? seconds * 1000 : Number.isFinite(date) ? date - Date.now() : 0;
      // The overall deadline also bounds server-directed delays.
      await sleep(Math.min(timeoutMs, Math.max(pollIntervalMs, delay)), undefined, { signal: controller.signal });
    }
    throw timeoutError;
  };
  try {
    return await Promise.race([run(), deadline]);
  } finally {
    clearTimeout(timer);
  }
}
