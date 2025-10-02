import { Octokit } from "@octokit/core";
import { paginateRest } from "@octokit/plugin-paginate-rest";
import { restEndpointMethods } from "@octokit/plugin-rest-endpoint-methods";
import { throttling } from "@octokit/plugin-throttling";
import { retry } from "@octokit/plugin-retry";
import chalk from "chalk";
import fs from "fs";
import https from "https";

export interface OctokitFactoryOptions {
  token: string;
  baseUrl?: string; // GitHub Enterprise Server URL (no trailing slash)
  userAgentExtra?: string;
  suppressSecondaryRateLimitLogs?: boolean;
  onSecondaryRateLimitHit?: (retryAfterSeconds: number) => void; // callback hook
  caBundlePath?: string; // path to PEM file with additional CA(s)
}

const MyOctokit = Octokit.plugin(paginateRest, restEndpointMethods, throttling, retry);

export function createOctokit({ token, baseUrl, userAgentExtra, suppressSecondaryRateLimitLogs, onSecondaryRateLimitHit, caBundlePath }: OctokitFactoryOptions) {
  const normalize = (raw?: string): string | undefined => {
    if (!raw || !raw.trim()) return undefined; // let Octokit default to api.github.com
    let candidate = raw.trim().replace(/\/$/, "");
    // If user accidentally passed a REST path (e.g. https://host/api/v3) that's okay; we'll detect later.
    // Ensure we have a protocol; default to https.
    if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`;
    let url: URL;
    try { url = new URL(candidate); } catch { return candidate; }
    const host = url.hostname.toLowerCase();
    const isDotCom = host === "github.com" || host === "api.github.com";
    const isGheCom = host.endsWith(".ghe.com") || host === "ghe.com" || host.startsWith("api.") && host.endsWith(".ghe.com");

    if (isDotCom) {
      // Always use api.github.com for REST base
      return "https://api.github.com";
    }

    if (isGheCom) {
      // Enterprise Managed Users / data residency domains behave like dotcom: api.<host> pattern, no /api/v3
      // If host already starts with api. keep as-is, else prepend.
      if (!host.startsWith("api.")) {
        return `${url.protocol}//api.${url.hostname}`;
      }
      return `${url.protocol}//${url.hostname}`;
    }

    // GHES: arbitrary hostname -> REST at /api/v3, regardless of whether user supplied bare host.
    // If path already includes /api/v3 (case-insensitive), keep it.
    const pathLower = url.pathname.toLowerCase();
    if (/\/api\/v3$/.test(pathLower)) {
      return `${url.origin}${url.pathname.replace(/\/$/, "")}`;
    }
    // If they provided /api or /api/ (GraphQL style attempt), normalize to /api/v3 for REST.
    if (/\/api$/.test(pathLower) || /\/api\/$/.test(pathLower)) {
      return `${url.origin}/api/v3`;
    }
    return `${url.origin}/api/v3`;
  };

  const normalizedBase = normalize(baseUrl);

  // Optional custom CA bundle (self-signed / internal PKI)
  let agent: https.Agent | undefined;
  if (caBundlePath) {
    try {
      const caPem = fs.readFileSync(caBundlePath, "utf8");
      agent = new https.Agent({ ca: caPem });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`Failed to load CA bundle at ${caBundlePath}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return new MyOctokit({
    auth: token,
    baseUrl: normalizedBase,
    userAgent: `github-sbom-toolkit/0.1.0 ${userAgentExtra ?? ""}`.trim(),
    request: { timeout: 30_000, agent },
    retry: { doNotRetry: [400, 401, 403, 404] },
    throttle: {
      onRateLimit: (retryAfter: number, options: unknown, _octokit: unknown, retryCount: number) => {
        const opt = options as { method?: string; url?: string };
        if (retryCount < 2) {
          console.warn(`Rate limit hit for ${opt.method} ${opt.url}. Retrying after ${retryAfter}s.`);
          return true;
        }
        console.error(`Rate limit exceeded for ${opt.method} ${opt.url}. Not retrying.`);
        return false;
      },
      onSecondaryRateLimit: async (retryAfter: number, _options: unknown) => {
        if (!suppressSecondaryRateLimitLogs) {
          console.warn(chalk.grey(`Secondary rate limit hit. Pausing for ${retryAfter}s.`));
        }
        try { onSecondaryRateLimitHit?.(retryAfter); } catch { /* swallow callback errors */ }
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        return true;
      }
    }
  });
}
