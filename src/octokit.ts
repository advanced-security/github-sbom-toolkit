import { Octokit } from "@octokit/core";
import { paginateRest } from "@octokit/plugin-paginate-rest";
import { restEndpointMethods } from "@octokit/plugin-rest-endpoint-methods";
import { throttling } from "@octokit/plugin-throttling";
import { retry } from "@octokit/plugin-retry";

export interface OctokitFactoryOptions {
  token: string;
  baseUrl?: string; // GitHub Enterprise Server URL (no trailing slash)
  userAgentExtra?: string;
}

const MyOctokit = Octokit.plugin(paginateRest, restEndpointMethods, throttling, retry);

export function createOctokit({ token, baseUrl, userAgentExtra }: OctokitFactoryOptions) {
  let normalizedBase = baseUrl?.replace(/\/$/, "");
  if (normalizedBase && !/github\.com/.test(normalizedBase) && !/\/api\/v3$/.test(normalizedBase)) {
    // Likely a GHES host root; append /api/v3
    normalizedBase = `${normalizedBase}/api/v3`;
  }
  return new MyOctokit({
    auth: token,
    baseUrl: normalizedBase,
    userAgent: `gh-sbom-collector/0.1.0 ${userAgentExtra ?? ""}`.trim(),
    request: { timeout: 30_000 },
    retry: { doNotRetry: [400, 401, 403, 404] },
    throttle: {
      // Using unknown to avoid any; casting only what's needed.
      onRateLimit: (retryAfter: number, options: unknown, _octokit: unknown, retryCount: number) => {
        const opt = options as { method?: string; url?: string };
        if (retryCount < 2) {
          console.warn(`Rate limit hit for ${opt.method} ${opt.url}. Retrying after ${retryAfter}s.`);
          return true;
        }
        console.error(`Rate limit exceeded for ${opt.method} ${opt.url}. Not retrying.`);
        return false;
      },
      onSecondaryRateLimit: (retryAfter: number, options: unknown) => {
        const opt = options as { method?: string; url?: string };
        console.warn(`Secondary rate limit detected for ${opt.method} ${opt.url}. Pausing for ${retryAfter}s.`);
        return true;
      }
    }
  });
}
