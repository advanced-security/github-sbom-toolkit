import { Octokit } from "@octokit/core";
import { paginateRest } from "@octokit/plugin-paginate-rest";
import { restEndpointMethods } from "@octokit/plugin-rest-endpoint-methods";
import { throttling } from "@octokit/plugin-throttling";
import { retry } from "@octokit/plugin-retry";
import chalk from "chalk";

export interface OctokitFactoryOptions {
  token: string;
  baseUrl?: string; // GitHub Enterprise Server URL (no trailing slash)
  userAgentExtra?: string;
  suppressSecondaryRateLimitLogs?: boolean;
  onSecondaryRateLimitHit?: (retryAfterSeconds: number) => void; // callback hook
}

const MyOctokit = Octokit.plugin(paginateRest, restEndpointMethods, throttling, retry);

export function createOctokit({ token, baseUrl, userAgentExtra, suppressSecondaryRateLimitLogs, onSecondaryRateLimitHit }: OctokitFactoryOptions) {
  const normalizedBase = baseUrl?.replace(/\/$/, "");
  return new MyOctokit({
    auth: token,
    baseUrl: normalizedBase,
    userAgent: `github-sbom-toolkit/0.1.0 ${userAgentExtra ?? ""}`.trim(),
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
