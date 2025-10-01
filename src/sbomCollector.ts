import { createOctokit } from "./octokit.js";
import type { RepositorySbom, CollectionSummary, SbomPackage, Sbom } from "./types.js";
import * as semver from "semver";
import { readAll } from "./serialization.js";
// p-limit lacks bundled types in some versions; declare minimal shape
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import pLimit from "p-limit";
import chalk from "chalk";

export interface CollectorOptions {
  token: string | undefined; // GitHub token with repo + security_events scope
  enterprise?: string; // Enterprise slug to enumerate orgs
  org?: string; // Single org alternative
  baseUrl?: string; // For GHES
  concurrency?: number; // parallel repo SBOM fetches
  includePrivate?: boolean;
  delayMsBetweenRepos?: number;
  loadFromDir?: string; // optional pre-existing serialized SBOM directory
  syncSboms?: boolean; // if true, fetch SBOMs from GitHub (requires token)
  autoEnableDependencyGraph?: boolean; // attempt to enable Dependency Graph if disabled
}

export class SbomCollector {
  private octokit; // typed by Octokit instance
  private opts: Required<CollectorOptions>;
  private sboms: RepositorySbom[] = [];
  private summary: CollectionSummary;
  private baselineMap: Map<string, RepositorySbom> = new Map();
  private decisions: Record<string, string> = {}; // repo -> reason

  constructor(options: CollectorOptions) {
    if (!options.loadFromDir && !options.enterprise && !options.org) {
      throw new Error("Either enterprise/org or loadFromDir must be specified");
    }
    this.opts = {
      concurrency: 5,
      includePrivate: true,
      delayMsBetweenRepos: 0,
      baseUrl: options.baseUrl ?? undefined,
      autoEnableDependencyGraph: true,
      loadFromDir: options.loadFromDir ?? undefined,
      syncSboms: options.syncSboms ?? false,
      ...options
    } as Required<CollectorOptions>;

    if (this.opts.token) {
      this.octokit = createOctokit({ token: this.opts.token, baseUrl: this.opts.baseUrl });
    }

    this.summary = {
      enterprise: this.opts.enterprise,
      orgs: [],
      repositoryCount: 0,
      successCount: 0,
      failedCount: 0,
      skippedCount: 0,
      startedAt: new Date().toISOString()
    };
  }

  getAllSboms(): RepositorySbom[] { return this.sboms; }
  getSummary(): CollectionSummary { return this.summary; }
  getDecisions(): Record<string, string> { return this.decisions; }

  async collect(): Promise<RepositorySbom[]> {
    // Offline mode: load from directory if provided
    if (this.opts.loadFromDir) {
      // find just the path for a single org, if given
      const loadPath = this.opts.org ? `${this.opts.loadFromDir}/${this.opts.org}` : this.opts.loadFromDir;

      console.log(chalk.blue(`Loading SBOMs from cache at ${loadPath}`));

      this.sboms = readAll(loadPath);

      this.summary.repositoryCount = this.sboms.length;
      this.summary.successCount = this.sboms.filter(s => !s.error).length;
      this.summary.failedCount = this.sboms.filter(s => !!s.error).length;
      this.summary.finishedAt = new Date().toISOString();

      for (const sbom of this.sboms) this.baselineMap.set(sbom.repo.toLowerCase(), sbom);

      // Derive org list if present
      const orgSet = new Set<string>();
      for (const s of this.sboms) orgSet.add(s.org);
      this.summary.orgs = Array.from(orgSet);
    }

    if (!this.opts.syncSboms) {
      return this.sboms;
    }

    // Online mode: fetch from GitHub
    if (!this.octokit && this.opts.syncSboms) {
      throw new Error("No Octokit instance; token may be missing");
    }

    const orgs = this.opts.org ? [this.opts.org] : await this.listEnterpriseOrgs(this.opts.enterprise!);
    this.summary.orgs = orgs;
    this.summary.repositoryCount = 0; // reset to recount

    for (const org of orgs) {
      console.log(chalk.blue(`Collecting SBOMs for org ${org}`));
      const repos = await this.listOrgRepos(org);
      const repoNames = new Set(repos.map(r => r.name));
      const limit = pLimit(this.opts.concurrency);
      this.summary.repositoryCount += repos.length;  // override with actual count, not the cached one

      let newSboms: RepositorySbom[] = [];

      const tasks = repos.map((repo) => limit(async () => {
        if (this.opts.delayMsBetweenRepos) {
          await new Promise(r => setTimeout(r, this.opts.delayMsBetweenRepos));
        }
        const fullName = `${org}/${repo.name}`;
        const baseline = this.baselineMap.get(fullName.toLowerCase());

        if (baseline && baseline.repoPushedAt && repo.pushed_at) {
          try {
            if (new Date(repo.pushed_at) <= new Date(baseline.repoPushedAt)) {
              // Reuse baseline
              newSboms.push(baseline);
              this.summary.skippedCount++;
              this.decisions[fullName] = `Skipping (no new pushes since last fetch)`;
              return;
            }
            this.decisions[fullName] = `Fetching because new pushes detected since last fetch: ${repo.pushed_at} > ${baseline.repoPushedAt}`;
          } catch {
            this.decisions[fullName] = `Fetching because error comparing pushed_at (${baseline.repoPushedAt} / ${repo.pushed_at})`;
          }
        } else {
          this.decisions[fullName] = baseline ? `Fetching because missing pushed_at (${baseline.repoPushedAt} / ${repo.pushed_at})` : "Fetching because no baseline";
        }
        const res = await this.fetchSbom(org, repo.name, repo);
        newSboms.push(res);
        if (res.error) this.summary.failedCount++; else this.summary.successCount++;
      }));
      await Promise.all(tasks);
      // clear up any old cached repos that are not in the current list of in var `repos` in the org
      newSboms = newSboms.filter(s => repoNames.has(s.repo));
      this.sboms.push(...newSboms);
    }
    this.summary.finishedAt = new Date().toISOString();

    return this.sboms;
  }

  private async listEnterpriseOrgs(enterprise: string): Promise<string[]> {
    // GitHub API: GET /enterprises/{enterprise}/orgs (preview might require accept header)

    if (!this.octokit) throw new Error("No Octokit instance");

    interface Org { login: string }
    try {
      const orgs: string[] = [];
      const per_page = 100;
      let page = 1;
      let done = false;
      while (!done) {
        const resp = await this.octokit.request("GET /enterprises/{enterprise}/orgs", { enterprise, per_page, page });
        const items = resp.data as unknown as Org[];
        for (const o of items) orgs.push(o.login);
        if (items.length < per_page) done = true; else page++;
      }
      return orgs;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`Failed to list orgs for enterprise ${enterprise}: ${msg}`);
    }
  }

  private async listOrgRepos(org: string): Promise<{ name: string; pushed_at?: string; updated_at?: string; default_branch?: string }[]> {
    if (!this.octokit) throw new Error("No Octokit instance");

    // GET /orgs/{org}/repos
    interface RepoMeta { name: string; pushed_at?: string; updated_at?: string; default_branch?: string }
    const repos: RepoMeta[] = [];
    const per_page = 100;
    let page = 1;
    let done = false;
    while (!done) {
      try {
        const resp = await this.octokit.request("GET /orgs/{org}/repos", { org, per_page, page, type: this.opts.includePrivate ? "all" : "public" });
        const items = resp.data as Array<{ name: string; pushed_at?: string; updated_at?: string; default_branch?: string }>;
        for (const r of items) {
          repos.push({ name: r.name, pushed_at: r.pushed_at, updated_at: r.updated_at, default_branch: r.default_branch });
        }
        if (items.length < per_page) done = true; else page++;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error(`Error listing repos for org ${org} page ${page}: ${msg}`);
        done = true;
      }
    }
    return repos;
  }

  private async fetchSbom(org: string, repo: string, repoMeta?: { pushed_at?: string; updated_at?: string; default_branch?: string }): Promise<RepositorySbom> {
    if (!this.octokit) throw new Error("No Octokit instance");

    const fullName = `${org}/${repo}`;
    try {
      // TODO: Ensure dependency graph is enabled before requesting SBOM
      const resp = await this.octokit.request("GET /repos/{owner}/{repo}/dependency-graph/sbom", { owner: org, repo, headers: { Accept: "application/vnd.github+json" } });
      const sbomWrapper = resp.data as { sbom?: Sbom };
      const packages: SbomPackage[] = sbomWrapper?.sbom?.packages ?? [];
      return {
        repo: fullName,
        org,
        enterprise: this.opts.enterprise,
        retrievedAt: new Date().toISOString(),
        sbom: sbomWrapper?.sbom,
        packages,
        repoPushedAt: repoMeta?.pushed_at,
        repoUpdatedAt: repoMeta?.updated_at,
        defaultBranch: repoMeta?.default_branch,
        etag: (resp.headers as Record<string, string | undefined>)["etag"]
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        repo: fullName,
        org,
        enterprise: this.opts.enterprise,
        retrievedAt: new Date().toISOString(),
        packages: [],
        error: msg,
        repoPushedAt: repoMeta?.pushed_at,
        repoUpdatedAt: repoMeta?.updated_at,
        defaultBranch: repoMeta?.default_branch
      };
    }
  }

  // New method including the query that produced each match
  searchByPurlsWithReasons(purls: string[]): Map<string, { purl: string; reason: string }[]> {
    purls = purls.map(q => q.startsWith("pkg:") ? q : `pkg:${q}`);
    interface ParsedQuery {
      raw: string;
      lower: string;
      isPrefixWildcard: boolean;
      exact?: string;
      type?: string;
      name?: string;
      versionConstraint?: string;
    }
    const looksLikeSemverRange = (v: string) => /[\^~><=]|\|\|/.test(v.trim());
    const parseQuery = (raw: string): ParsedQuery | null => {
      const trimmed = raw.trim();
      if (!trimmed) return null;
      const lower = trimmed.toLowerCase();
      if (lower.endsWith("*")) return { raw: trimmed, lower, isPrefixWildcard: true };
      if (lower.startsWith("pkg:")) {
        const atIdx = trimmed.indexOf("@");
        if (atIdx > -1) {
          const coord = trimmed.slice(4, atIdx);
          const verPart = trimmed.slice(atIdx + 1).trim();
          const slashIdx = coord.indexOf("/");
          if (slashIdx > 0) {
            const type = coord.slice(0, slashIdx).toLowerCase();
            const name = coord.slice(slashIdx + 1);
            if (looksLikeSemverRange(verPart)) {
              return { raw: trimmed, lower, isPrefixWildcard: false, type, name, versionConstraint: verPart };
            }
          }
        }
        return { raw: trimmed, lower, isPrefixWildcard: false, exact: lower };
      }
      return { raw: trimmed, lower, isPrefixWildcard: false, exact: lower };
    };
    const queries: ParsedQuery[] = purls.map(parseQuery).filter((q): q is ParsedQuery => !!q);
    const results = new Map<string, { purl: string; reason: string }[]>();
    if (!queries.length) return results;
    for (const repoSbom of this.sboms) {
      if (repoSbom.error) continue;
      interface ExtRef { referenceType: string; referenceLocator: string }
      const found = new Map<string, string>(); // purl -> query
      for (const pkg of repoSbom.packages as Array<SbomPackage & { externalRefs?: ExtRef[] }>) {
        const refs = pkg.externalRefs;
        const candidatePurls: string[] = [];
        if (refs) for (const r of refs) if (r.referenceType === "purl" && r.referenceLocator) candidatePurls.push(r.referenceLocator);
        if ((pkg as { purl?: string }).purl) candidatePurls.push((pkg as { purl?: string }).purl as string);
        const unique = Array.from(new Set(candidatePurls));
        for (const p of unique) {
          const pLower = p.toLowerCase();
          for (const q of queries) {
            if (q.isPrefixWildcard) {
              const prefix = q.lower.slice(0, -1);
              if (pLower.startsWith(prefix)) { if (!found.has(p)) found.set(p, q.raw); }
              continue;
            }
            if (q.versionConstraint && q.type && q.name) {
              if (!pLower.startsWith("pkg:")) continue;
              const body = p.slice(4);
              const atIdx = body.indexOf("@");
              const main = atIdx >= 0 ? body.slice(0, atIdx) : body;
              const ver = atIdx >= 0 ? body.slice(atIdx + 1) : (pkg.version as string | undefined) || undefined;
              const slashIdx = main.indexOf("/");
              if (slashIdx < 0) continue;
              const pType = main.slice(0, slashIdx).toLowerCase();
              const pName = main.slice(slashIdx + 1);
              if (pType === q.type && pName.toLowerCase() === q.name.toLowerCase() && ver) {
                try {
                  const coerced = semver.coerce(ver)?.version || ver;
                  if (semver.valid(coerced) && semver.satisfies(coerced, q.versionConstraint, { includePrerelease: true })) {
                    if (!found.has(p)) found.set(p, q.raw);
                  }
                } catch { /* ignore */ }
              }
            } else if (q.exact) {
              if (pLower === q.exact) { if (!found.has(p)) found.set(p, q.raw); }
            }
          }
        }
      }
      if (found.size) results.set(repoSbom.repo, Array.from(found.entries()).map(([purl, reason]) => ({ purl, reason })));
    }
    return results;
  }
}
