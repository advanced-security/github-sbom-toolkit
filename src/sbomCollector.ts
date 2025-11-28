import { createOctokit } from "./octokit.js";
import type { RepositorySbom, CollectionSummary, SbomPackage, Sbom, BranchDependencyDiff, DependencyReviewPackageChange } from "./types.js";
import * as semver from "semver";
import { readAll, writeOne } from "./serialization.js";
import { submitSnapshotIfPossible } from "./componentSubmission.js";
// p-limit lacks bundled types in some versions; declare minimal shape
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import pLimit from "p-limit";
import chalk from "chalk";

export interface CollectorOptions {
  token: string | undefined; // GitHub token with repo + security_events scope
  enterprise?: string; // Enterprise slug to enumerate orgs
  org?: string; // Single org alternative
  repo?: string; // Single repo alternative
  baseUrl?: string; // For GHES
  concurrency?: number; // parallel repo SBOM fetches
  includePrivate?: boolean;
  delayMsBetweenRepos?: number;
  lightDelayMs?: number; // delay for lightweight (non-SBOM) requests
  loadFromDir?: string; // optional pre-existing serialized SBOM directory
  syncSboms?: boolean; // if true, fetch SBOMs from GitHub (requires token)
  autoEnableDependencyGraph?: boolean; // attempt to enable Dependency Graph if disabled
  showProgressBar?: boolean; // render a simple progress bar when fetching SBOMs
  suppressSecondaryRateLimitLogs?: boolean; // suppress secondary rate limit warning logs (so they don't break the progress bar)
  quiet?: boolean; // suppress non-error logging (does not affect progress bar)
  caBundlePath?: string; // path to PEM CA bundle for self-signed/internal certs
  includeBranches?: boolean; // when true, fetch SBOM for non-default branches
  branchLimit?: number; // limit number of branches per repo (excluding default)
  branchDiffBase?: string; // override base branch for diffs (defaults to default branch)
  submitOnMissingSnapshot?: boolean; // run component detection submission when diff 404
  submitLanguages?: string[]; // limit submission to these languages
  componentDetectionBinPath?: string; // optional path to component-detection executable
}

export class SbomCollector {
  private octokit: ReturnType<typeof createOctokit> | undefined; // explicit type
  private opts: Required<CollectorOptions>;
  private sboms: RepositorySbom[] = [];
  private summary: CollectionSummary;
  private baselineMap: Map<string, RepositorySbom> = new Map();
  private decisions: Record<string, string> = {}; // repo -> reason

  constructor(options: CollectorOptions) {
    if (!options.loadFromDir && !options.enterprise && !options.org && !options.repo) {
      throw new Error("One of enterprise/org/repo or loadFromDir must be specified");
    }
    // Spread user options first then apply defaults via nullish coalescing so that
    // passing undefined does not erase defaults
    const o = { ...options };
    this.opts = {
      token: o.token,
      enterprise: o.enterprise,
      org: o.org,
      repo: o.repo,
      baseUrl: o.baseUrl,
      concurrency: o.concurrency ?? 5,
      includePrivate: o.includePrivate ?? true,
      delayMsBetweenRepos: o.delayMsBetweenRepos ?? 5000,
      lightDelayMs: o.lightDelayMs ?? 500,
      loadFromDir: o.loadFromDir,
      syncSboms: o.syncSboms ?? false,
      autoEnableDependencyGraph: o.autoEnableDependencyGraph ?? true,
      showProgressBar: o.showProgressBar ?? false,
      suppressSecondaryRateLimitLogs: o.suppressSecondaryRateLimitLogs ?? false,
      quiet: o.quiet ?? false,
      caBundlePath: o.caBundlePath
      ,includeBranches: o.includeBranches ?? false
      ,branchLimit: o.branchLimit ?? 20
      ,branchDiffBase: o.branchDiffBase
      ,submitOnMissingSnapshot: o.submitOnMissingSnapshot ?? false
      ,submitLanguages: o.submitLanguages ?? undefined
      ,componentDetectionBinPath: o.componentDetectionBinPath
    } as Required<CollectorOptions>;

    if (this.opts.token) {
      this.octokit = createOctokit({
        token: this.opts.token,
        baseUrl: this.opts.baseUrl,
        suppressSecondaryRateLimitLogs: this.opts.suppressSecondaryRateLimitLogs || this.opts.quiet,
        onSecondaryRateLimitHit: () => {
          // Increase SBOM delay (delayMsBetweenRepos) by 10% each time to reduce pressure.
          const oldDelay = this.opts.delayMsBetweenRepos;
          const newDelay = Math.ceil(oldDelay * 1.1 + 1);
          this.opts.delayMsBetweenRepos = newDelay as unknown as typeof this.opts.delayMsBetweenRepos;
          if (!this.opts.quiet) {
            console.warn(chalk.yellow(`Adaptive backoff: increased SBOM delay from ${oldDelay}ms to ${newDelay}ms after secondary rate limit.`));
          }
        },
        caBundlePath: this.opts.caBundlePath
      });
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
      // find just the path for a single org or repo, if given
      const loadPath = this.opts.org ? `${this.opts.loadFromDir}/${this.opts.org}` : this.opts.repo ? `${this.opts.loadFromDir}/${this.opts.repo}` : this.opts.loadFromDir;

      if (!this.opts.quiet) process.stderr.write(chalk.blue(`Loading SBOMs from cache at ${loadPath}`) + "\n");

      try {
        this.sboms = readAll(loadPath);
      } catch (error) {
        console.error(chalk.yellow(`Didn't load any SBOMs from cache: ${error as Error}`));
      }

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

    if (this.opts.enterprise && !this.opts.quiet) {
      process.stderr.write(chalk.blue(`Getting list of organizations for enterprise ${this.opts.enterprise}`) + "\n");
    }

    const orgs = this.opts.org ? [this.opts.org] : this.opts.enterprise ? await this.listEnterpriseOrgs(this.opts.enterprise!) : [this.opts.repo.split("/")[0]];
    this.summary.orgs = orgs;

    // Pre-list all repos if showing progress bar so we know the total upfront
    const orgRepoMap: Record<string, { name: string; pushed_at?: string; updated_at?: string; default_branch?: string }[]> = {};
    let totalRepos = 0;

    if (!this.opts.repo) {
      for (const org of orgs) {
        if (!this.opts.quiet) process.stderr.write(chalk.blue(`Listing repositories for org ${org}`) + "\n");
        if (this.opts.lightDelayMs) await new Promise(r => setTimeout(r, this.opts.lightDelayMs));
        const repos = await this.listOrgRepos(org);
        orgRepoMap[org] = repos;
        totalRepos += repos.length;
      }
    } else {
      totalRepos = 1;
      const [org, repoName] = this.opts.repo.split("/");
      orgRepoMap[org] = [await this.getRepo(org, repoName)];
      this.summary.orgs = orgs;
    }

    this.summary.repositoryCount = totalRepos;

    let processed = 0;
    let lastRender = 0;
    const renderBar = () => {
      if (!this.opts.showProgressBar) return;
      const now = Date.now();
      if (now - lastRender < 80) return; // throttle to ~12fps
      lastRender = now;
      const width = 30;
      const ratio = totalRepos === 0 ? 0 : processed / totalRepos;
      const filled = Math.round(ratio * width);
      const bar = `[${"#".repeat(filled).padEnd(width, "-")}] ${(ratio * 100).toFixed(1)}% (${processed}/${totalRepos})`;
      process.stdout.write(`\r${bar}`);
    };

    if (this.opts.showProgressBar && totalRepos > 0 && !this.opts.quiet) {
      process.stdout.write(chalk.blue(`Fetching SBOMs for ${orgs.length} org(s) / ${totalRepos} repositories...`) + "\n");
    }

    for (const org of orgs) {
      if (!this.opts.showProgressBar && !this.opts.quiet) {
        process.stderr.write(chalk.blue(`Collecting SBOMs for org ${org}`) + "\n");
      }
      const repos = orgRepoMap[org];
      const repoNames = new Set(repos.map(r => r.name));
      const limit = pLimit(this.opts.concurrency);
      let newSboms: RepositorySbom[] = [];

      const tasks = repos.map(repo => limit(async () => {
        const fullName = `${org}/${repo.name}`;
        const baseline = this.baselineMap.get(fullName.toLowerCase());
        let skipped = false;
        let pendingCommitMeta: { sha?: string; date?: string } | undefined;
        if (baseline && baseline.repoPushedAt && repo.pushed_at) {
          try {
            if (new Date(repo.pushed_at) <= new Date(baseline.repoPushedAt)) {
              // repo pushed_at unchanged -> skip
              newSboms.push(baseline);
              this.summary.skippedCount++;
              this.decisions[fullName] = `Skipping (no new pushes since last fetch)`;
              skipped = true;
            } else {
              // There have been pushes; refine by checking default branch head commit date
              if (repo.default_branch) {
                try {
                  if (this.opts.lightDelayMs) await new Promise(r => setTimeout(r, this.opts.lightDelayMs));
                  const commitResp = await this.octokit!.request("GET /repos/{owner}/{repo}/commits/{ref}", { owner: org, repo: repo.name, ref: repo.default_branch });
                  const commit = commitResp.data as { sha?: string; commit?: { author?: { date?: string }; committer?: { date?: string } } };
                  const commitDate = commit.commit?.committer?.date || commit.commit?.author?.date;
                  pendingCommitMeta = { sha: commit.sha, date: commitDate };
                  if (commitDate) {
                    const commitTime = new Date(commitDate).getTime();
                    const previousRetrieval = new Date(baseline.retrievedAt).getTime();
                    if (commitTime <= previousRetrieval) {
                      // Default branch head hasn't advanced since last SBOM retrieval -> skip
                      newSboms.push(baseline);
                      this.summary.skippedCount++;
                      this.decisions[fullName] = `Skipping (default branch commit not newer than previous SBOM: ${commitDate} <= ${baseline.retrievedAt})`;
                      skipped = true;
                    } else {
                      this.decisions[fullName] = `Fetching (default branch commit is newer: ${commitDate} > ${baseline.retrievedAt})`;
                    }
                  } else {
                    this.decisions[fullName] = `Fetching (commit date missing; pushes detected ${repo.pushed_at} > ${baseline.repoPushedAt})`;
                  }
                } catch (e) {
                  this.decisions[fullName] = `Fetching (failed to get default branch commit for refinement: ${(e as Error).message})`;
                }
              } else {
                this.decisions[fullName] = `Fetching (no default branch info to refine; pushes detected)`;
              }
            }
          } catch {
            this.decisions[fullName] = `Fetching because error comparing pushed_at (${baseline.repoPushedAt} / ${repo.pushed_at})`;
          }
        } else {
          this.decisions[fullName] = baseline ? `Fetching because missing pushed_at (${baseline.repoPushedAt} / ${repo.pushed_at})` : "Fetching because no baseline";
        }

        let sbom : RepositorySbom | undefined = undefined;

        if (!skipped) {
          const res = await this.fetchSbom(org, repo.name, repo);
          if (this.opts.delayMsBetweenRepos) {
            await new Promise(r => setTimeout(r, this.opts.delayMsBetweenRepos));
          }
          if (pendingCommitMeta) {
            res.defaultBranchCommitSha = pendingCommitMeta.sha;
            res.defaultBranchCommitDate = pendingCommitMeta.date;
          }

          sbom = res;
        } else {
          sbom = baseline;
        }

        // Branch scanning (optional)
        // TODO: implement some check to see if the diff info we have is already fresher than the branch info
        if (this.opts.includeBranches && sbom?.sbom) {

          console.log(chalk.blue(`Scanning branches for ${fullName}...`));

          try {
            const branches = await this.listBranches(org, repo.name);
            const nonDefault = branches.filter(b => b.name !== sbom.defaultBranch);
            const limited = this.opts.branchLimit && this.opts.branchLimit > 0 ? nonDefault.slice(0, this.opts.branchLimit) : nonDefault;
            const branchDiffs: BranchDependencyDiff[] = [];
            for (const b of limited) {
              if (this.opts.lightDelayMs) await new Promise(r => setTimeout(r, this.opts.lightDelayMs));
              const base = this.opts.branchDiffBase || sbom?.defaultBranch;
              if (!base) { console.error(chalk.red(`Cannot compute branch diff for ${fullName} branch ${b.name} because base branch is undefined.`)); continue; }
              if (this.opts.lightDelayMs) await new Promise(r => setTimeout(r, this.opts.lightDelayMs));
              const diff = await this.fetchDependencyReviewDiff(org, repo.name, base, b.name);
              console.log(diff);
              branchDiffs.push(diff);
            }
            if (branchDiffs.length) sbom.branchDiffs = branchDiffs;
          } catch (e) {
            // Non-fatal; annotate decision
            this.decisions[fullName] = (this.decisions[fullName] || "") + ` (branch scan error: ${(e as Error).message})`;
          }
          newSboms.push(sbom);
          if (sbom.error) this.summary.failedCount++; else this.summary.successCount++;
          // Write freshly fetched SBOM immediately if a cache directory is configured
          if (this.opts.loadFromDir && this.opts.syncSboms && this.opts.loadFromDir.length) {
            try { writeOne(sbom, { outDir: this.opts.loadFromDir }); } catch { /* ignore write errors */ }
          }
        }
        processed++;
        renderBar();
      }));
      await Promise.all(tasks);
      newSboms = newSboms.filter(s => repoNames.has(s.repo));
      this.sboms.push(...newSboms);
    }
    if (this.opts.showProgressBar) process.stdout.write("\n");
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

  private async getRepo(org: string, repo: string): Promise<{ name: string; pushed_at?: string; updated_at?: string; default_branch?: string }> {
    if (!this.octokit) throw new Error("No Octokit instance");

    try {
      const resp = await this.octokit.request("GET /repos/{owner}/{repo}", { owner: org, repo });
      const data = resp.data as { name: string; pushed_at?: string; updated_at?: string; default_branch?: string };
      return data;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`Failed to get repo metadata for ${org}/${repo}: ${msg}`);
    }
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

  private async listBranches(org: string, repo: string): Promise<{ name: string; protected?: boolean; commit?: { sha?: string } }[]> {
    if (!this.octokit) throw new Error("No Octokit instance");
    const branches: { name: string; protected?: boolean; commit?: { sha?: string } }[] = [];
    const per_page = 100; let page = 1; let done = false;
    while (!done) {
      try {
        const resp = await this.octokit.request("GET /repos/{owner}/{repo}/branches", { owner: org, repo, per_page, page });
        const data = resp.data as Array<{ name: string; protected?: boolean; commit?: { sha?: string } }>;
        branches.push(...data);
        if (data.length < per_page) done = true; else page++;
      } catch (e) {
        throw new Error(`Failed listing branches for ${org}/${repo}: ${(e as Error).message}`);
      }
    }
    return branches;
  }

  private async fetchDependencyReviewDiff(org: string, repo: string, base: string, head: string): Promise<BranchDependencyDiff> {
    if (!this.octokit) throw new Error("No Octokit instance");
    try {
      const basehead = `${base}...${head}`;
      const resp = await this.octokit.request("GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}", { owner: org, repo, basehead, headers: { Accept: "application/vnd.github+json" } });
      // Response shape includes change_set array (per docs). We normalize to DependencyReviewPackageChange[]
      const raw = resp.data;

      const changes: DependencyReviewPackageChange[] = [];
      for (const c of raw) {
        const obj = c as Record<string, unknown>;
        const change: DependencyReviewPackageChange = {
          changeType: String(obj.change_type || "unknown"),
          name: obj.name as string | undefined,
          ecosystem: obj.ecosystem as string | undefined,
          packageURL: obj.package_url as string | undefined,
          license: obj.license as string | undefined,
          manifest: obj.manifest as string | undefined,
          scope: obj.scope as string | undefined,
          version: obj.version as string | undefined
        };
        changes.push(change);
      }
      console.log(`Parsed dependency review diff for ${org}/${repo} ${base}...${head}: ${JSON.stringify(changes)}`);
      return { base, head, retrievedAt: new Date().toISOString(), changes };
    } catch (e) {
      const status = (e as { status?: number })?.status;
      let reason = e instanceof Error ? e.message : String(e);
      if (status === 404) {
        reason = "Dependency review unavailable (missing snapshot or feature disabled)";
        // Optional retry path: submit snapshot then retry once
        if (this.opts.submitOnMissingSnapshot) {
          console.log(chalk.blue(`Attempting to submit component snapshot for ${org}/${repo} branch ${head} before retrying dependency review diff...`));
          try {
            const ok = await submitSnapshotIfPossible({ octokit: this.octokit, owner: org, repo: repo, branch: head, languages: this.opts.submitLanguages, quiet: this.opts.quiet, componentDetectionBinPath: this.opts.componentDetectionBinPath });
            if (ok) {
              console.log(chalk.blue(`Snapshot submission attempted; waiting 3 seconds before retrying dependency review diff for ${org}/${repo} ${base}...${head}...`));
              await new Promise(r => setTimeout(r, 3000));
              return await this.fetchDependencyReviewDiff(org, repo, base, head);
            }
          } catch (subErr) {
            console.error(chalk.red(`Snapshot submission failed for ${org}/${repo} branch ${head}: ${(subErr as Error).message}`));
            reason += ` (submission attempt failed: ${(subErr as Error).message})`;
          }
        }
      }
      return { base, head, retrievedAt: new Date().toISOString(), changes: [], error: reason };
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
      // Include branch SBOM packages
      if (repoSbom.branchSboms) {
        for (const b of repoSbom.branchSboms) {
          if (b.error) continue;
          for (const pkg of b.packages as Array<SbomPackage & { externalRefs?: ExtRef[] }>) {
            const refs = (pkg as { externalRefs?: ExtRef[] }).externalRefs;
            const candidatePurls: string[] = [];
            if (refs) for (const r of refs) if (r.referenceType === "purl" && r.referenceLocator) candidatePurls.push(r.referenceLocator);
            if ((pkg as { purl?: string }).purl) candidatePurls.push((pkg as { purl?: string }).purl as string);
            const unique = Array.from(new Set(candidatePurls));
            for (const p of unique) {
              const pLower = p.toLowerCase();
              for (const q of queries) {
                if (q.isPrefixWildcard) {
                  const prefix = q.lower.slice(0, -1);
                  if (pLower.startsWith(prefix)) { if (!found.has(`${p}@${b.branch}`)) found.set(`${p}@${b.branch}`, q.raw); }
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
                        if (!found.has(`${p}@${b.branch}`)) found.set(`${p}@${b.branch}`, q.raw);
                      }
                    } catch { /* ignore */ }
                  }
                } else if (q.exact) {
                  if (pLower === q.exact) { if (!found.has(`${p}@${b.branch}`)) found.set(`${p}@${b.branch}`, q.raw); }
                }
              }
            }
          }
        }
      }
      // Include dependency review diff additions/updates (head packages only)
      if (repoSbom.branchDiffs) {
        for (const diff of repoSbom.branchDiffs) {
          for (const change of diff.changes) {
            if (change.changeType !== "added") continue;
            const p = change.packageURL;
            if (!p) continue;
            const pLower = p.toLowerCase();
            for (const q of queries) {
              if (q.isPrefixWildcard) {
                const prefix = q.lower.slice(0, -1);
                if (pLower.startsWith(prefix)) { if (!found.has(`${p}@${diff.head}`)) found.set(`${p}@${diff.head}`, q.raw); }
                continue;
              }
              if (q.versionConstraint && q.type && q.name) {
                if (!pLower.startsWith("pkg:")) continue;
                const body = p.slice(4);
                const atIdx = body.indexOf("@");
                const main = atIdx >= 0 ? body.slice(0, atIdx) : body;
                const ver = atIdx >= 0 ? body.slice(atIdx + 1) : change.newVersion;
                const slashIdx = main.indexOf("/");
                if (slashIdx < 0) continue;
                const pType = main.slice(0, slashIdx).toLowerCase();
                const pName = main.slice(slashIdx + 1);
                if (pType === q.type && pName.toLowerCase() === q.name.toLowerCase() && ver) {
                  try {
                    const coerced = semver.coerce(ver)?.version || ver;
                    if (semver.valid(coerced) && semver.satisfies(coerced, q.versionConstraint, { includePrerelease: true })) {
                      if (!found.has(`${p}@${diff.head}`)) found.set(`${p}@${diff.head}`, q.raw);
                    }
                  } catch { /* ignore */ }
                }
              } else if (q.exact) {
                if (pLower === q.exact) { if (!found.has(`${p}@${diff.head}`)) found.set(`${p}@${diff.head}`, q.raw); }
              }
            }
          }
        }
      }
      if (found.size) results.set(repoSbom.repo, Array.from(found.entries()).map(([purl, reason]) => ({ purl, reason })));
    }
    return results;
  }
}
