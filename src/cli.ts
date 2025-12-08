#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import chalk from "chalk";
import { SbomCollector } from "./sbomCollector.js";
import inquirer from "inquirer"; // still used elsewhere if needed
import readline from "readline";
import { CollectionSummary, RepositorySbom } from "./types.js";
import { MalwareAdvisorySync } from "./malwareAdvisories.js";
import { MalwareMatch } from "./malwareMatcher.js";
import fs from "fs";

async function main() {
  const argv = await yargs(hideBin(process.argv))
    .scriptName("gh-sbom-collector")
    .option("token", { type: "string", describe: "GitHub token with repo + security_events scope" })
    .option("enterprise", { type: "string", describe: "Enterprise slug (mutually exclusive with --org)" })
    .option("org", { type: "string", describe: "Single organization login" })
    .option("repo", { type: "string", describe: "Single repository name" })
    .option("base-url", { type: "string", describe: "GitHub Enterprise Server base URL, e.g. https://github.mycompany.com/api/v3" })
    .option("ghes", { type: "boolean", default: false, describe: "Indicates that the provided base URL is for GitHub Enterprise Server" })
    .option("concurrency", { type: "number", default: 5 })
    .option("sbom-delay", { type: "number", default: 3000, describe: "Delay (ms) between SBOM fetch requests" })
    .option("light-delay", { type: "number", default: 100, describe: "Delay (ms) between lightweight metadata requests (org/repo listing, commit head checks)" })
    .option("sbom-cache", { type: "string", describe: "Directory to read/write cached SBOM JSON files" })
    .option("purl", { type: "array", describe: "One or more PURL strings to search (supports suffix * wildcard after slash)" })
    .option("sync-sboms", { type: "boolean", default: false, describe: "Fetch SBOMs from GitHub (write to --sbom-cache if provided) instead of offline-only" })
    .option("progress", { type: "boolean", default: false, describe: "Show a progress bar while fetching SBOMs" })
    .option("suppress-secondary-rate-limit-logs", { type: "boolean", default: false, describe: "Silence secondary rate limit warning logs (useful with --progress)" })
    .option("quiet", { type: "boolean", default: false, describe: "Suppress all non-error output (does not suppress progress bar or JSON)" })
    .option("interactive", { type: "boolean", default: false, describe: "Enter interactive PURL search mode after collection" })
    .option("sync-malware", { type: "boolean", default: false, describe: "Sync malware advisories (MALWARE classification) to local cache" })
    .option("malware-cache", { type: "string", default: "malware-cache", describe: "Directory to store malware advisory cache" })
    .option("malware-since", { type: "string", describe: "Override last sync timestamp (ISO) for malware advisory incremental sync" })
    .option("ca-bundle", { type: "string", describe: "Path to PEM file with additional CA certificate(s) (self-signed/internal)" })
    .option("match-malware", { type: "boolean", default: false, describe: "After sync/load, match SBOM packages against malware advisories" })
    .option("sarif-dir", { type: "string", describe: "Directory to write SARIF 2.1.0 files (one per repository) when --match-malware is used" })
    .option("upload-sarif", { type: "boolean", default: false, describe: "Upload generated SARIF (per-repo) to the Code Scanning API (requires --match-malware)" })
    .option("malware-cutoff", { type: "string", describe: "Ignore advisories whose publishedAt and updatedAt are both before this ISO date (e.g. 2025-09-29)" })
    .option("purl-file", { type: "string", describe: "Path to file with PURL queries (one per line; supports version ranges & wildcards; # or // for comments)" })
    .option("json", { type: "boolean", describe: "Emit search results as JSON to stdout (suppresses human output unless --cli also provided)" })
    .option("cli", { type: "boolean", describe: "When used with --json, also emit human-readable CLI output" })
    .option("output-file", { type: "string", describe: "Write search JSON/CSV output to this file. Required when using --cli with JSON/CSV." })
    .option("csv", { type: "boolean", describe: "Emit results (search + malware matches) as CSV" })
    .option("ignore-file", { type: "string", describe: "Path to YAML ignore file (advisories, purls, scoped ignores)" })
    .option("ignore-unbounded-malware", { type: "boolean", default: false, describe: "Ignore malware advisories whose vulnerable range covers all versions (e.g. '*', '>=0')" })
    .option("branch-scan", { type: "boolean", default: false, describe: "Fetch SBOM diffs for non-default branches (limited by --branch-limit)" })
    .option("branch-limit", { type: "number", default: undefined, describe: "Limit number of non-default branches to scan per repository" })
    .option("diff-base", { type: "string", describe: "Override base branch for dependency review diffs (defaults to default branch)" })
    .option("submit-on-missing-snapshot", { type: "boolean", default: false, describe: "When dependency review diff returns 404 (missing snapshot), run Component Detection to submit a snapshot, then retry." })
    .option("submit-languages", { type: "array", describe: "Limit snapshot submission to these languages (e.g., JavaScript,TypeScript,Python,Maven)." })
    .option("component-detection-bin", { type: "string", describe: "Path to a local component-detection executable to use for snapshot submission (skips download)." })
    .option("force-submission", { type: "boolean", default: false, describe: "Always run Dependency Submission for scanned branches before fetching diffs." })
    .option("debug", { type: "boolean", default: false, describe: "Enable debug logging" })
    .check(args => {
      const syncing = !!args.syncSboms;
      if (syncing) {
        if (!args.enterprise && !args.org && !args.repo) throw new Error("Provide --enterprise, --org or --repo with --sync-sboms");
        if (args.enterprise && args.org) throw new Error("Specify only one of --enterprise or --org");
        if (args.repo && (args.enterprise || args.org)) throw new Error("Specify only one of --enterprise, --org, or --repo");
        if (args.repo && !(args.repo as string).includes("/")) throw new Error("--repo must be in the format owner/repo");
        if (syncing && !args.sbomCache) throw new Error("--sync-sboms requires --sbom-cache to write updated SBOMs to disk");
      } else {
        const malwareOnly = !!args["sync-malware"] && !args.sbomCache && !args.purl && !args["purl-file"] && !args["match-malware"] && !args.uploadSarif && !args.interactive;
        if (!malwareOnly && !args.sbomCache) throw new Error("Offline mode requires --sbom-cache unless running --sync-malware by itself");
      }
      // If --cli is specified in combination with JSON or CSV, require an output file to avoid mixed stdout streams.
      if (args.cli && !args.outputFile && (args.json || args.csv)) {
        throw new Error("--cli with --json or --csv requires --output-file to avoid interleaving JSON and human output on stdout.");
      }
      // check that --malware-cache is provided
      if (args["match-malware"] && !args["malware-cache"]) {
        throw new Error("--match-malware must be used with --malware-cache to provide advisories to match against.")
      }
      if (args["sync-malware"] && !args["malware-cache"]) {
        throw new Error("--sync-malware must be used with --malware-cache to store advisories.")
      }
      if (args.uploadSarif && !args["match-malware"]) {
        throw new Error("--upload-sarif requires --match-malware to generate findings.");
      }
      if (args.uploadSarif && !args.sarifDir) {
        throw new Error("--upload-sarif requires --sarif-dir to write SARIF files prior to upload.");
      }
      if (args.csv && args.json) {
        throw new Error("Use one of --json or --csv")
      }
      return true;
    })
    .help()
    .parseAsync();

  const debug = argv.debug as boolean;

  if (debug) {
    console.debug(chalk.blue("Debug logging enabled"));
  } else {
    console.debug = () => { };
  }

  const token = argv.token as string | undefined || process.env.GITHUB_TOKEN;

  // Require a token for any network operation (syncing SBOMs, malware advisories, or SARIF upload)
  if (argv.syncSboms || argv["sync-malware"] || argv.uploadSarif) {
    if (!token) {
      console.error(chalk.red("GitHub token must be provided via --token or GITHUB_TOKEN environment variable"));
      process.exit(1);
    }
  }

  const offline = !argv.syncSboms;
  const quiet = argv.quiet as boolean;
  const wantJson = !!argv.json;
  const wantCsv = !!argv.csv;
  const hasOutputFile = !!argv.outputFile;
  const wantCli = !!argv.cli && hasOutputFile; // only allow CLI alongside machine output when writing file

  let sboms: RepositorySbom[] = [];
  let summary: CollectionSummary | undefined;

  const needCollector = !!argv.syncSboms || !!argv.sbomCache || !!argv.purl || !!argv["purl-file"] || !!argv["match-malware"] || !!argv.uploadSarif || !!argv.interactive;
  const collector = needCollector ? new SbomCollector({
    token: token,
    enterprise: argv.enterprise as string | undefined,
    org: argv.org as string | undefined,
    repo: argv.repo as string | undefined,
    baseUrl: argv["base-url"] as string | undefined,
    ghes: argv.ghes as boolean | undefined,
    concurrency: argv.concurrency as number,
    delayMsBetweenRepos: argv["sbom-delay"] as number,
    lightDelayMs: argv["light-delay"] as number,
    loadFromDir: argv["sbom-cache"] as string | undefined,
    syncSboms: argv.syncSboms as boolean,
    showProgressBar: argv.progress as boolean,
    suppressSecondaryRateLimitLogs: argv.suppressSecondaryRateLimitLogs as boolean,
    quiet,
    caBundlePath: argv["ca-bundle"] as string | undefined,
    includeBranches: argv["branch-scan"] as boolean,
    branchLimit: argv["branch-limit"] as number | undefined,
    branchDiffBase: argv["diff-base"] as string | undefined,
    submitOnMissingSnapshot: argv["submit-on-missing-snapshot"] as boolean,
    forceSubmission: argv["force-submission"] as boolean,
    submitLanguages: (argv["submit-languages"] as string[] | undefined) || undefined,
    componentDetectionBinPath: argv["component-detection-bin"] as string | undefined,
  }) : undefined;

  if (collector && (argv.sbomCache || argv.syncSboms)) {
    if (!quiet) process.stderr.write(chalk.cyan(offline ? "Loading SBOMs from cache..." : "Collecting SBOMs from cache & GitHub...") + "\n");
    sboms = await collector.collect();
    summary = collector.getSummary();
    if (!quiet) process.stderr.write(chalk.green(`Done. Success: ${summary.successCount} / ${summary.repositoryCount}. Failed: ${summary.failedCount}. Cached: ${summary.skippedCount}`) + "\n");
  }

  const mas = new MalwareAdvisorySync({
    token: token!,
    baseUrl: argv["base-url"] ? (argv["base-url"] as string).replace(/\/v3$/, "/graphql") : undefined,
    cacheDir: argv["malware-cache"] as string | undefined,
    since: argv["malware-since"] as string | undefined,
    caBundlePath: argv["ca-bundle"] as string | undefined,
    quiet
  });

  if (argv.syncMalware) {
    if (!quiet) process.stderr.write(chalk.cyan("Syncing malware advisories from GitHub Advisory Database...") + "\n");

    const { added, updated, total } = await mas.sync();
    if (!quiet) process.stderr.write(chalk.green(`Malware advisories sync complete. Added: ${added}, Updated: ${updated}, Total cached: ${total}`) + "\n");
  }

  let malwareMatches: MalwareMatch[] = [];

  if (argv["match-malware"]) {
    const { matchMalware, buildSarifPerRepo, writeSarifFiles, uploadSarifPerRepo } = await import("./malwareMatcher.js");
    malwareMatches = matchMalware(mas.getAdvisories(), sboms, { advisoryDateCutoff: argv["malware-cutoff"] as string | undefined });
    // Optional suppression of unbounded version-range advisories
    if (argv["ignore-unbounded-malware"] && malwareMatches?.length) {
      const before = malwareMatches.length;
      const isUnbounded = (range: string | null) => {
        if (!range) return false;
        const r = range.trim();
        if (r === "*") return true;
        const compact = r.replace(/\s+/g, "");
        return /^(>=|>=?) ?0(\.0){0,2}$/i.test(compact); // '>=0', '>0', '0', '0.0.0'
      };
      malwareMatches = malwareMatches.filter(m => !isUnbounded(m.vulnerableVersionRange));
      if (!quiet) process.stderr.write(chalk.yellow(`Filtered ${before - malwareMatches.length} unbounded-range malware match(es)`) + "\n");
    }
    // Apply ignore file if provided
    if (argv["ignore-file"] && malwareMatches?.length) {
      try {
        const { IgnoreMatcher } = await import("./ignore.js");
        const matcher = IgnoreMatcher.load(argv["ignore-file"] as string, {});
        if (matcher) {
          const { kept, ignored } = matcher.filter(malwareMatches);
          if (!argv.quiet) {
            process.stderr.write(chalk.yellow(`Ignored ${ignored.length} malware match(es) via ignore file; ${kept.length} remaining.`) + "\n");
          }
          malwareMatches = kept;
          // If writing SARIF we intentionally only report kept matches; optionally we could emit a log of ignored reasons.
        } else if (!argv.quiet) {
          process.stderr.write(chalk.yellow(`Ignore file '${argv["ignore-file"]}' not found or failed to parse; proceeding without filtering.`) + "\n");
        }
      } catch (e) {
        console.error(chalk.red(`Failed applying ignore file: ${(e as Error).message}`));
      }
    }
    if (!quiet) process.stderr.write(chalk.magenta(`Malware matches found: ${malwareMatches?.length ?? 0}`) + "\n");
    if (malwareMatches) {
      const showMalwareCli = (!wantJson && !wantCsv) || wantCli; // show only in pure CLI or combined mode
      if (showMalwareCli && !quiet) {
        for (const m of malwareMatches) {
          const branchInfo = m.branch ? ` [branch: ${m.branch}]` : "";
          process.stdout.write(`${m.repo} :: ${m.purl} => ${m.advisoryGhsaId} (${m.vulnerableVersionRange ?? "(no range)"}){advisory: ${m.reason}}${branchInfo} ${m.advisoryPermalink}\n`);
        }
      }
      if (argv.sarifDir) {
        const sarifMap = buildSarifPerRepo(malwareMatches, mas.getAdvisories());
        writeSarifFiles(argv.sarifDir as string, sarifMap);
        if (sarifMap.size === 0) {
          if (!quiet) process.stderr.write(chalk.yellow("No SARIF files generated.") + "\n");
          return;
        }
        if (!quiet) process.stderr.write(chalk.green(`Wrote SARIF for ${sarifMap.size} repos to ${argv.sarifDir}`) + "\n");
        if (argv.uploadSarif) {
          if (!token) console.error(chalk.red("Token required for SARIF upload"));
          else await uploadSarifPerRepo({ sarifDir: argv.sarifDir as string, matches: malwareMatches, advisories: mas.getAdvisories(), sboms, token, baseUrl: argv["base-url"] as string | undefined, caBundlePath: argv["ca-bundle"] as string | undefined });
        }
      }
    }
  }

  const runSearchCli = (purls: string[], results: Map<string, { purl: string; reason: string }[]>) => {
    if (!results.size) {
      process.stdout.write("No matches.\n");
      return;
    }
    if (!quiet) process.stderr.write(chalk.magenta(`Search results for ${purls.length} purl(s):`) + "\n");
    for (const [repo, entries] of results.entries()) {
      process.stdout.write(chalk.bold(repo) + "\n");
      for (const { purl, reason } of entries) process.stdout.write(`  - ${purl} {query: ${reason}}\n`);
    }
  };
  // Load queries from file if provided
  const filePurls: string[] = [];
  if (argv["purl-file"]) {
    try {
      const fs = await import("fs");
      const raw = fs.readFileSync(argv["purl-file"] as string, "utf8");
      for (const lineRaw of raw.split(/\r?\n/)) {
        const line = lineRaw.trim();
        if (!line || line.startsWith("#")) continue;
        filePurls.push(line);
      }
      if (filePurls.length && !quiet) process.stderr.write(chalk.cyan(`Loaded ${filePurls.length} PURL query(ies) from file`) + "\n");
    } catch (e) {
      console.error(chalk.red(`Failed to read purl file: ${e instanceof Error ? e.message : String(e)}`));
      process.exit(1);
    }
  }
  const combinedPurlsRaw = [...(argv.purl as string[] ?? []), ...filePurls];
  const combinedPurls = combinedPurlsRaw.map(p => p.startsWith("pkg:") ? p : `pkg:${p}`);

  let searchMap: Map<string, { purl: string; reason: string }[]> | undefined;
  if (combinedPurls.length && collector) {
    searchMap = collector.searchByPurlsWithReasons(combinedPurls);
  }

  if (wantJson) {
    const jsonSearch = Array.from((searchMap || new Map()).entries()).map(([repo, entries]) => ({ repo, matches: entries }));
    if (hasOutputFile) {
      try {
        let existing: { search?: unknown; malwareMatches?: MalwareMatch[] } = {};
        if (fs.existsSync(argv.outputFile as string)) {
          try { existing = JSON.parse(fs.readFileSync(argv.outputFile as string, "utf8")); } catch { existing = {}; }
        }
        existing.search = jsonSearch;
        if (malwareMatches) existing.malwareMatches = existing.malwareMatches || malwareMatches;
        fs.writeFileSync(argv.outputFile as string, JSON.stringify(existing, null, 2) + "\n", "utf8");
        if (!quiet) process.stderr.write(chalk.green(`Wrote search JSON to ${argv.outputFile}`) + "\n");
      } catch (e) {
        console.error(chalk.red(`Failed to write output file: ${(e as Error).message}`));
        process.exit(1);
      }
    } else {
      const payloadObj: { search: unknown; malwareMatches?: import("./malwareMatcher.js").MalwareMatch[] } = { search: jsonSearch };
      if (malwareMatches) payloadObj.malwareMatches = malwareMatches;
      process.stdout.write(JSON.stringify(payloadObj, null, 2) + "\n");
    }
    if (wantCli && searchMap) runSearchCli(combinedPurls, searchMap);
  } else if (wantCsv) {
    // CSV output section (covers search results and malware matches if present)
    const fs = await import("fs");
    // Collect search data if searches were run; reconstruct from collector if we have combinedPurls
    const searchRows: Array<{ repo: string; purl: string; reason: string }> = [];
    if (combinedPurls.length && searchMap) {
      for (const [repo, entries] of searchMap.entries()) {
        for (const { purl, reason } of entries) searchRows.push({ repo, purl, reason });
      }
    }
    const malwareRows: Array<{ repo: string; purl: string; advisory: string; range: string | null; updatedAt: string; branch: string | undefined }> = [];
    if (malwareMatches) {
      for (const m of malwareMatches) {
        malwareRows.push({ repo: m.repo, purl: m.purl, advisory: m.advisoryGhsaId, range: m.vulnerableVersionRange, updatedAt: m.advisoryUpdatedAt, branch: m.branch });
      }
    }
    // CSV columns: type,repo,purl,reason_or_advisory,range,updatedAt
    const header = ["type", "repo", "purl", "reason_or_advisory", "range", "updatedAt", "branch"];
    const sanitize = (val: unknown): string => {
      if (val === null || val === undefined) return "";
      let s = String(val);
      // Neutralize leading characters that can trigger spreadsheet formula execution
      if (/^[=+\-@]/.test(s)) s = "'" + s; // prefix apostrophe to neutralize
      // Escape quotes for CSV
      if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    const lines: string[] = [header.join(",")];
    for (const r of searchRows) {
      lines.push([
        "search",
        sanitize(r.repo),
        sanitize(r.purl),
        sanitize(r.reason),
        "",
        ""
      ].join(","));
    }
    for (const r of malwareRows) {
      lines.push([
        "malware",
        sanitize(r.repo),
        sanitize(r.purl),
        sanitize(r.advisory),
        sanitize(r.range ?? ""),
        sanitize(r.updatedAt),
        sanitize(r.branch ?? "")
      ].join(","));
    }
    const csvPayload = lines.join("\n") + "\n";
    if (hasOutputFile) {
      try {
        fs.writeFileSync(argv.outputFile as string, csvPayload, "utf8");
        if (!quiet) process.stderr.write(chalk.green(`Wrote CSV to ${argv.outputFile}`) + "\n");
      } catch (e) {
        console.error(chalk.red(`Failed to write CSV file: ${e instanceof Error ? e.message : String(e)}`));
        process.exit(1);
      }
    } else {
      process.stdout.write(csvPayload);
    }
    if (wantCli && searchMap) runSearchCli(combinedPurls, searchMap);
  } else if (combinedPurls.length && searchMap) {
    // Pure CLI (no json/csv)
    runSearchCli(combinedPurls, searchMap);
  }

  // If malware matches were computed but no search JSON writing happened yet and an output file was requested, persist them now.
  if (malwareMatches && argv.outputFile) {
    const fs = await import("fs");
    try {
      let existing: { search?: unknown; malwareMatches?: import("./malwareMatcher.js").MalwareMatch[] } = {};
      if (fs.existsSync(argv.outputFile as string)) {
        try { existing = JSON.parse(fs.readFileSync(argv.outputFile as string, "utf8")); } catch { existing = {}; }
      }
      existing.malwareMatches = malwareMatches;
      fs.writeFileSync(argv.outputFile as string, JSON.stringify(existing, null, 2) + "\n", "utf8");
      if (!quiet) process.stderr.write(chalk.green(`Wrote malware matches JSON to ${argv.outputFile}`) + "\n");
    } catch (e) {
      console.error(chalk.red(`Failed to write malware matches to output file: ${e instanceof Error ? e.message : String(e)}`));
    }
  }

  if (argv.interactive) {
    // Prefer readline for native shell history (arrow up/down) so users can edit previous queries.
    if (process.stdin.isTTY && process.stdout.isTTY) {
      if (!quiet) {
        process.stderr.write(chalk.cyan("Interactive mode: enter PURL queries (supports semver ranges, wildcards, version ranges).") + "\n");
        process.stderr.write(chalk.cyan("Tips: Use arrow keys for history. Blank line or Ctrl+C on empty prompt exits. Ctrl+C on a non-empty line clears it.") + "\n");
      }
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        historySize: 2000,
        prompt: "purl> ",
        removeHistoryDuplicates: true
      });

      const closeGracefully = () => {
        rl.close();
      };

      rl.on("SIGINT", () => {
        // If current line is empty, exit. Else clear the line to allow quick re-entry.
        if (!rl.line) {
          process.stdout.write("\n");
          closeGracefully();
        } else {
          // Clear current input line
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore - write with control sequence to clear
          rl.write(null, { name: 'u', ctrl: true });
          rl.prompt();
        }
      });

      rl.on("line", (line: string) => {
        const trimmed = line.trim();
        if (!trimmed) {
          closeGracefully();
          return;
        }
        const list = trimmed.split(/[\s,]+/).filter(Boolean);
        try {
          if (!collector) {
            console.error(chalk.red("Interactive search requires SBOMs; provide --sbom-cache or run with --sync-sboms."));
            rl.prompt();
            return;
          }
          const map = collector.searchByPurlsWithReasons(list.map(p => p.startsWith("pkg:") ? p : `pkg:${p}`));
          runSearchCli(list, map);
        } catch (e) {
          console.error(chalk.red((e as Error).message));
        }
        rl.prompt();
      });

      rl.on("close", () => { if (!quiet) console.log(chalk.cyan("Exiting interactive mode.")); });

      rl.prompt();
      await new Promise<void>(resolve => rl.once("close", resolve));
    } else {
      // Fallback to inquirer if not a TTY
      for (; ;) {
        const ans = await inquirer.prompt<{ purl: string }>([
          { name: "purl", message: "Enter a PURL (blank to exit)", type: "input" }
        ]);
        if (!ans.purl) break;
        if (!collector) {
          console.error(chalk.red("Interactive search requires SBOMs; provide --sbom-cache or run with --sync-sboms."));
          continue;
        }
        const map = collector.searchByPurlsWithReasons([ans.purl.startsWith("pkg:") ? ans.purl : `pkg:${ans.purl}`]);
        runSearchCli([ans.purl], map);
      }
    }
  }
}

main().catch(err => {
  console.error(chalk.red(err.stack || err.message));
  process.exit(1);
});
