#!/usr/bin/env node
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import chalk from "chalk";
import { SbomCollector } from "./sbomCollector.js";
import { writeAll } from "./serialization.js";
import inquirer from "inquirer"; // still used elsewhere if needed
import readline from "readline";
const { MalwareAdvisorySync } = await import("./malwareAdvisories.js");

async function main() {
  const argv = await yargs(hideBin(process.argv))
    .scriptName("gh-sbom-collector")
    .option("token", { type: "string", describe: "GitHub token with repo + security_events scope" })
    .option("enterprise", { type: "string", describe: "Enterprise slug (mutually exclusive with --org)" })
    .option("org", { type: "string", describe: "Single organization login" })
    .option("base-url", { type: "string", describe: "GitHub Enterprise Server base URL, e.g. https://github.mycompany.com/api/v3" })
    .option("concurrency", { type: "number", default: 5 })
    .option("delay", { type: "number", default: 0, describe: "Delay milliseconds between repository SBOM requests" })
    .option("out", { type: "string", describe: "Directory to serialize SBOM JSON files" })
    .option("purl", { type: "array", describe: "One or more PURL strings to search (supports suffix * wildcard after slash)" })
    .option("load", { type: "string", describe: "Directory of previously serialized SBOM JSON files to load instead of fetching" })
    .option("interactive", { type: "boolean", default: false, describe: "Enter interactive PURL search mode after collection" })
    .option("sync-malware", { type: "boolean", default: false, describe: "Sync malware advisories (MALWARE classification) to local cache" })
    .option("malware-cache", { type: "string", default: "malware-cache", describe: "Directory to store malware advisory cache" })
    .option("malware-since", { type: "string", describe: "Override last sync timestamp (ISO) for malware advisory incremental sync" })
    .option("match-malware", { type: "boolean", default: false, describe: "After sync/load, match SBOM packages against malware advisories" })
    .option("malware-report", { type: "string", describe: "If set, write malware match results (JSON array) to this file when --match-malware is used" })
    .option("purl-file", { type: "string", describe: "Path to file with PURL queries (one per line; supports version ranges & wildcards; # or // for comments)" })
    .option("incremental", { type: "boolean", default: false, describe: "Skip SBOM fetch for repos whose pushed_at has not advanced vs baseline" })
    .option("baseline", { type: "string", describe: "Directory of prior SBOM JSON files used as baseline for --incremental" })
    .option("json", { type: "boolean", describe: "Emit search results as JSON to stdout (suppresses human output unless --cli also provided)" })
    .option("cli", { type: "boolean", describe: "When used with --json, also emit human-readable CLI output" })
    .check(args => {
      if (!args.load) {
        if (!args.enterprise && !args.org) throw new Error("Provide --enterprise or --org (or --load)\n");
        if (args.enterprise && args.org) throw new Error("Specify only one of --enterprise or --org");
      }
      return true;
    })
    .help()
    .parseAsync();

  const token = argv.token as string | undefined || process.env.GITHUB_TOKEN;

  if (argv.sbom || argv["sync-malware"]) {
    if (!token) {
      console.error(chalk.red("GitHub token must be provided via --token or GITHUB_TOKEN environment variable"));
      process.exit(1);
    }
  }

  const collector = new SbomCollector({
    token: token,
    enterprise: argv.enterprise as string | undefined,
    org: argv.org as string | undefined,
    baseUrl: argv["base-url"] as string | undefined,
    concurrency: argv.concurrency as number,
    delayMsBetweenRepos: argv.delay as number,
    loadFromDir: argv.load as string | undefined,
    incremental: argv.incremental as boolean,
    baselineDir: argv.baseline as string | undefined
  });

  console.log(chalk.cyan(collector['opts'].loadFromDir ? "Loading SBOMs..." : "Collecting SBOMs..."));
  const sboms = await collector.collect();
  const summary = collector.getSummary();
  console.log(chalk.green(`Done. Success: ${summary.successCount} / ${summary.repositoryCount}. Failed: ${summary.failedCount}. Skipped: ${summary.skippedCount}`));

  const mas = new MalwareAdvisorySync({
    token: token!,
    baseUrl: argv["base-url"] ? (argv["base-url"] as string).replace(/\/v3$/, "/graphql") : undefined,
    cacheDir: argv["malware-cache"] as string | undefined,
    since: argv["malware-since"] as string | undefined
  });

  if (argv["sync-malware"]) {

    console.log(chalk.cyan("Syncing malware advisories..."));

    const { added, updated, total } = await mas.sync();
    console.log(chalk.green(`Malware advisories sync complete. Added: ${added}, Updated: ${updated}, Total cached: ${total}`));
  }

  if (argv["match-malware"]) {
    const { matchMalware } = await import("./malwareMatcher.js");
    const matches = matchMalware(mas.getAdvisories(), sboms);
    console.log(chalk.magenta(`Malware matches found: ${matches.length}`));
    for (const m of matches) {
      console.log(`${m.repo} :: ${m.purl} => ${m.advisoryGhsaId} (${m.vulnerableVersionRange}) {advisory: ${m.reason}} ${m.advisoryPermalink}`);
    }
    if (argv["malware-report"]) {
      const fs = await import("fs");
      const outPath = argv["malware-report"] as string;
      try {
        fs.writeFileSync(outPath, JSON.stringify(matches, null, 2), "utf8");
        console.log(chalk.green(`Wrote malware match report to ${outPath}`));
      } catch (e) {
        console.error(chalk.red(`Failed to write malware report: ${e instanceof Error ? e.message : String(e)}`));
      }
    }
  }
  if (argv.out) {
    console.log(`Writing SBOM JSON to ${argv.out}`);
    writeAll(sboms, { outDir: argv.out as string });
  }

  const runSearch = (purls: string[]) => {
    const results = collector.searchByPurlsWithReasons(purls);
    console.log(chalk.magenta(`Search results for ${purls.length} purl(s):`));
    if (!results.size) {
      console.log("No matches.");
      return;
    }
    for (const [repo, entries] of results.entries()) {
      console.log(chalk.bold(repo));
      for (const { purl, reason } of entries) console.log(`  - ${purl} {query: ${reason}}`);
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
      if (filePurls.length) {
        console.log(chalk.cyan(`Loaded ${filePurls.length} PURL query(ies) from file`));
      }
    } catch (e) {
      console.error(chalk.red(`Failed to read purl file: ${e instanceof Error ? e.message : String(e)}`));
      process.exit(1);
    }
  }
  const combinedPurlsRaw = [...(argv.purl as string[] ?? []), ...filePurls];
  const combinedPurls = combinedPurlsRaw.map(p => p.startsWith("pkg:") ? p : `pkg:${p}`);
  if (combinedPurls.length) {
    if (argv.json) {
      // Build JSON structure of search results with reasons
      const map = collector.searchByPurlsWithReasons(combinedPurls);
      const json = Array.from(map.entries()).map(([repo, entries]) => ({ repo, matches: entries }));
      process.stdout.write(JSON.stringify({ search: json }, null, 2) + "\n");
      if (argv.cli) {
        runSearch(combinedPurls); // also emit human-readable form
      }
    } else {
      runSearch(combinedPurls);
    }
  }

  if (argv.interactive) {
    // Prefer readline for native shell history (arrow up/down) so users can edit previous queries.
    if (process.stdin.isTTY && process.stdout.isTTY) {
      console.log(chalk.cyan("Interactive mode: enter PURL queries (supports semver ranges, wildcards, version ranges)."));
      console.log(chalk.cyan("Tips: Use arrow keys for history. Blank line or Ctrl+C on empty prompt exits. Ctrl+C on a non-empty line clears it."));
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
          runSearch(list);
        } catch (e) {
          console.error(chalk.red((e as Error).message));
        }
        rl.prompt();
      });

      rl.on("close", () => {
        console.log(chalk.cyan("Exiting interactive mode."));
      });

      rl.prompt();
      await new Promise<void>(resolve => rl.once("close", resolve));
    } else {
      // Fallback to inquirer if not a TTY
      for (; ;) {
        const ans = await inquirer.prompt<{ purls: string }>([
          { name: "purls", message: "Enter comma-separated PURLs (blank to exit)", type: "input" }
        ]);
        if (!ans.purls) break;
        const list = ans.purls.split(/[\s,]+/).filter(Boolean);
        runSearch(list);
      }
    }
  }
}

main().catch(err => {
  console.error(chalk.red(err.stack || err.message));
  process.exit(1);
});
