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
    .option("sbom-cache", { type: "string", describe: "Directory to read/write cached SBOM JSON files" })
    .option("purl", { type: "array", describe: "One or more PURL strings to search (supports suffix * wildcard after slash)" })
    .option("sync-sboms", { type: "boolean", default: false, describe: "Fetch SBOMs from GitHub (write to --sbom-cache if provided) instead of offline-only" })
    .option("interactive", { type: "boolean", default: false, describe: "Enter interactive PURL search mode after collection" })
    .option("sync-malware", { type: "boolean", default: false, describe: "Sync malware advisories (MALWARE classification) to local cache" })
    .option("malware-cache", { type: "string", default: "malware-cache", describe: "Directory to store malware advisory cache" })
    .option("malware-since", { type: "string", describe: "Override last sync timestamp (ISO) for malware advisory incremental sync" })
    .option("match-malware", { type: "boolean", default: false, describe: "After sync/load, match SBOM packages against malware advisories" })
    .option("sarif-dir", { type: "string", describe: "Directory to write SARIF 2.1.0 files (one per repository) when --match-malware is used" })
    .option("upload-sarif", { type: "boolean", default: false, describe: "Upload generated SARIF (per-repo) to the Code Scanning API (requires --match-malware)" })
    .option("purl-file", { type: "string", describe: "Path to file with PURL queries (one per line; supports version ranges & wildcards; # or // for comments)" })
    .option("json", { type: "boolean", describe: "Emit search results as JSON to stdout (suppresses human output unless --cli also provided)" })
    .option("cli", { type: "boolean", describe: "When used with --json, also emit human-readable CLI output" })
    .option("output-file", { type: "string", describe: "Write search JSON output to this file (implied JSON generation). Required when using --cli with JSON." })
    .check(args => {
      const syncing = !!args.syncSboms;
      if (syncing) {
        if (!args.enterprise && !args.org) throw new Error("Provide --enterprise or --org with --sync-sboms");
        if (args.enterprise && args.org) throw new Error("Specify only one of --enterprise or --org");
      } else {
        if (!args.sbomCache) throw new Error("Offline mode requires --sbom-cache (omit --sync-sboms)");
      }
      // If --cli is specified in combination intending JSON, require an output file to avoid mixed stdout streams.
      if (args.cli && !args.outputFile && !args.json) {
        throw new Error("--cli provided without --json/--output-file. Use --json --cli --output-file <path> to emit both.");
      }
      if (args.cli && !args.outputFile && args.json) {
        throw new Error("--cli with --json requires --output-file to avoid interleaving JSON and human output on stdout.");
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
      return true;
    })
    .help()
    .parseAsync();

  const token = argv.token as string | undefined || process.env.GITHUB_TOKEN;

  if (argv.sbom || argv["sync-malware"] || argv.uploadSarif) {
    if (!token) {
      console.error(chalk.red("GitHub token must be provided via --token or GITHUB_TOKEN environment variable"));
      process.exit(1);
    }
  }

  const offline = !argv.syncSboms;
  const collector = new SbomCollector({
    token: token,
    enterprise: argv.enterprise as string | undefined,
    org: argv.org as string | undefined,
    baseUrl: argv["base-url"] as string | undefined,
    concurrency: argv.concurrency as number,
    delayMsBetweenRepos: argv.delay as number,
    loadFromDir: argv["sbom-cache"] as string | undefined,
    syncSboms: argv.syncSboms as boolean,
  });

  console.log(chalk.cyan(offline ? "Loading SBOMs from cache..." : "Collecting SBOMs from cache & GitHub..."));
  const sboms = await collector.collect();
  const summary = collector.getSummary();
  console.log(chalk.green(`Done. Success: ${summary.successCount} / ${summary.repositoryCount}. Failed: ${summary.failedCount}. Cached: ${summary.skippedCount}`));

  const mas = new MalwareAdvisorySync({
    token: token!,
    baseUrl: argv["base-url"] ? (argv["base-url"] as string).replace(/\/v3$/, "/graphql") : undefined,
    cacheDir: argv["malware-cache"] as string | undefined,
    since: argv["malware-since"] as string | undefined
  });

  if (argv["sync-malware"]) {

    console.log(chalk.cyan("Syncing malware advisories from GitHub Advisory Database..."));

    const { added, updated, total } = await mas.sync();
    console.log(chalk.green(`Malware advisories sync complete. Added: ${added}, Updated: ${updated}, Total cached: ${total}`));
  }

  let malwareMatches: import("./malwareMatcher.js").MalwareMatch[] | undefined;
  if (argv["match-malware"]) {
    const { matchMalware, buildSarifPerRepo, writeSarifFiles, uploadSarifPerRepo } = await import("./malwareMatcher.js");
    malwareMatches = matchMalware(mas.getAdvisories(), sboms);
    console.log(chalk.magenta(`Malware matches found: ${malwareMatches?.length ?? 0}`));
    if (malwareMatches) {
      for (const m of malwareMatches) {
        console.log(`${m.repo} :: ${m.purl} => ${m.advisoryGhsaId} (${m.vulnerableVersionRange ?? "(no range)"}) {advisory: ${m.reason}} ${m.advisoryPermalink}`);
      }
      if (argv.sarifDir) {
        const sarifMap = buildSarifPerRepo(malwareMatches, mas.getAdvisories());
        writeSarifFiles(argv.sarifDir as string, sarifMap);
        if (sarifMap.size === 0) {
          console.log(chalk.yellow("No SARIF files generated."));
          return;
        }
        console.log(chalk.green(`Wrote SARIF for ${sarifMap.size} repos to ${argv.sarifDir}`));
        if (argv.uploadSarif) {
          if (!token) console.error(chalk.red("Token required for SARIF upload"));
          else await uploadSarifPerRepo({ sarifDir: argv.sarifDir as string, matches: malwareMatches, advisories: mas.getAdvisories(), sboms, token, baseUrl: argv["base-url"] as string | undefined });
        }
      }
    }
  }
  if (argv.syncSboms && argv["sbom-cache"] && summary.skippedCount != summary.repositoryCount) {
    writeAll(sboms, { outDir: argv["sbom-cache"] as string });
    console.log(chalk.blue(`Wrote SBOM JSON to cache directory ${argv["sbom-cache"]}`));
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
    const needJson = argv.json || argv.outputFile;
    if (needJson) {
      const map = collector.searchByPurlsWithReasons(combinedPurls);
      const jsonSearch = Array.from(map.entries()).map(([repo, entries]) => ({ repo, matches: entries }));
      if (argv.outputFile) {
        try {
          const fs = await import("fs");
          let existing: { search?: unknown; malwareMatches?: import("./malwareMatcher.js").MalwareMatch[] } = {};
          if (fs.existsSync(argv.outputFile as string)) {
            try { existing = JSON.parse(fs.readFileSync(argv.outputFile as string, "utf8")); } catch { existing = {}; }
          }
          existing.search = jsonSearch;
          if (malwareMatches) existing.malwareMatches = existing.malwareMatches || malwareMatches; // preserve if already set
          const payload = JSON.stringify(existing, null, 2) + "\n";
          fs.writeFileSync(argv.outputFile as string, payload, "utf8");
          console.log(chalk.green(`Wrote search JSON to ${argv.outputFile}`));
        } catch (e) {
          console.error(chalk.red(`Failed to write output file: ${e instanceof Error ? e.message : String(e)}`));
          process.exit(1);
        }
      } else if (argv.json) {
  const payloadObj: { search: unknown; malwareMatches?: import("./malwareMatcher.js").MalwareMatch[] } = { search: jsonSearch };
        if (malwareMatches) payloadObj.malwareMatches = malwareMatches;
        process.stdout.write(JSON.stringify(payloadObj, null, 2) + "\n");
      }
      // If CLI output requested (either implicit because no --json OR explicit --cli with output-file requirement) then show human form
      if (!needJson || (argv.cli && needJson)) {
        runSearch(combinedPurls);
      } else if (argv.cli) { // This branch only occurs when validation prevented missing output-file
        runSearch(combinedPurls);
      }
    } else {
      // Pure CLI
      runSearch(combinedPurls);
    }
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
      console.log(chalk.green(`Wrote malware matches JSON to ${argv.outputFile}`));
    } catch (e) {
      console.error(chalk.red(`Failed to write malware matches to output file: ${e instanceof Error ? e.message : String(e)}`));
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
        const ans = await inquirer.prompt<{ purl: string }>([
          { name: "purl", message: "Enter a PURL (blank to exit)", type: "input" }
        ]);
        if (!ans.purl) break;
        runSearch([ans.purl]);
      }
    }
  }
}

main().catch(err => {
  console.error(chalk.red(err.stack || err.message));
  process.exit(1);
});
