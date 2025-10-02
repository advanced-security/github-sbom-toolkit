import { readAll } from "./serialization.js";
import { matchMalware } from "./malwareMatcher.js";
import { MalwareAdvisoryNode } from "./malwareAdvisories.js";
import fs from "fs";
import path from "path";

// Load SBOM fixture
const sboms = readAll(path.join(process.cwd(), "fixtures/sboms"));
// Load malware advisory fixture
const cachePath = path.join(process.cwd(), "fixtures/malware-cache/malware-advisories.json");
const cache = JSON.parse(fs.readFileSync(cachePath, "utf8"));
const advisories: MalwareAdvisoryNode[] = cache.advisories;

const matches = matchMalware(advisories, sboms);
process.stdout.write("Matches:\n");
for (const m of matches) {
  process.stdout.write(`${m.repo} => ${m.purl} matched advisory ${m.advisoryGhsaId} range ${m.vulnerableVersionRange}\n`);
}
if (!matches.length) {
  console.error("No matches found - expected chalk 5.6.1");
  process.exit(1);
}
