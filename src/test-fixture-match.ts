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
console.log("Matches:");
for (const m of matches) {
  console.log(`${m.repo} => ${m.purl} matched advisory ${m.advisoryGhsaId} range ${m.vulnerableVersionRange}`);
}
if (!matches.length) {
  console.error("No matches found - expected chalk 5.6.1");
  process.exit(1);
}
