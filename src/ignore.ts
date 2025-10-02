import fs from "fs";
import path from "path";
import * as semver from "semver";
import { MalwareMatch } from "./malwareMatcher.js";
import YAML from "yaml";

/**
 * Ignore file schema (YAML)
 *
 * Example:
 * ---
 * # Ignore by advisory id everywhere
 * advisories:
 *   - GHSA-xxxx-yyyy-zzzz
 *
 * # Ignore by PURL (any version) or version range
 * purls:
 *   - pkg:npm/lodash  # ignore any version
 *   - pkg:npm/react@>=18.0.0 <18.3.0  # ignore a version range
 *
 * # Scoped ignores (repo full name or org). If provided, the ignore only applies within those repos/orgs.
 * scoped:
 *   - scope: my-org            # applies to every repo in org
 *     advisories: [GHSA-1111-2222-3333]
 *   - scope: my-org/my-repo    # applies only to that repository
 *     purls:
 *       - pkg:maven/org.example/app@1.2.3
 */
export interface IgnoreFileRoot {
  advisories?: string[];
  purls?: string[]; // each may have optional version/range after @
  scoped?: Array<ScopedIgnoreBlock>;
}

export interface ScopedIgnoreBlock {
  scope: string; // org or org/repo
  advisories?: string[];
  purls?: string[];
}

export interface IgnoreMatcherOptions {
  cwd?: string; // base dir for relative path
}

interface ParsedPurlIgnore {
  raw: string;
  type: string;
  name: string;
  versionConstraint?: string; // semver range or exact version
}

function parsePurlIgnore(raw: string): ParsedPurlIgnore | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const full = trimmed.startsWith("pkg:") ? trimmed.slice(4) : trimmed;
  const atIdx = full.indexOf("@");
  const main = atIdx >= 0 ? full.slice(0, atIdx) : full;
  const ver = atIdx >= 0 ? full.slice(atIdx + 1) : undefined;
  const slashIdx = main.indexOf("/");
  if (slashIdx < 0) return null;
  const type = main.slice(0, slashIdx).toLowerCase();
  const name = main.slice(slashIdx + 1);
  if (!type || !name) return null;
  return { raw: trimmed.startsWith("pkg:") ? trimmed : `pkg:${trimmed}`, type, name, versionConstraint: ver };
}

export class IgnoreMatcher {
  private globalAdvisories: Set<string> = new Set();
  private globalPurls: ParsedPurlIgnore[] = [];
  private scoped: Array<{ scope: string; isRepo: boolean; advisories: Set<string>; purls: ParsedPurlIgnore[] } > = [];

  static load(filePath: string, opts?: IgnoreMatcherOptions): IgnoreMatcher | undefined {
    const abs = path.isAbsolute(filePath) ? filePath : path.join(opts?.cwd || process.cwd(), filePath);
    if (!fs.existsSync(abs)) return undefined;
    const text = fs.readFileSync(abs, "utf8");
    let doc: IgnoreFileRoot | undefined;
    try {
      const parsed = YAML.parse(text) as unknown;
      if (parsed && typeof parsed === "object") doc = parsed as IgnoreFileRoot;
    } catch (e) {
      console.warn(`Failed to parse ignore file ${abs}: ${(e as Error).message}`);
      return undefined;
    }
    const matcher = new IgnoreMatcher();
    if (doc?.advisories) for (const a of doc.advisories) matcher.globalAdvisories.add(a.trim());
    if (doc?.purls) for (const p of doc.purls) { const parsed = parsePurlIgnore(p); if (parsed) matcher.globalPurls.push(parsed); }
    if (doc?.scoped) {
      for (const block of doc.scoped) {
        if (!block.scope) continue;
        const advisories = new Set<string>();
        if (block.advisories) for (const a of block.advisories) advisories.add(a.trim());
        const purls: ParsedPurlIgnore[] = [];
        if (block.purls) for (const p of block.purls) { const parsed = parsePurlIgnore(p); if (parsed) purls.push(parsed); }
        const isRepo = block.scope.includes("/");
        matcher.scoped.push({ scope: block.scope.toLowerCase(), isRepo, advisories, purls });
      }
    }
    return matcher;
  }

  private purlMatches(ignore: ParsedPurlIgnore, candidate: { purl: string; ecosystem: string; packageName: string; version: string | null }): boolean {
    const { purl, version } = candidate;
    // quick name match: we only stored type+name; ensure purl contains that coordination after pkg:
    const body = purl.startsWith("pkg:") ? purl.slice(4) : purl;
    const atIdx = body.indexOf("@");
    const main = atIdx >= 0 ? body.slice(0, atIdx) : body;
    const nameStart = main.indexOf("/");
    if (nameStart < 0) return false;
    const type = main.slice(0, nameStart).toLowerCase();
    const name = main.slice(nameStart + 1);
    if (ignore.type !== type) return false;
    if (ignore.name.toLowerCase() !== name.toLowerCase()) return false;
    if (!ignore.versionConstraint) return true; // any version
    if (!version) return false;
    const range = ignore.versionConstraint.trim();
    try {
      if (semver.validRange(range)) {
        const coerced = semver.coerce(version)?.version || version;
        if (coerced && semver.satisfies(coerced, range, { includePrerelease: true })) return true;
      } else if (/^[0-9A-Za-z._-]+$/.test(range)) {
        return version === range;
      }
    } catch { /* ignore */ }
    return false;
  }

  /** Determine whether the given match should be ignored. */
  shouldIgnore(match: MalwareMatch): { ignored: boolean; reason?: string } {
    // Global advisory
    if (this.globalAdvisories.has(match.advisoryGhsaId)) return { ignored: true, reason: `advisory:${match.advisoryGhsaId}` };
    // Global purl (with optional range)
    for (const p of this.globalPurls) {
      if (this.purlMatches(p, match)) return { ignored: true, reason: `purl:${p.raw}` };
    }
    // Scoped
    for (const block of this.scoped) {
      if (block.isRepo) {
        if (match.repo.toLowerCase() !== block.scope) continue;
      } else {
        // org scope
        if (!match.repo.toLowerCase().startsWith(block.scope + "/")) continue;
      }
      if (block.advisories.has(match.advisoryGhsaId)) return { ignored: true, reason: `scoped-advisory:${block.scope}:${match.advisoryGhsaId}` };
      for (const p of block.purls) if (this.purlMatches(p, match)) return { ignored: true, reason: `scoped-purl:${block.scope}:${p.raw}` };
    }
    return { ignored: false };
  }

  filter(matches: MalwareMatch[]): { kept: MalwareMatch[]; ignored: Array<MalwareMatch & { ignoreReason: string }> } {
    const kept: MalwareMatch[] = [];
    const ignored: Array<MalwareMatch & { ignoreReason: string }> = [];
    for (const m of matches) {
      const res = this.shouldIgnore(m);
      if (res.ignored) ignored.push({ ...m, ignoreReason: res.reason || "unknown" }); else kept.push(m);
    }
    return { kept, ignored };
  }
}
