import fs from "fs";
import path from "path";
import { BranchDependencyDiff, RepositorySbom } from "./types.js";

type SerializedRepositorySbom = Omit<RepositorySbom, "branchDiffs"> & {
  branchDiffs?: BranchDependencyDiff[];
};

export interface SerializeOptions {
  outDir: string;
  flatten?: boolean; // if true, use repo-replaced-with-dash.json
}

export function writeAll(sboms: RepositorySbom[], { outDir, flatten = false }: SerializeOptions) {
  for (const s of sboms) {
    const repoPath = flatten ? s.repo.replace(/\//g, "-") : s.repo;
    const fileDir = path.join(outDir, repoPath);
    const filePath = flatten ? path.join(outDir, `${repoPath}.json`) : path.join(fileDir, "sbom.json");
    fs.mkdirSync(flatten ? path.dirname(filePath) : fileDir, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(prepareForWrite(s), null, 2), "utf8");
  }
}

export function writeOne(sbom: RepositorySbom, { outDir, flatten = false }: SerializeOptions) {
  const repoPath = flatten ? sbom.repo.replace(/\//g, "-") : sbom.repo;
  const fileDir = path.join(outDir, repoPath);
  const filePath = flatten ? path.join(outDir, `${repoPath}.json`) : path.join(fileDir, "sbom.json");
  fs.mkdirSync(flatten ? path.dirname(filePath) : fileDir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(prepareForWrite(sbom), null, 2), "utf8");
}

export interface ReadOptions {
  /** Treat directory as flattened (owner-repo.json). */
  flatten?: boolean;
  /** Log parse errors (filename + message). */
  logParseErrors?: boolean;
  /** Stop after reading this many valid SBOMs (safety for huge trees). */
  maxFiles?: number;
}

/**
 * Read all serialized SBOMs below a directory.
 * Modes:
 *  - Hierarchical (default): recurse and only accept files named exactly `sbom.json` (tightened from previous any *.json behavior).
 *  - Flattened: do not recurse; accept top-level *.json where filename (without extension) contains at least one dash (owner-repo convention).
 */
export function readAll(dir: string, opts: ReadOptions = {}): RepositorySbom[] {
  const { flatten = false, logParseErrors = false, maxFiles } = opts;
  const results: RepositorySbom[] = [];
  if (!fs.existsSync(dir)) throw new Error(`Directory not found: ${dir}`);

  const pushIfValid = (filePath: string) => {
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const obj = reviveAfterRead(JSON.parse(raw));
      if (isRepositorySbom(obj)) {
        results.push(obj as RepositorySbom);
      }
    } catch (e) {
      if (logParseErrors) {

        console.warn(`Skipping malformed SBOM JSON ${filePath}: ${(e as Error).message}`);
      }
    }
  };

  if (flatten) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      if (!ent.name.endsWith('.json')) continue;
      // Require at least one dash to loosely match owner-repo.json (avoid pulling unrelated JSON)
      const baseName = ent.name.slice(0, -5); // remove .json
      if (!baseName.includes('-')) continue;
      pushIfValid(path.join(dir, ent.name));
      if (maxFiles && results.length >= maxFiles) break;
    }
  } else {
    const visit = (current: string) => {
      const stat = fs.statSync(current);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(current);
        for (const e of entries) {
          visit(path.join(current, e));
          if (maxFiles && results.length >= maxFiles) return; // early exit
        }
      } else if (stat.isFile()) {
        const base = path.basename(current);
        if (base === "sbom.json") {
          pushIfValid(current);
        }
      }
    };
    visit(dir);
  }
  return results;
}

// Convert Maps to plain serializable structures before JSON.stringify
function prepareForWrite(sbom: RepositorySbom): unknown {
  if (sbom.branchDiffs instanceof Map) {
    return { ...sbom, branchDiffs: Array.from(sbom.branchDiffs.values()) } satisfies SerializedRepositorySbom;
  }
  return sbom;
}

// Convert array representations back into Maps after JSON.parse
function reviveAfterRead(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !("branchDiffs" in value) || !Array.isArray(value.branchDiffs)) {
    return value;
  }
  const map = new Map<string, BranchDependencyDiff>();
  for (const diff of value.branchDiffs) {
    if (typeof diff === "object" && diff !== null && "head" in diff && typeof diff.head === "string") {
      map.set(diff.head, diff as BranchDependencyDiff);
    }
  }
  return { ...value, branchDiffs: map };
}

function isRepositorySbom(value: unknown): value is RepositorySbom {
  return typeof value === "object" && value !== null &&
    "repo" in value && typeof value.repo === "string" &&
    "packages" in value && Array.isArray(value.packages);
}
