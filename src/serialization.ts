import fs from "fs";
import path from "path";
import { RepositorySbom } from "./types.js";

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
    fs.writeFileSync(filePath, JSON.stringify(s, null, 2), "utf8");
  }
}

export interface ReadOptions { flatten?: boolean }

export function readAll(dir: string, _opts: ReadOptions = {}): RepositorySbom[] {
  const results: RepositorySbom[] = [];
  if (!fs.existsSync(dir)) throw new Error(`Directory not found: ${dir}`);

  const visit = (current: string) => {
    const stat = fs.statSync(current);
    if (stat.isDirectory()) {
      const entries = fs.readdirSync(current);
      for (const e of entries) visit(path.join(current, e));
    } else if (stat.isFile()) {
      const base = path.basename(current);
      if (base === "sbom.json" || base.endsWith(".json")) {
        try {
          const raw = fs.readFileSync(current, "utf8");
          const obj = JSON.parse(raw);
          if (obj && obj.repo && Array.isArray(obj.packages)) {
            results.push(obj as RepositorySbom);
          }
        } catch (e) {
          // skip malformed file
        }
      }
    }
  };
  visit(dir);
  return results;
}
