import chalk from 'chalk';
import { spawn } from 'child_process';
import path from 'path';

export interface SubmitOpts {
  owner: string;
  repo: string;
  branch: string;
  token?: string;
  baseUrl?: string;
  caBundlePath?: string;
  quiet?: boolean;
  languages?: string[];
}

// This helper attempts to run the Component Detection + Dependency Submission action
// as a local script, assuming the repository has the submodule checked out at
// `component-detection-dependency-submission-action`.
// It falls back to returning false if not available.
export async function submitSnapshotIfPossible(opts: SubmitOpts): Promise<boolean> {
  const root = process.cwd();
  const actionDir = path.join(root, 'component-detection-dependency-submission-action');
  const entry = path.join(actionDir, 'dist/index.js');
  const fs = await import('fs');
  if (!fs.existsSync(entry)) {
    if (!opts.quiet) console.error(chalk.yellow('Component Detection action not found; ensure submodule initialized and built.'));
    return false;
  }
  const token = opts.token || process.env.GITHUB_TOKEN || '';
  if (!token) {
    if (!opts.quiet) console.error(chalk.red('GITHUB_TOKEN required to submit dependency snapshot'));
    return false;
  }

  // If languages filter provided, inspect repo languages and perform sparse checkout of relevant manifests
  let cwd = root;
  if (opts.languages && opts.languages.length) {
    const { createOctokit } = await import('./octokit.js');
    const o = createOctokit({ token, baseUrl: opts.baseUrl });
    try {
      const langResp = await o.request('GET /repos/{owner}/{repo}/languages', { owner: opts.owner, repo: opts.repo });
      const repoLangs = Object.keys(langResp.data || {});
      const wanted = opts.languages;
      const intersect = repoLangs.filter(l => wanted.some(w => w.toLowerCase() === l.toLowerCase()));
      if (!intersect.length) {
        if (!opts.quiet) console.error(chalk.yellow(`Skipping submission: none of selected languages present in repo (${repoLangs.join(', ')})`));
        return false;
      }
      // Create temp dir and sparse checkout only manifest files according to selected languages
      const os = await import('os');
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-submission-'));
      cwd = tmp;
      const repoUrl = (opts.baseUrl && opts.baseUrl.includes('api/v3'))
        ? opts.baseUrl.replace(/\/api\/v3$/, '') + `/${opts.owner}/${opts.repo}.git`
        : `https://github.com/${opts.owner}/${opts.repo}.git`;
      const patterns = buildSparsePatterns(intersect);
      // init repo
      await execGit(['init'], { cwd });
      await execGit(['remote', 'add', 'origin', repoUrl], { cwd });
      await execGit(['config', 'core.sparseCheckout', 'true'], { cwd });
      fs.mkdirSync(path.join(cwd, '.git', 'info'), { recursive: true });
      fs.writeFileSync(path.join(cwd, '.git', 'info', 'sparse-checkout'), patterns.join('\n') + '\n', 'utf8');
      await execGit(['fetch', '--depth=1', 'origin', opts.branch], { cwd });
      await execGit(['checkout', 'FETCH_HEAD'], { cwd });
    } catch (e) {
      if (!opts.quiet) console.error(chalk.red(`Sparse checkout failed: ${(e as Error).message}`));
      return false;
    }
  }

  // Run the action entrypoint pointing at the sparse checkout dir (or root if none)
  await new Promise<void>((resolve, reject) => {
    const env = {
      ...process.env,
      GITHUB_TOKEN: token,
      GITHUB_BASE_URL: opts.baseUrl || process.env.GITHUB_BASE_URL || '',
    };
    const child = spawn('node', [entry], { env, stdio: opts.quiet ? 'ignore' : 'inherit', cwd });
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`entrypoint exit ${code}`)));
  });
  return true;
}

function buildSparsePatterns(langs: string[]): string[] {
  const set = new Set<string>();
  const add = (p: string) => set.add(p);
  for (const l of langs) {
    const ll = l.toLowerCase();
    if (ll === 'javascript' || ll === 'typescript') {
      add('**/package.json');
      add('**/package-lock.json');
      add('**/yarn.lock');
      add('**/pnpm-lock.yaml');
    } else if (ll === 'python') {
      add('**/requirements.txt');
      add('**/Pipfile.lock');
      add('**/poetry.lock');
      add('**/pyproject.toml');
    } else if (ll === 'go') {
      add('**/go.mod');
      add('**/go.sum');
    } else if (ll === 'ruby') {
      add('**/Gemfile.lock');
      add('**/gems.locked');
    } else if (ll === 'rust') {
      add('**/Cargo.toml');
      add('**/Cargo.lock');
    } else if (ll === 'java') {
      // Maven & Gradle
      add('**/pom.xml');
      add('**/build.gradle');
      add('**/build.gradle.kts');
      add('**/settings.gradle');
      add('**/settings.gradle.kts');
      add('**/gradle.lockfile');
    } else if (ll === 'c#' || ll === 'csharp') {
      add('**/packages.lock.json');
      add('**/*.csproj');
      add('**/*.sln');
    }
  }
  // Always include root lockfiles just in case
  add('package.json'); add('package-lock.json'); add('yarn.lock'); add('pnpm-lock.yaml');
  return Array.from(set);
}

async function execGit(args: string[], opts: { cwd: string }): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn('git', args, { cwd: opts.cwd, stdio: 'inherit' });
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`git ${args.join(' ')} exit ${code}`)));
  });
}
