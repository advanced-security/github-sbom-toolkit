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
}

// This helper attempts to run the Component Detection + Dependency Submission action
// as a local script, assuming the repository has the submodule checked out at
// `component-detection-dependency-submission-action`.
// It falls back to returning false if not available.
export async function submitSnapshotIfPossible(opts: SubmitOpts): Promise<boolean> {
  const root = process.cwd();
  const actionDir = path.join(root, 'component-detection-dependency-submission-action');
  const entry = path.join(actionDir, 'dist', 'entrypoint.js');
  // Minimal validation: require entrypoint to exist
  try {
    const fs = await import('fs');
    if (!fs.existsSync(entry)) {
      if (!opts.quiet) console.error(chalk.yellow('Component Detection action not found; ensure submodule initialized and built.'));
      return false;
    }
  } catch {
    return false;
  }
  // Run the entrypoint with necessary env vars
  const env = {
    ...process.env,
    GITHUB_TOKEN: opts.token || process.env.GITHUB_TOKEN || '',
    GITHUB_BASE_URL: opts.baseUrl || process.env.GITHUB_BASE_URL || '',
    TARGET_OWNER: opts.owner,
    TARGET_REPO: opts.repo,
    TARGET_REF: opts.branch
  };
  if (!env.GITHUB_TOKEN) {
    if (!opts.quiet) console.error(chalk.red('GITHUB_TOKEN required to submit dependency snapshot'));
    return false;
  }
  await new Promise<void>((resolve, reject) => {
    const child = spawn('node', [entry], { env, stdio: opts.quiet ? 'ignore' : 'inherit' });
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`entrypoint exit ${code}`)));
  });
  return true;
}
