import chalk from 'chalk';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import type { Context } from '@actions/github/lib/context.js'

import ComponentDetection from './componentDetection.js';
import {
    Snapshot,
    submitSnapshot
} from '@github/dependency-submission-toolkit';

export interface SubmitOpts {
    octokit?: any; // Octokit instance, optional
    owner: string;
    repo: string;
    branch: string;
    token?: string;
    baseUrl?: string;
    caBundlePath?: string;
    quiet?: boolean;
    languages?: string[];
}

export async function submitSnapshotIfPossible(opts: SubmitOpts): Promise<boolean> {
    if (!opts.octokit) {
        throw new Error('Octokit instance is required in opts.octokit');
    }

    // If languages filter provided, inspect repo languages and perform sparse checkout of relevant manifests
    if (opts.languages && opts.languages.length) {
        try {
            const langResp = await opts.octokit.request('GET /repos/{owner}/{repo}/languages', { owner: opts.owner, repo: opts.repo });
            const repoLangs = Object.keys(langResp.data || {});
            const wanted = opts.languages;
            const intersect = repoLangs.filter(l => wanted.some(w => w.toLowerCase() === l.toLowerCase()));
            if (!intersect.length) {
                if (!opts.quiet) console.error(chalk.yellow(`Skipping submission: none of selected languages present in repo (${repoLangs.join(', ')})`));
                return false;
            }
            // Create temp dir and sparse checkout only manifest files according to selected languages
            const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cd-submission-'));
            const cwd = tmp;
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

            // Run the ComponentDetection module to detect components and submit snapshot
            const process = await execGit(['rev-parse', 'HEAD'], { cwd });
            const sha = process?.stdout?.toString().trim();

            if (!sha) {
                if (!opts.quiet) console.error(chalk.red(`Failed to determine SHA for ${opts.owner}/${opts.repo} on branch ${opts.branch}`));
                return false;
            }
            await run(opts.owner, opts.repo, sha, opts.branch);

        } catch (e) {
            if (!opts.quiet) console.error(chalk.red(`Sparse checkout failed: ${(e as Error).message}`));
            return false;
        }
    }

    return false;
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

async function execGit(args: string[], opts: { cwd: string, quiet?: boolean }): Promise<ChildProcess> {
    return await new Promise<ChildProcess>((resolve, reject) => {
        const child = spawn('git', args, { cwd: opts.cwd, stdio: 'pipe' });
        child.on('error', reject);
        child.on('exit', code => code === 0 ? resolve(child) : reject(new Error(`git ${args.join(' ')} exit ${code}`)));
    });
}

export async function run(owner: string, repo: string, sha: string, ref: string) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-'));

    let manifests = await ComponentDetection.scanAndGetManifests(
        tmpDir
    );

    // Get detector configuration inputs
    const detectorName = "Component Detection in GitHub SBOM Toolkit: advanced-security/github-sbom-toolkit";
    const detectorVersion = "0.0.1";
    const detectorUrl = "https://github.com/advanced-security/github-sbom-toolkit";

    // Use provided detector config or defaults
    const detector = {
        name: detectorName,
        version: detectorVersion,
        url: detectorUrl,
    };

    const context: Context = {
        repo: { owner: owner, repo: repo },
        job: 'github-sbom-toolkit',
        runId: Math.floor(Math.random() * Number.MAX_SAFE_INTEGER),
        ref: ref,
        sha: sha,
        // required for Context type but not used in snapshot submission
        payload: {}, eventName: '', workflow: '', action: '', actor: '', runNumber: 0, runAttempt: 0, apiUrl: '', serverUrl: '', graphqlUrl: '', issue: { owner: '', repo: '', number: 0 }
    };

    let snapshot = new Snapshot(detector, context);

    manifests?.forEach((manifest) => {
        snapshot.addManifest(manifest);
    });

    submitSnapshot(snapshot);
}
