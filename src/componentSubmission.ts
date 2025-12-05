import chalk from 'chalk';
import { execFile } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';

import ComponentDetection from './componentDetection.js';
import {
    Job,
    Snapshot,
} from '@github/dependency-submission-toolkit';
import { Octokit } from 'octokit';
import { RequestError } from '@octokit/request-error'

export interface SubmitOpts {
    octokit: Octokit;
    owner: string;
    repo: string;
    branch: string;
    token?: string;
    baseUrl?: string;
    caBundlePath?: string;
    quiet?: boolean;
    languages?: string[];
    componentDetectionBinPath?: string; // optional path to component-detection executable
}

export async function getLanguageIntersection(octokit: Octokit, owner: string, repo: string, languages: string[] | undefined, quiet: boolean = false): Promise<string[]> {
    const langResp = await octokit.request('GET /repos/{owner}/{repo}/languages', { owner, repo });
    const repoLangs = Object.keys(langResp.data || {});
    const wanted = languages;
    const intersect = wanted ? repoLangs.filter(l => wanted.some(w => w.toLowerCase() === l.toLowerCase())) : repoLangs;
    if (!intersect.length) {
        if (!quiet) console.error(chalk.yellow(`Skipping submission: none of selected languages present in repo (${repoLangs.join(', ')})`));
        return [];
    }
    return intersect;
}

export async function sparseCheckout(owner: string, repo: string, branch: string, destDir: string, intersect: string[], baseUrl?: string) {
    const cwd = destDir;
    const repoUrl = (baseUrl && baseUrl.includes('api/v3'))
        ? baseUrl.replace(/\/api\/v3$/, '') + `/${owner}/${repo}.git`
        : `https://github.com/${owner}/${repo}.git`;
    const patterns = buildSparsePatterns(intersect);
    // init repo
    await execGit(['init'], { cwd });
    await execGit(['remote', 'add', 'origin', repoUrl], { cwd });
    await execGit(['config', 'core.sparseCheckout', 'true'], { cwd });
    fs.mkdirSync(path.join(cwd, '.git', 'info'), { recursive: true });
    fs.writeFileSync(path.join(cwd, '.git', 'info', 'sparse-checkout'), patterns.join('\n') + '\n', 'utf8');
    await execGit(['fetch', '--depth=1', 'origin', branch], { cwd });
    await execGit(['checkout', 'FETCH_HEAD'], { cwd });

    const { stdout: shaOut } = await execGit(['rev-parse', 'HEAD'], { cwd: destDir });
    const sha = shaOut.trim();
    console.debug(`Checked out ${owner}/${repo}@${branch} to ${destDir} at commit ${sha}`);
    return sha;
}

export async function submitSnapshotIfPossible(opts: SubmitOpts): Promise<boolean> {
    if (!opts.octokit) {
        throw new Error('Octokit instance is required in opts.octokit');
    }

    const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'cd-submission-'));

    try {
        const intersect = await getLanguageIntersection(opts.octokit, opts.owner, opts.repo, opts.languages);
        // Create temp dir and sparse checkout only manifest files according to selected languages
        if (!intersect.length) {
            // No matching languages, skip submission
            return false;
        }
        console.debug(chalk.green(`Sparse checkout into ${tmp} for languages: ${intersect.join(', ')}`));

        const sha = await sparseCheckout(opts.owner, opts.repo, opts.branch, tmp, intersect, opts.baseUrl);

        // Run the ComponentDetection module to detect components and submit snapshot
        if (!sha) {
            if (!opts.quiet) console.error(chalk.red(`Failed to determine SHA for ${opts.owner}/${opts.repo} on branch ${opts.branch}`));
            return false;
        }
        await run(opts.octokit, tmp, opts.owner, opts.repo, sha, opts.branch, opts.componentDetectionBinPath);
        return true;
    } catch (e) {
        if (!opts.quiet) console.error(chalk.red(`Component Detection failed: ${(e as Error).message}`));
        return false;
    } finally {
        // Clean up temp dir
        await fs.promises.rm(tmp, { recursive: true, force: true });
    }
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
    // Include root lockfiles only if JavaScript/TypeScript is among selected languages
    if (langs.some(l => ['javascript', 'typescript', 'node', 'js', 'ts'].includes(l.toLowerCase()))) {
        add('package.json'); add('package-lock.json'); add('yarn.lock'); add('pnpm-lock.yaml');
    }
    return Array.from(set);
}

async function execGit(args: string[], opts: { cwd: string, quiet?: boolean }): Promise<{ stdout: string; stderr: string }> {
    return await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
        execFile('git', args, { cwd: opts.cwd, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
            if (error) {
                const msg = stderr?.trim() || error.message;
                reject(new Error(`git ${args.join(' ')} failed: ${msg}`));
            } else {
                resolve({ stdout, stderr: stderr ?? '' });
            }
        });
    });
}

export async function run(octokit: Octokit, tmpDir: string, owner: string, repo: string, sha: string, ref: string, componentDetectionBinPath?: string) {

    const componentDetection = new ComponentDetection(octokit, '', componentDetectionBinPath);

    let manifests = await componentDetection.scanAndGetManifests(tmpDir);

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

    const date = new Date().toISOString();

    const job: Job = {
        correlator: 'github-sbom-toolkit',
        id: `${owner}-${repo}-${ref}-${date}-${Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString()}`
    };

    let snapshot = new Snapshot(detector, undefined, job);
    snapshot.ref = `refs/heads/${ref}`;
    snapshot.sha = sha;

    console.debug(`Submitting snapshot for ${owner}/${repo} at ${snapshot.ref} (${snapshot.sha}) with ${manifests?.length || 0} manifests`);

    manifests?.forEach((manifest) => {
        snapshot.addManifest(manifest);
    });

    await submitSnapshot(octokit, snapshot, { owner, repo });
}

/**
 * submitSnapshot submits a snapshot to the Dependency Submission API - vendored in from @github/dependency-submission-toolkit, to make it work at the CLI, vs in Actions.
 *
 * @param {Snapshot} snapshot
 * @param {Repo} repo
 */
export async function submitSnapshot(
    octokit: Octokit,
    snapshot: Snapshot,
    repo: { owner: string; repo: string }
) {
    console.debug('Submitting snapshot...')
    console.debug(snapshot.prettyJSON())

    try {
        const response = await octokit.request(
            'POST /repos/{owner}/{repo}/dependency-graph/snapshots',
            {
                headers: {
                    accept: 'application/vnd.github+json'
                },
                owner: repo.owner,
                repo: repo.repo,
                ...snapshot
            }
        )
        const result = response.data.result
        if (result === 'SUCCESS' || result === 'ACCEPTED') {
            console.debug(
                `Snapshot successfully created at ${response.data.created_at.toString()}` +
                ` with id ${response.data.id}`
            )
        } else {
            console.error(
                `Snapshot creation failed with result: "${result}: ${response.data.message}"`
            )
        }
    } catch (error) {
        if (error instanceof RequestError) {
            console.error(
                `HTTP Status ${error.status} for request ${error.request.method} ${error.request.url}`
            )
            if (error.response) {
                console.error(
                    `Response body:\n${JSON.stringify(error.response.data, undefined, 2)}`
                )
            }
        }
        if (error instanceof Error) {
            console.error(error.message)
            if (error.stack) console.error(error.stack)
        }
        throw new Error(`Failed to submit snapshot: ${error}`)
    }
}