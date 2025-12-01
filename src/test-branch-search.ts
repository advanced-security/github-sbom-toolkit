import fs from 'fs';
import path from 'path';
import { SbomCollector } from './sbomCollector.js';
import type { RepositorySbom } from './types.js';

// This test harness validates that branch SBOMs and dependency review diffs
// participate in search results. It constructs a synthetic repo SBOM object,
// writes it to a temp cache directory, then performs searches.

async function main() {
  const tempRoot = path.join(process.cwd(), 'tmp-branch-search-cache');
  const org = 'example-org';
  const repo = 'demo-repo';
  const repoDir = path.join(tempRoot, org, repo);
  fs.rmSync(tempRoot, { recursive: true, force: true });
  fs.mkdirSync(repoDir, { recursive: true });

  const basePackages = [
    { name: 'chalk', version: '5.6.1', purl: 'pkg:npm/chalk@5.6.1' },
    { name: 'react', version: '18.2.0', purl: 'pkg:npm/react@18.2.0' }
  ];
  const featurePackages = [
    { name: 'react', version: '18.3.0-beta', purl: 'pkg:npm/react@18.3.0-beta' },
    { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' }
  ];
  const diffChanges = [
    { changeType: 'added', name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.21', newVersion: '4.17.21' },
    { changeType: 'updated', name: 'react', ecosystem: 'npm', purl: 'pkg:npm/react@18.3.0-beta', previousVersion: '18.2.0', newVersion: '18.3.0-beta' }
  ];

  const synthetic: RepositorySbom = {
    repo: `${org}/${repo}`,
    org,
    retrievedAt: new Date().toISOString(),
    packages: basePackages,
    // Use Map keyed by branch name per updated type
    branchDiffs: new Map<string, any>([
      [
        'feature-x',
        {
          latestCommitDate: new Date().toISOString(),
          base: 'main',
          head: 'feature-x',
          retrievedAt: new Date().toISOString(),
          changes: diffChanges
        }
      ]
    ])
  } as RepositorySbom;

  fs.writeFileSync(path.join(repoDir, 'sbom.json'), JSON.stringify(synthetic, null, 2), 'utf8');

  const collector = new SbomCollector({
    token: undefined,
    org,
    loadFromDir: tempRoot,
    syncSboms: false,
    quiet: true
  });
  await collector.collect();

  const queries = [
    'pkg:npm/react@>=18.2.0 <19.0.0', // should match base & branch updated version
    'pkg:npm/lodash@4.17.21',          // should match added in branch diff & branch SBOM
    'pkg:npm/chalk@5.6.1'              // base only
  ];
  const results = collector.searchByPurlsWithReasons(queries);

  if (!results.size) {
    console.error('No search results found; expected matches from branch data');
    process.exit(1);
  }
  const entries = results.get(`${org}/${repo}`);
  if (!entries || entries.length < 4) {
    console.error(`Unexpected number of matches: ${(entries || []).length}`);
    console.error(JSON.stringify(entries, null, 2));
    process.exit(1);
  }

  process.stdout.write('Branch search test passed. Matches:\n');
  for (const e of entries) {
    process.stdout.write(`  ${e.purl} {query: ${e.reason}}\n`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
