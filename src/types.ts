export interface SbomPackage {
  name?: string;
  version?: string;
  purl?: string; // Package URL standard
  type?: string;
  [k: string]: unknown;
}

// SPDX 2.2 style structures returned inside the `sbom` key from
// GET /repos/{owner}/{repo}/dependency-graph/sbom
// (GitHub provides an SPDX JSON document subset.)
export interface SbomExternalRef {
  referenceCategory?: string;
  referenceType?: string;
  referenceLocator?: string;
  [k: string]: unknown;
}

export interface SbomChecksum {
  algorithm?: string; // e.g. SHA256
  checksumValue?: string;
}

export interface SbomCreationInfo {
  created?: string; // ISO timestamp
  creators?: string[]; // e.g. ["Tool: github.com/dependency-graph"]
  [k: string]: unknown;
}

export interface SbomRelationship {
  spdxElementId: string; // SPDXRef-...
  relationshipType: string; // e.g. DEPENDS_ON
  relatedSpdxElement: string; // SPDXRef-...
  [k: string]: unknown;
}

// Extend the basic SbomPackage type with common SPDX package fields.
export interface SbomSpdxPackage extends SbomPackage {
  SPDXID?: string; // SPDXRef for the package
  downloadLocation?: string;
  filesAnalyzed?: boolean;
  licenseConcluded?: string;
  licenseDeclared?: string;
  supplier?: string;
  originator?: string;
  description?: string;
  homepage?: string;
  externalRefs?: SbomExternalRef[];
  checksums?: SbomChecksum[];
  [k: string]: unknown;
}

export interface Sbom {
  spdxVersion?: string; // e.g. SPDX-2.2
  dataLicense?: string; // e.g. CC0-1.0
  documentNamespace?: string;
  name?: string; // repository name (owner/repo)
  creationInfo?: SbomCreationInfo;
  packages?: SbomSpdxPackage[]; // SPDX packages
  relationships?: SbomRelationship[];
  // Some fields GitHub may add (future-proof with index signature)
  [k: string]: unknown;
}

export interface RepositorySbom {
  repo: string; // owner/repo
  org: string; // org login
  enterprise?: string;
  retrievedAt: string; // ISO string
  sbom?: Sbom; // Raw SBOM JSON structure from GitHub
  packages: SbomPackage[];
  error?: string; // error message if retrieval failed
  // Incremental fetch metadata
  repoPushedAt?: string; // repository.pushed_at at time of retrieval
  repoUpdatedAt?: string; // repository.updated_at
  defaultBranch?: string; // repository.default_branch
  etag?: string; // ETag from SBOM response (future: conditional requests)
  defaultBranchCommitSha?: string; // commit SHA of default branch at time of retrieval
  defaultBranchCommitDate?: string; // ISO date of that commit
  // Branch-level diffs (optional when branch scanning enabled)
  branchDiffs?: Map<string, BranchDependencyDiff>;
}

export interface CollectionSummary {
  enterprise?: string;
  orgs: string[];
  repositoryCount: number;
  successCount: number;
  failedCount: number;
  skippedCount: number; // Incremental skips (reused baseline)
  startedAt: string;
  finishedAt?: string;
}

export interface SearchResultEntry {
  repository: string;
  matches: SbomPackage[];
}

// Branch-specific SBOM capture
export interface BranchSbom {
  branch: string;
  commitSha?: string;
  retrievedAt: string;
  sbom?: Sbom;
  packages: SbomPackage[];
  error?: string;
}

// Dependency Review change format (subset; future-proof with index signature)
export interface DependencyReviewPackageChange {
  changeType: string; // added | removed | updated
  name?: string; // package name
  ecosystem?: string; // e.g. npm, maven, pip
  packageURL?: string; // raw package URL (may be purl-like)
  purl?: string; // normalized purl (if derivable)
  license?: string;
  manifest?: string; // manifest path
  scope?: string; // e.g. runtime, development
  previousVersion?: string; // for updated/removed
  newVersion?: string; // for added/updated
  [k: string]: unknown;
}

export interface BranchDependencyDiff {
  latestCommitDate: string;
  base: string; // base branch
  head: string; // head branch
  retrievedAt: string;
  changes: DependencyReviewPackageChange[];
  error?: string;
}
