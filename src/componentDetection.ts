import { Octokit } from "octokit"
import {
  PackageCache,
  Package,
  Manifest,
} from '@github/dependency-submission-toolkit'
import fetch from 'cross-fetch'
import fs from 'fs'
import { spawn } from 'child_process';
//import dotenv from 'dotenv'
import path from 'path';
import { tmpdir } from 'os';
//dotenv.config();

export default class ComponentDetection {
  public static componentDetectionPath = process.platform === "win32" ? './component-detection.exe' : './component-detection';
  public static outputPath = path.join(tmpdir(), `component-detection-output-${Date.now()}.json`);

  // This is the default entry point for this class.
  // If executablePath is provided, use it directly and skip download.
  static async scanAndGetManifests(path: string, executablePath?: string): Promise<Manifest[] | undefined> {
    if (executablePath) {
      this.componentDetectionPath = executablePath;
    } else {
      await this.downloadLatestRelease();
    }
    await this.runComponentDetection(path);
    return await this.getManifestsFromResults();
  }
  // Get the latest release from the component-detection repo, download the tarball, and extract it
  public static async downloadLatestRelease() {
    try {
      const statResult = fs.statSync(this.componentDetectionPath);
      if (statResult && statResult.isFile()) {
        console.debug(`Component-detection binary already exists at ${this.componentDetectionPath}, skipping download.`);
        return;
      }
    } catch (error) {
      // File does not exist, proceed to download
    }

    try {
      console.debug(`Downloading latest release for ${process.platform}`);
      const downloadURL = await this.getLatestReleaseURL();
      const blob = await (await fetch(new URL(downloadURL))).blob();
      const arrayBuffer = await blob.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);

      // Write the blob to a file
      console.debug(`Writing binary to file ${this.componentDetectionPath}`);
      await fs.writeFileSync(this.componentDetectionPath, buffer, { mode: 0o777, flag: 'w' });
    } catch (error: any) {
      console.error(error);
    }
  }

  // Run the component-detection CLI on the path specified
  public static async runComponentDetection(path: string) {
    console.info("Running component-detection");

    try {
      await spawn(`${this.componentDetectionPath}`, ['scan', '--SourceDirectory', path, '--ManifestFile', this.outputPath], { stdio: 'pipe' });
    } catch (error: any) {
      console.error(error);
    }
  }

  public static async getManifestsFromResults(): Promise<Manifest[] | undefined> {
    console.info("Getting manifests from results");
    console.info(`Reading results from ${this.outputPath}`);
    console.info(`Stat: ${fs.statSync(this.outputPath)}`);
    const results = await fs.readFileSync(this.outputPath, 'utf8');
    var json: any = JSON.parse(results);
    let dependencyGraphs: DependencyGraphs = this.normalizeDependencyGraphPaths(json.dependencyGraphs, '.');
    return this.processComponentsToManifests(json.componentsFound, dependencyGraphs);
  }

  public static processComponentsToManifests(componentsFound: any[], dependencyGraphs: DependencyGraphs): Manifest[] {
    // Parse the result file and add the packages to the package cache
    const packageCache = new PackageCache();
    const packages: Array<ComponentDetectionPackage> = [];

    componentsFound.forEach(async (component: any) => {
      // Skip components without packageUrl
      if (!component.component.packageUrl) {
        console.debug(`Skipping component detected without packageUrl: ${JSON.stringify({
          id: component.component.id,
          name: component.component.name || 'unnamed',
          type: component.component.type || 'unknown'
        }, null, 2)}`);
        return;
      }

      const packageUrl = ComponentDetection.makePackageUrl(component.component.packageUrl);

      // Skip if the packageUrl is empty (indicates an invalid or missing packageUrl)
      if (!packageUrl) {
        console.debug(`Skipping component with invalid packageUrl: ${component.component.id}`);
        return;
      }

      if (!packageCache.hasPackage(packageUrl)) {
        const pkg = new ComponentDetectionPackage(packageUrl, component.component.id,
          component.isDevelopmentDependency, component.topLevelReferrers, component.locationsFoundAt, component.containerDetailIds, component.containerLayerIds);
        packageCache.addPackage(pkg);
        packages.push(pkg);
      }
    });

    // Set the transitive dependencies
    console.debug("Sorting out transitive dependencies");
    packages.forEach(async (pkg: ComponentDetectionPackage) => {
      pkg.topLevelReferrers.forEach(async (referrer: any) => {
        // Skip if referrer doesn't have a valid packageUrl
        if (!referrer.packageUrl) {
          console.debug(`Skipping referrer without packageUrl for component: ${pkg.id}`);
          return;
        }

        const referrerUrl = ComponentDetection.makePackageUrl(referrer.packageUrl);
        referrer.packageUrlString = referrerUrl

        // Skip if the generated packageUrl is empty
        if (!referrerUrl) {
          console.debug(`Skipping referrer with invalid packageUrl for component: ${pkg.id}`);
          return;
        }

        try {
          const referrerPackage = packageCache.lookupPackage(referrerUrl);
          if (referrerPackage === pkg) {
            console.debug(`Skipping self-reference for package: ${pkg.id}`);
            return; // Skip self-references
          }
          if (referrerPackage) {
            referrerPackage.dependsOn(pkg);
          }
        } catch (error) {
          console.debug(`Error looking up referrer package: ${error}`);
        }
      });
    });

    // Create manifests
    const manifests: Array<Manifest> = [];

    // Check the locationsFoundAt for every package and add each as a manifest
    this.addPackagesToManifests(packages, manifests, dependencyGraphs);

    return manifests;
  }

  private static addPackagesToManifests(packages: Array<ComponentDetectionPackage>, manifests: Array<Manifest>, dependencyGraphs: DependencyGraphs): void {
    packages.forEach((pkg: ComponentDetectionPackage) => {
      pkg.locationsFoundAt.forEach((location: any) => {
        // Use the normalized path (remove leading slash if present)
        let normalizedLocation = location.startsWith('/') ? location.substring(1) : location;
        // Unescape the path, as upstream ComponentDetection emits locationsFoundAt in URL-encoded form
        normalizedLocation = decodeURIComponent(normalizedLocation);

        if (!manifests.find((manifest: Manifest) => manifest.name == normalizedLocation)) {
          const manifest = new Manifest(normalizedLocation, normalizedLocation);
          manifests.push(manifest);
        }

        const depGraphEntry = dependencyGraphs[normalizedLocation];
        if (!depGraphEntry) {
          console.warn(`No dependency graph entry found for manifest location: ${normalizedLocation}`);
          return; // Skip this location if not found in dependencyGraphs
        }

        const directDependencies = depGraphEntry.explicitlyReferencedComponentIds;
        if (directDependencies.includes(pkg.id)) {
          manifests
            .find((manifest: Manifest) => manifest.name == normalizedLocation)
            ?.addDirectDependency(
              pkg,
              ComponentDetection.getDependencyScope(pkg)
            );
        } else {
          manifests
            .find((manifest: Manifest) => manifest.name == normalizedLocation)
            ?.addIndirectDependency(
              pkg,
              ComponentDetection.getDependencyScope(pkg)
            );
        }
      });
    });
  }

  private static getDependencyScope(pkg: ComponentDetectionPackage) {
    return pkg.isDevelopmentDependency ? 'development' : 'runtime'
  }

  public static makePackageUrl(packageUrlJson: any): string {
    // Handle case when packageUrlJson is null or undefined
    if (
      !packageUrlJson ||
      typeof packageUrlJson.Scheme !== 'string' ||
      typeof packageUrlJson.Type !== 'string' ||
      !packageUrlJson.Scheme ||
      !packageUrlJson.Type
    ) {
      console.debug(`Warning: Received null or undefined packageUrlJson. Unable to create package URL.`);
      return ""; // Return a blank string for unknown packages
    }

    try {
      var packageUrl = `${packageUrlJson.Scheme}:${packageUrlJson.Type}/`;
      if (packageUrlJson.Namespace) {
        packageUrl += `${packageUrlJson.Namespace.replaceAll("@", "%40")}/`;
      }
      packageUrl += `${packageUrlJson.Name.replaceAll("@", "%40")}`;
      if (packageUrlJson.Version) {
        packageUrl += `@${packageUrlJson.Version}`;
      }
      if (typeof packageUrlJson.Qualifiers === "object"
        && packageUrlJson.Qualifiers !== null
        && Object.keys(packageUrlJson.Qualifiers).length > 0) {
        const qualifierString = Object.entries(packageUrlJson.Qualifiers)
          .map(([key, value]) => `${key}=${value}`)
          .join("&");
        packageUrl += `?${qualifierString}`;
      }
      return packageUrl;
    } catch (error) {
      console.debug(`Error creating package URL from packageUrlJson: ${JSON.stringify(packageUrlJson, null, 2)}`);
      console.debug(`Error details: ${error}`);
      return ""; // Return a blank string for error cases
    }
  }

  private static async getLatestReleaseURL(): Promise<string> {
    let githubToken = process.env.GITHUB_TOKEN || "";

    const githubAPIURL = process.env.GITHUB_API_URL || 'https://api.github.com';

    let ghesMode = process.env.GITHUB_API_URL != githubAPIURL;
    // If the we're running in GHES, then use an empty string as the token
    if (ghesMode) {
      githubToken = "";
    }
    const octokit = new Octokit({
      auth: githubToken, baseUrl: githubAPIURL, request: { fetch: fetch }, log: {
        debug: console.debug,
        info: console.info,
        warn: console.warn,
        error: console.error
      },
    });

    const owner = "microsoft";
    const repo = "component-detection";
    console.debug("Attempting to download latest release from " + githubAPIURL);

    try {
      const latestRelease = await octokit.request("GET /repos/{owner}/{repo}/releases/latest", { owner, repo });

      var downloadURL: string = "";
      // TODO: do we need to handle different architectures here?
      // can we allow x64 on MacOS? We could allow an input parameter to override?
      const assetName = process.platform === "win32" ? "component-detection-win-x64.exe" : process.platform === "linux" ? "component-detection-linux-x64" : "component-detection-osx-arm64";
      latestRelease.data.assets.forEach((asset: any) => {
        if (asset.name === assetName) {
          downloadURL = asset.browser_download_url;
        }
      });

      return downloadURL;
    } catch (error: any) {
      console.error(error);
      console.debug(error.message);
      console.debug(error.stack);
      throw new Error("Failed to download latest release");
    }
  }

  /**
   * Normalizes the keys of a DependencyGraphs object to be relative paths from the resolved filePath input.
   * @param dependencyGraphs The DependencyGraphs object to normalize.
   * @param filePathInput The filePath input (relative or absolute) from the action configuration.
   * @returns A new DependencyGraphs object with relative path keys.
   */
  public static normalizeDependencyGraphPaths(
    dependencyGraphs: DependencyGraphs,
    filePathInput: string
  ): DependencyGraphs {
    // Resolve the base directory from filePathInput (relative to cwd if not absolute)
    const baseDir = path.resolve(process.cwd(), filePathInput);
    const normalized: DependencyGraphs = {};
    for (const absPath in dependencyGraphs) {
      // Make the path relative to the baseDir
      let relPath = path.relative(baseDir, absPath).replace(/\\/g, '/');
      normalized[relPath] = dependencyGraphs[absPath];
    }
    return normalized;
  }
}

class ComponentDetectionPackage extends Package {
  public packageUrlString: string;

  constructor(packageUrl: string, public id: string, public isDevelopmentDependency: boolean, public topLevelReferrers: [],
    public locationsFoundAt: [], public containerDetailIds: [], public containerLayerIds: []) {
    super(packageUrl);
    this.packageUrlString = packageUrl;
  }
}

/**
 * Types for the dependencyGraphs section of output.json
 */
export type DependencyGraph = {
  /**
   * The dependency graph: keys are component IDs, values are either null (no dependencies) or an array of component IDs (dependencies)
   */
  graph: Record<string, string[] | null>;
  /**
   * Explicitly referenced component IDs
   */
  explicitlyReferencedComponentIds: string[];
  /**
   * Development dependencies
   */
  developmentDependencies: string[];
  /**
   * Regular dependencies
   */
  dependencies: string[];
};

/**
 * The top-level dependencyGraphs object: keys are manifest file paths, values are DependencyGraph objects
 */
export type DependencyGraphs = Record<string, DependencyGraph>;










