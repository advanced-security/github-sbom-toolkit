import { Octokit } from "@octokit/core";
import {
  PackageCache,
  Package,
  Manifest,
} from '@github/dependency-submission-toolkit'
import fetch from 'cross-fetch'
import fs from 'fs'
import { spawn } from 'child_process';
import path from 'path';
import { tmpdir } from 'os';
import { StringDecoder } from 'node:string_decoder';

export default class ComponentDetection { 
  public componentDetectionPath: string = process.platform === "win32" ? './component-detection.exe' : './component-detection';
  public outputPath: string;
  octokit: Octokit;
  baseUrl: string;

  constructor(octokit: Octokit, baseUrl: string, executablePath?: string) {
    this.octokit = octokit;
    this.baseUrl = baseUrl;
    if (executablePath) {
      this.componentDetectionPath = executablePath;
    }

    // Set the output path
    this.outputPath = (() => {
      const tmpDir = fs.mkdtempSync(path.join(tmpdir(), 'component-detection-'));
      return path.join(tmpDir, 'output.json');
    })();
  }

  // This is the default entry point for this class.
  // If executablePath is provided, use it directly and skip download.
  async scanAndGetManifests(path: string): Promise<Manifest[] | undefined> {
    if (!this.componentDetectionPath) {
      await this.downloadLatestRelease();
    }

    // make an empty file to write results into
    fs.writeFileSync(this.outputPath, '', { flag: 'w' });

    if (!await this.runComponentDetection(path)) {
      return;
    }

    return await this.getManifestsFromResults(this.outputPath, path);
  }
  // Get the latest release from the component-detection repo, download the tarball, and extract it
  public async downloadLatestRelease() {
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
      await fs.writeFileSync(this.componentDetectionPath, buffer, { mode: 0o755, flag: 'w' });
    } catch (error: any) {
      console.error(error);
    }
  }

  // Run the component-detection CLI on the path specified
  public runComponentDetection(path: string): Promise<boolean> {
    console.debug(`Running component-detection on ${path}`);

    console.debug(`Writing to output file: ${this.outputPath}`);

    return new Promise<boolean>((resolve, reject) => {
      try {
        const child = spawn(`${this.componentDetectionPath}`, ['scan', '--SourceDirectory', path, '--ManifestFile', this.outputPath], { stdio: 'pipe' });
        const pid = child.pid;

        child.on('error', (err) => {
          console.error(`Component-detection process ${pid} error: ${err instanceof Error ? err.message : String(err)}`);
          reject(err);
        });

        child.on('exit', (code) => {
          console.debug(`Component-detection process ${pid} exited with code ${code}`);
          if (code === 0) {
            console.debug(`Component-detection completed successfully.`);
            resolve(true);
          } else {
            console.error(`Component-detection failed with exit code ${code}.`);
            const decoder = new StringDecoder('utf8');
            const stdout = child.stdout.read();
            const stderr = child.stderr.read();
            if (stdout) {
              console.error(decoder.write(stdout));
            }
            if (stderr) {
              console.error(decoder.write(stderr));
            }
            resolve(false);
          }
        });
      } catch (error: any) {
        console.error(error);
        reject(error);
      }
    });
  }

  public async getManifestsFromResults(file: string, path: string): Promise<Manifest[] | undefined> {
    console.debug(`Reading results from ${file}`);
    const results = await fs.readFileSync(file, 'utf8');
    const json: any = JSON.parse(results);

    let dependencyGraphs: DependencyGraphs = this.normalizeDependencyGraphPaths(json.dependencyGraphs, path);

    return this.processComponentsToManifests(json.componentsFound, dependencyGraphs);
  }

  public processComponentsToManifests(componentsFound: any[], dependencyGraphs: DependencyGraphs): Manifest[] {
    // Parse the result file and add the packages to the package cache
    const packageCache = new PackageCache();
    const packages: Array<ComponentDetectionPackage> = [];

    for (const component of componentsFound) {
      // Skip components without packageUrl
      if (!component.component.packageUrl) {
        console.debug(`Skipping component detected without packageUrl: ${JSON.stringify({
          id: component.component.id,
          name: component.component.name || 'unnamed',
          type: component.component.type || 'unknown'
        }, null, 2)}`);
        continue;
      }

      console.debug(`Processing component: ${component.component.id}`);
      console.debug(`Component details: ${JSON.stringify(component.component.packageUrl, null, 2)}`);

      const packageUrl = ComponentDetection.makePackageUrl(component.component.packageUrl);

      // Skip if the packageUrl is empty (indicates an invalid or missing packageUrl)
      if (!packageUrl) {
        console.debug(`Skipping component with invalid packageUrl: ${component.component.id}`);
        continue;
      }

      if (!packageCache.hasPackage(packageUrl)) {
        const pkg = new ComponentDetectionPackage(packageUrl, component.component.id,
          component.isDevelopmentDependency, component.topLevelReferrers, component.locationsFoundAt, component.containerDetailIds, component.containerLayerIds);
        packageCache.addPackage(pkg);
        packages.push(pkg);
      }
    }

    // Set the transitive dependencies
    console.debug("Sorting out transitive dependencies");
    for (const pkg of packages) {
      for (const referrer of pkg.topLevelReferrers) {
        // Skip if referrer doesn't have a valid packageUrl
        if (!referrer.packageUrl) {
          console.debug(`Skipping referrer without packageUrl for component: ${pkg.id}`);
          continue;
        }

        const referrerUrl = ComponentDetection.makePackageUrl(referrer.packageUrl);
        referrer.packageUrlString = referrerUrl;

        // Skip if the generated packageUrl is empty
        if (!referrerUrl) {
          console.debug(`Skipping referrer with invalid packageUrl for component: ${pkg.id}`);
          continue;
        }

        try {
          const referrerPackage = packageCache.lookupPackage(referrerUrl);
          if (referrerPackage === pkg) {
            console.debug(`Found self-reference for package: ${pkg.id}`);
            continue; // Skip self-references
          }
          if (referrerPackage) {
            referrerPackage.dependsOn(pkg);
          }
        } catch (error) {
          console.debug(`Error looking up referrer package: ${error}`);
        }
      }
    }

    // Create manifests
    const manifests: Array<Manifest> = [];

    console.debug("Dependency Graphs:");
    console.debug(JSON.stringify(dependencyGraphs, null, 2));

    // Check the locationsFoundAt for every package and add each as a manifest
    this.addPackagesToManifests(packages, manifests, dependencyGraphs);

    return manifests;
  }

  private addPackagesToManifests(packages: Array<ComponentDetectionPackage>, manifests: Array<Manifest>, dependencyGraphs: DependencyGraphs): void {
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
      let packageUrl = `${packageUrlJson.Scheme}:${packageUrlJson.Type}/`;
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

  private async getLatestReleaseURL(): Promise<string> {
    let octokit: Octokit = this.octokit;

    if (this.baseUrl !== 'https://api.github.com') {
      octokit = new Octokit({
        auth: "", request: { fetch: fetch }, log: {
          debug: console.debug,
          info: console.info,
          warn: console.warn,
          error: console.error
        },
      });
    }

    const owner = "microsoft";
    const repo = "component-detection";
    console.debug(`Attempting to download latest release from ${owner}/${repo}`);

    try {
      const latestRelease = await octokit.request("GET /repos/{owner}/{repo}/releases/latest", { owner, repo });

      let downloadURL: string = "";
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
  public normalizeDependencyGraphPaths(
    dependencyGraphs: DependencyGraphs,
    filePathInput: string
  ): DependencyGraphs {
    // Resolve the base directory from filePathInput (relative to cwd if not absolute)
    const baseDir = path.resolve(process.cwd(), filePathInput);
    // Use a null-prototype object to avoid prototype pollution
    const normalized: DependencyGraphs = Object.create(null);
    for (const absPath in dependencyGraphs) {
      // Only process own properties
      if (!Object.prototype.hasOwnProperty.call(dependencyGraphs, absPath)) continue;
      // Make the path relative to the baseDir
      let relPath = path.relative(baseDir, absPath).replace(/\\/g, '/');
      // Guard against special keys that could lead to prototype injection
      if (relPath === '__proto__' || relPath === 'constructor' || relPath === 'prototype') {
        console.warn(`Skipping unsafe manifest key: ${relPath}`);
        continue;
      }
      // Define property safely
      Object.defineProperty(normalized, relPath, {
        value: dependencyGraphs[absPath],
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return normalized;
  }
}

class ComponentDetectionPackage extends Package {
  public packageUrlString: string;

  constructor(packageUrl: string, public id: string, public isDevelopmentDependency: boolean, public topLevelReferrers: any[],
    public locationsFoundAt: any[], public containerDetailIds: any[], public containerLayerIds: any[]) {
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










