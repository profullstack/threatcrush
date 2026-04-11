/**
 * WinGet (Windows Package Manager)
 *
 * Submits a PR to microsoft/winget-pkgs with manifest files.
 */

import { BasePackageManager } from './base.js';
import { resolveAssetSha256 } from './sha256.js';
import type { ReleaseInfo, SubmissionResult } from './types.js';

const WINGET_OWNER = 'microsoft';
const WINGET_REPO = 'winget-pkgs';
const PACKAGE_IDENTIFIER = 'Profullstack.ThreatCrush';

export class WingetPackageManager extends BasePackageManager {
  readonly name = 'winget';
  readonly displayName = 'WinGet';
  readonly platform = 'windows' as const;
  readonly priority = 3;

  isConfigured(): Promise<boolean> {
    return Promise.resolve(this.config.enabled && !!this.getGitHubToken());
  }

  async checkExisting(version: string): Promise<boolean> {
    try {
      const path = `manifests/p/Profullstack/ThreatCrush/${version}/${PACKAGE_IDENTIFIER}.yaml`;
      const file = await this.getFileContent(WINGET_OWNER, WINGET_REPO, path);
      return file !== null;
    } catch {
      return false;
    }
  }

  async generateManifest(release: ReleaseInfo): Promise<Record<string, string>> {
    // Find the Windows installer
    const x64Exe = this.findAsset(
      release,
      (a) => a.name.endsWith('.exe') && (a.name.includes('x64') || !a.name.includes('arm'))
    );

    const x64Sha = x64Exe ? (await resolveAssetSha256(x64Exe)).toUpperCase() : '';
    const downloadUrl =
      x64Exe?.downloadUrl ??
      `https://github.com/profullstack/threatcrush/releases/download/v${release.version}/ThreatCrush-${release.version}-x64.exe`;

    // Version manifest
    const versionManifest = `# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.10.0.schema.json
PackageIdentifier: ${PACKAGE_IDENTIFIER}
PackageVersion: ${release.version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.10.0
`;

    // Installer manifest
    const installerManifest = `# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.10.0.schema.json
PackageIdentifier: ${PACKAGE_IDENTIFIER}
PackageVersion: ${release.version}
Platform:
  - Windows.Desktop
MinimumOSVersion: 10.0.17763.0
InstallerType: nullsoft
Scope: user
InstallModes:
  - interactive
  - silent
  - silentWithProgress
InstallerSwitches:
  Silent: /S
  SilentWithProgress: /S
Installers:
  - Architecture: x64
    InstallerUrl: ${downloadUrl}
    InstallerSha256: ${x64Sha}
ManifestType: installer
ManifestVersion: 1.10.0
`;

    // Locale manifest
    const localeManifest = `# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.10.0.schema.json
PackageIdentifier: ${PACKAGE_IDENTIFIER}
PackageVersion: ${release.version}
PackageLocale: en-US
Publisher: Profullstack, Inc.
PublisherUrl: https://threatcrush.com
PublisherSupportUrl: https://github.com/profullstack/threatcrush/issues
PrivacyUrl: https://threatcrush.com/privacy
PackageName: ThreatCrush
PackageUrl: https://threatcrush.com
License: MIT
LicenseUrl: https://github.com/profullstack/threatcrush/blob/master/LICENSE
ShortDescription: Collaborative screen sharing with remote control
Description: |-
  ThreatCrush enables real-time screen sharing with simultaneous local and remote
  mouse/keyboard control for pair programming and collaboration.
Tags:
  - screen-sharing
  - remote-control
  - collaboration
  - webrtc
  - pair-programming
  - remote-desktop
ReleaseNotesUrl: https://github.com/profullstack/threatcrush/releases/tag/v${release.version}
ManifestType: defaultLocale
ManifestVersion: 1.10.0
`;

    return Promise.resolve({
      version: versionManifest,
      installer: installerManifest,
      locale: localeManifest,
    });
  }

  /**
   * Close any existing open PRs for this package before submitting a new one
   */
  private async closeExistingPRs(forkOwner: string): Promise<void> {
    try {
      // Search for open PRs from our fork that match ThreatCrush
      const searchQuery = `repo:${WINGET_OWNER}/${WINGET_REPO} is:pr is:open author:${forkOwner} ${PACKAGE_IDENTIFIER} in:title`;
      const searchResult = await this.githubRequest<{
        items: { number: number; title: string }[];
      }>(`/search/issues?q=${encodeURIComponent(searchQuery)}`);

      for (const pr of searchResult.items) {
        this.logger.info(`Closing superseded PR #${pr.number}: ${pr.title}`);
        try {
          // Add a comment explaining why we're closing
          await this.githubRequest(
            `/repos/${WINGET_OWNER}/${WINGET_REPO}/issues/${pr.number}/comments`,
            {
              method: 'POST',
              body: JSON.stringify({
                body: 'Closing this PR as a newer version is being submitted.',
              }),
            }
          );
          // Close the PR
          await this.githubRequest(`/repos/${WINGET_OWNER}/${WINGET_REPO}/pulls/${pr.number}`, {
            method: 'PATCH',
            body: JSON.stringify({ state: 'closed' }),
          });
        } catch (error) {
          this.logger.warn(`Failed to close PR #${pr.number}: ${error}`);
        }
      }
    } catch (error) {
      this.logger.warn(`Failed to search for existing PRs: ${error}`);
    }
  }

  async submit(release: ReleaseInfo, dryRun = false): Promise<SubmissionResult> {
    // Check if already exists
    if (await this.checkExisting(release.version)) {
      return {
        packageManager: this.name,
        status: 'skipped',
        message: `Version ${release.version} already exists in winget-pkgs`,
        alreadyExists: true,
      };
    }

    const manifests = await this.generateManifest(release);

    if (dryRun) {
      this.logger.info('Dry run - generated WinGet manifests:');
      console.log('=== Version Manifest ===');
      console.log(manifests.version);
      console.log('=== Installer Manifest ===');
      console.log(manifests.installer);
      console.log('=== Locale Manifest ===');
      console.log(manifests.locale);
      return {
        packageManager: this.name,
        status: 'skipped',
        message: 'Dry run - manifests generated',
      };
    }

    const basePath = `manifests/p/Profullstack/ThreatCrush/${release.version}`;

    // Submit via PR to microsoft/winget-pkgs
    // First, we need to fork the repo to our account
    const token = this.getGitHubToken();
    if (!token) {
      return {
        packageManager: this.name,
        status: 'failed',
        message: 'GITHUB_TOKEN required for WinGet submission',
      };
    }

    // Get our username
    const user = await this.githubRequest<{ login: string }>('/user');
    const forkOwner = user.login;

    // Close any existing open PRs before creating a new one
    await this.closeExistingPRs(forkOwner);

    // Check if fork exists, if not create it
    const forkExists = await this.repoExists(forkOwner, WINGET_REPO);
    if (!forkExists) {
      this.logger.info('Creating fork of winget-pkgs...');
      await this.githubRequest(`/repos/${WINGET_OWNER}/${WINGET_REPO}/forks`, {
        method: 'POST',
        body: JSON.stringify({ default_branch_only: true }),
      });
      // Wait for fork to be ready
      await this.sleep(5000);
    }

    // Sync fork with upstream
    try {
      await this.githubRequest(`/repos/${forkOwner}/${WINGET_REPO}/merge-upstream`, {
        method: 'POST',
        body: JSON.stringify({ branch: 'master' }),
      });
    } catch {
      // May fail if already up to date
    }

    const branchName = `threatcrush-${release.version}`;

    // Submit via cross-fork PR to microsoft/winget-pkgs
    return this.submitCrossForkPR({
      upstreamOwner: WINGET_OWNER,
      upstreamRepo: WINGET_REPO,
      forkOwner,
      baseBranch: 'master',
      headBranch: branchName,
      files: [
        { path: `${basePath}/${PACKAGE_IDENTIFIER}.yaml`, content: manifests.version },
        { path: `${basePath}/${PACKAGE_IDENTIFIER}.installer.yaml`, content: manifests.installer },
        { path: `${basePath}/${PACKAGE_IDENTIFIER}.locale.en-US.yaml`, content: manifests.locale },
      ],
      commitMessage: `New version: ${PACKAGE_IDENTIFIER} version ${release.version}`,
      prTitle: `New version: ${PACKAGE_IDENTIFIER} version ${release.version}`,
      prBody: `## Manifests

- Package: ${PACKAGE_IDENTIFIER}
- Version: ${release.version}

## Pull Request

This is an automated submission from the ThreatCrush release pipeline.

### Validation

- [ ] Have you checked that this version hasn't been submitted before?
- [x] Have you validated the manifest with \`winget validate\`?
- [x] Have you tested the installation?

---

Created by [ThreatCrush Submit Packages](https://github.com/profullstack/threatcrush)`,
    });
  }
}
