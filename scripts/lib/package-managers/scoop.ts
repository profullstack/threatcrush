/**
 * Scoop Package Manager
 *
 * Submits to a Scoop bucket repository (profullstack/scoop-threatcrush).
 */

import { BasePackageManager } from './base.js';
import { resolveAssetSha256 } from './sha256.js';
import type { PackageManagerConfig, ReleaseInfo, SubmissionResult, Logger } from './types.js';

const DEFAULT_BUCKET_OWNER = 'profullstack';
const DEFAULT_BUCKET_REPO = 'scoop-threatcrush';

export class ScoopPackageManager extends BasePackageManager {
  readonly name = 'scoop';
  readonly displayName = 'Scoop';
  readonly platform = 'windows' as const;
  readonly priority = 2;

  private readonly bucketOwner: string;
  private readonly bucketRepo: string;

  constructor(config: PackageManagerConfig, logger: Logger) {
    super(config, logger);
    this.bucketOwner =
      (config.additionalConfig?.bucketOwner as string | undefined) ?? DEFAULT_BUCKET_OWNER;
    this.bucketRepo =
      (config.additionalConfig?.bucketRepo as string | undefined) ?? DEFAULT_BUCKET_REPO;
  }

  isConfigured(): Promise<boolean> {
    return Promise.resolve(this.config.enabled && !!this.getGitHubToken());
  }

  async checkExisting(version: string): Promise<boolean> {
    try {
      const file = await this.getFileContent(
        this.bucketOwner,
        this.bucketRepo,
        'bucket/threatcrush.json'
      );

      if (!file) return false;

      const manifest = JSON.parse(file.content) as { version?: string };
      return manifest.version === version;
    } catch {
      return false;
    }
  }

  async generateManifest(release: ReleaseInfo): Promise<string> {
    // Find the Windows installer (NSIS exe)
    const x64Exe = this.findAsset(
      release,
      (a) => a.name.endsWith('.exe') && a.name.includes('x64')
    );

    // If no x64 specific, find any exe
    const exe = x64Exe ?? this.findAsset(release, (a) => a.name.endsWith('.exe'));

    const sha256 = exe ? await resolveAssetSha256(exe) : '';

    const manifest = {
      version: release.version,
      description: 'Collaborative screen sharing with remote control',
      homepage: 'https://threatcrush.com',
      license: 'MIT',
      url:
        exe?.downloadUrl ??
        `https://github.com/profullstack/threatcrush/releases/download/v${release.version}/ThreatCrush-${release.version}-x64.exe`,
      hash: sha256,
      installer: {
        args: ['/S', '/D=$dir'],
      },
      uninstaller: {
        file: '$dir\\Uninstall ThreatCrush.exe',
        args: ['/S'],
      },
      shortcuts: [['ThreatCrush.exe', 'ThreatCrush']],
      checkver: {
        github: 'https://github.com/profullstack/threatcrush',
      },
      autoupdate: {
        url: `https://github.com/profullstack/threatcrush/releases/download/v$version/ThreatCrush-$version-x64.exe`,
      },
    };

    return Promise.resolve(JSON.stringify(manifest, null, 2));
  }

  async submit(release: ReleaseInfo, dryRun = false): Promise<SubmissionResult> {
    // Check if already exists
    if (await this.checkExisting(release.version)) {
      return {
        packageManager: this.name,
        status: 'skipped',
        message: `Version ${release.version} already exists in bucket`,
        alreadyExists: true,
      };
    }

    const manifest = await this.generateManifest(release);

    if (dryRun) {
      this.logger.info('Dry run - generated Scoop manifest:');
      console.log(manifest);
      return {
        packageManager: this.name,
        status: 'skipped',
        message: 'Dry run - manifest generated',
      };
    }

    // Ensure the bucket repository exists
    await this.ensureRepo(this.bucketOwner, this.bucketRepo, 'Scoop bucket for ThreatCrush', false);

    // Ensure bucket directory exists
    const bucketDir = await this.getFileContent(
      this.bucketOwner,
      this.bucketRepo,
      'bucket/.gitkeep'
    );
    if (!bucketDir) {
      try {
        await this.createOrUpdateFile(
          this.bucketOwner,
          this.bucketRepo,
          'bucket/.gitkeep',
          '',
          'Create bucket directory'
        );
      } catch {
        // Directory might already exist
      }
    }

    // Submit directly to the bucket (we own this repo)
    return this.submitDirect(
      this.bucketOwner,
      this.bucketRepo,
      [
        {
          path: 'bucket/threatcrush.json',
          content: manifest,
        },
      ],
      `threatcrush: Update to ${release.version}`
    );
  }
}
