import { createHash } from 'node:crypto';

/**
 * Compute the SHA256 hex digest of a downloadable file.
 * Used by package-manager scripts when release assets lack a pre-computed hash.
 */
export async function computeSha256FromUrl(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download asset from ${url}: ${response.status} ${response.statusText}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  return createHash('sha256').update(buffer).digest('hex');
}

/**
 * Resolve the SHA256 for a release asset.
 * Uses pre-computed hash if available; otherwise downloads and computes it.
 */
export async function resolveAssetSha256(asset: { downloadUrl: string; sha256?: string }): Promise<string> {
  if (asset.sha256) {
    return asset.sha256;
  }
  return computeSha256FromUrl(asset.downloadUrl);
}
