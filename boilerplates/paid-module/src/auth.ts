/**
 * Auth helpers shared between the module runtime and the login/logout/status
 * CLI entrypoints. Persists a license blob at:
 *   ~/.config/threatcrush/<module-name>/license.json
 *
 * The blob is intentionally minimal — { license_key, email, activated_at }.
 * Replace the stub `validateWithBackend()` with a real call to your billing
 * API once you have one.
 */

import { readFile, writeFile, mkdir, unlink, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const MODULE_NAME = 'paid-feed-example';

export interface LicenseBlob {
  license_key: string;
  email?: string;
  activated_at: string;
}

export function configDir(moduleName = MODULE_NAME): string {
  const base =
    process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.length > 0
      ? process.env.XDG_CONFIG_HOME
      : join(homedir(), '.config');
  return join(base, 'threatcrush', moduleName);
}

export function licensePath(moduleName = MODULE_NAME): string {
  return join(configDir(moduleName), 'license.json');
}

export async function readLicense(
  moduleName = MODULE_NAME,
): Promise<LicenseBlob | null> {
  try {
    const raw = await readFile(licensePath(moduleName), 'utf8');
    return JSON.parse(raw) as LicenseBlob;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function writeLicense(
  blob: LicenseBlob,
  moduleName = MODULE_NAME,
): Promise<void> {
  const dir = configDir(moduleName);
  await mkdir(dir, { recursive: true });
  await writeFile(licensePath(moduleName), JSON.stringify(blob, null, 2), {
    mode: 0o600,
  });
}

export async function clearLicense(
  moduleName = MODULE_NAME,
): Promise<boolean> {
  try {
    await unlink(licensePath(moduleName));
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw err;
  }
}

export async function licenseExists(
  moduleName = MODULE_NAME,
): Promise<boolean> {
  try {
    await stat(licensePath(moduleName));
    return true;
  } catch {
    return false;
  }
}

/**
 * Stub: in a real module this calls your billing/license backend with the
 * key the user typed and returns whether it's active. Replace the body with
 * a real fetch — e.g. POST https://api.your-product.com/v1/license/verify.
 */
export async function validateWithBackend(
  licenseKey: string,
): Promise<{ ok: true; email?: string } | { ok: false; reason: string }> {
  if (!licenseKey || licenseKey.length < 8) {
    return { ok: false, reason: 'license key looks too short' };
  }
  // TODO: replace with real verification call:
  //
  // const res = await fetch(`${API_BASE}/v1/license/verify`, {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify({ license_key: licenseKey }),
  // });
  // if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
  // const data = await res.json() as { active: boolean; email?: string };
  // return data.active ? { ok: true, email: data.email } : { ok: false, reason: 'inactive' };
  return { ok: true };
}
