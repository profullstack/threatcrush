import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const CLI_CONFIG_DIR = join(homedir(), '.threatcrush');
export const CLI_CONFIG_PATH = join(CLI_CONFIG_DIR, 'config.json');

export interface CliConfig {
  email?: string;
  user_id?: string;
  token?: string;
  refresh_token?: string;
  expires_at?: number;
  display_name?: string;
  current_org_id?: string;
  current_org_slug?: string;
}

export function readCliConfig(): CliConfig {
  try {
    return JSON.parse(readFileSync(CLI_CONFIG_PATH, 'utf-8')) as CliConfig;
  } catch {
    return {};
  }
}

export function writeCliConfig(config: CliConfig): void {
  if (!existsSync(CLI_CONFIG_DIR)) mkdirSync(CLI_CONFIG_DIR, { recursive: true });
  writeFileSync(CLI_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
  try { chmodSync(CLI_CONFIG_PATH, 0o600); } catch { /* non-posix */ }
}

export function updateCliConfig(patch: Partial<CliConfig>): CliConfig {
  const current = readCliConfig();
  const next = { ...current, ...patch };
  writeCliConfig(next);
  return next;
}

export function clearCliConfig(keys?: Array<keyof CliConfig>): void {
  const current = readCliConfig();
  if (!keys) {
    writeCliConfig({});
    return;
  }
  for (const key of keys) delete current[key];
  writeCliConfig(current);
}

export function isLoggedIn(): boolean {
  const cfg = readCliConfig();
  if (!cfg.token) return false;
  if (cfg.expires_at && cfg.expires_at * 1000 < Date.now()) return false;
  return true;
}

export function authHeaders(): Record<string, string> {
  const cfg = readCliConfig();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (cfg.token) headers['Authorization'] = `Bearer ${cfg.token}`;
  return headers;
}
