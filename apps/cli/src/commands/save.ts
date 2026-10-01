import { existsSync, readFileSync } from 'node:fs';
import chalk from 'chalk';
import TOML from '@iarna/toml';
import { banner } from '../core/logger.js';
import { cloudFetch, hasSession } from '../core/cli-config.js';
import { currentLink } from '../core/cloud-events.js';
import { PATHS } from '../daemon/paths.js';

/**
 * Alert channels carry SMTP passwords, webhook URLs and API keys; none of that
 * leaves the machine. The server redacts again with the same rule.
 */
const SECRET_KEY = /pass(word)?|secret|token|api_?key|private|webhook|dsn|url|routing_key|auth/i;
export const REDACTED = '[redacted]';

export function redactConfig(value: unknown, depth = 0): unknown {
  if (depth > 10) return REDACTED;
  if (Array.isArray(value)) return value.map((v) => redactConfig(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SECRET_KEY.test(key) && v !== null && typeof v !== 'object' && typeof v !== 'boolean'
        ? REDACTED
        : redactConfig(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * `threatcrush save` — store this machine's daemon config on its dashboard
 * server, so the fleet's settings are visible in one place. Reads the same file
 * the daemon reads (/etc/threatcrush/threatcrushd.conf under root).
 */
export async function saveCommand(opts: { config?: string } = {}): Promise<void> {
  banner();

  if (!hasSession()) {
    console.log(chalk.yellow('  Not logged in.'));
    console.log(chalk.dim(`  Log in with ${chalk.white('threatcrush login')}, then link this machine with ${chalk.white('threatcrush servers link')}.\n`));
    process.exitCode = 1;
    return;
  }
  const link = currentLink();
  if (!link) {
    console.log(chalk.yellow('  This machine is not linked to a dashboard server.'));
    console.log(chalk.dim(`  Link it with ${chalk.white('threatcrush servers link')}.\n`));
    process.exitCode = 1;
    return;
  }

  const path = opts.config ?? PATHS.configFile;
  let config: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      config = TOML.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>;
    } catch (err) {
      console.log(chalk.red(`  ✗ ${path} is not valid TOML: ${(err as Error).message}\n`));
      process.exitCode = 1;
      return;
    }
  }

  const res = await cloudFetch(`/api/orgs/${link.orgId}/servers/${link.serverId}/config`, {
    method: 'PUT',
    body: JSON.stringify({ config: redactConfig(config), source: path }),
  });
  const data = await res.json().catch(() => ({})) as { server?: { name?: string }; error?: string };
  if (!res.ok) {
    console.log(chalk.red(`  ✗ ${data.error || `Save failed (${res.status})`}\n`));
    process.exitCode = 1;
    return;
  }

  const sections = Object.keys(config);
  console.log(chalk.green(`  ✓ Saved ${path} to ${chalk.white(data.server?.name ?? link.serverId)}`));
  console.log(chalk.dim(
    sections.length > 0
      ? `    Sections: ${sections.join(', ')} (secrets redacted)\n`
      : '    No config file here, so the built-in defaults were saved as empty.\n',
  ));
}
