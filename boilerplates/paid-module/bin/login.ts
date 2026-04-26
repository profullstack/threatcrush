#!/usr/bin/env node
/**
 * paid-feed-example-login
 *
 * Prompts for a license key (or accepts --key=...) and persists it to
 * ~/.config/threatcrush/paid-feed-example/license.json.
 */

import { createInterface } from 'node:readline/promises';
import { stdin, stdout, argv, exit } from 'node:process';
import {
  validateWithBackend,
  writeLicense,
  licensePath,
  MODULE_NAME,
} from '../src/auth.js';

function flag(name: string): string | null {
  const prefix = `--${name}=`;
  const hit = argv.find((a) => a.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

async function prompt(message: string): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question(message);
    return answer.trim();
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const fromFlag = flag('key');
  const email = flag('email') ?? undefined;
  const licenseKey =
    fromFlag ?? (await prompt(`License key for ${MODULE_NAME}: `));

  if (!licenseKey) {
    console.error('No license key provided.');
    exit(1);
  }

  const verdict = await validateWithBackend(licenseKey);
  if (!verdict.ok) {
    console.error(`License rejected: ${verdict.reason}`);
    exit(1);
  }

  await writeLicense({
    license_key: licenseKey,
    email: email ?? verdict.email,
    activated_at: new Date().toISOString(),
  });

  console.log(`Activated. License saved to ${licensePath()}`);
}

main().catch((err) => {
  console.error('login failed:', err);
  exit(1);
});
