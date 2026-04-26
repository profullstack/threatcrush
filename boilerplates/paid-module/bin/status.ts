#!/usr/bin/env node
/**
 * paid-feed-example-status
 *
 * Prints the saved license metadata and re-validates it against the backend.
 */

import { exit } from 'node:process';
import { readLicense, validateWithBackend, licensePath } from '../src/auth.js';

async function main(): Promise<void> {
  const blob = await readLicense();
  if (!blob) {
    console.log(`Not logged in. (${licensePath()} does not exist)`);
    console.log('Run the *-login command to activate.');
    exit(2);
  }

  console.log(`License key:  ${blob.license_key.slice(0, 4)}…${blob.license_key.slice(-4)}`);
  if (blob.email) console.log(`Email:        ${blob.email}`);
  console.log(`Activated at: ${blob.activated_at}`);

  const verdict = await validateWithBackend(blob.license_key);
  if (verdict.ok) {
    console.log('Backend says:  active');
  } else {
    console.log(`Backend says:  inactive — ${verdict.reason}`);
    exit(1);
  }
}

main().catch((err) => {
  console.error('status failed:', err);
  exit(1);
});
