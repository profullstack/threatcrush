#!/usr/bin/env node
/**
 * paid-feed-example-logout
 *
 * Removes the saved license file. The module will refuse to poll on next
 * start until you re-run `*-login`.
 */

import { exit } from 'node:process';
import { clearLicense, licensePath } from '../src/auth.js';

async function main(): Promise<void> {
  const removed = await clearLicense();
  if (removed) {
    console.log(`Logged out. Removed ${licensePath()}`);
  } else {
    console.log('No saved license to remove.');
  }
}

main().catch((err) => {
  console.error('logout failed:', err);
  exit(1);
});
