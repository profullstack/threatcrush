#!/usr/bin/env node
import { runDaemon } from './daemon/index.js';
import { installUserAgent } from './core/user-agent.js';

installUserAgent();

runDaemon().catch((err) => {
  console.error('threatcrushd failed to start:', err);
  process.exit(1);
});
