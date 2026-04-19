#!/usr/bin/env node
import { runDaemon } from './daemon/index.js';

runDaemon().catch((err) => {
  console.error('threatcrushd failed to start:', err);
  process.exit(1);
});
