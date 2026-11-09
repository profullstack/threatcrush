// Worker-thread entry for `threatcrush av scan`: reads, hashes and checks files
// in parallel. Built to dist/av-worker.js next to the CLI bundle.
import { runScanWorker } from '@threatcrush/av/node';

runScanWorker();
