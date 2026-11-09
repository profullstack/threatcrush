import { parentPort, workerData } from 'node:worker_threads';
import { SignatureSet } from '../engine';
import { scanFileSync, type FileOutcome } from './scan-file';

/** What {@link scanPaths} hands each worker at start. */
export interface ScanWorkerInit {
  cap: number;
  maxFile: number;
  /** Full signature list, built-ins included; omitted = the built-in set. */
  signatures?: Array<[string, string]>;
}

export interface ScanWorkerRequest {
  id: number;
  files: string[];
}

export interface ScanWorkerReply {
  id: number;
  out: FileOutcome[];
}

/**
 * Body of a CrushAV scan worker thread. A host bundles a file that calls this
 * and passes its path to `scanPaths({ workerScript })`.
 */
export function runScanWorker(): void {
  const port = parentPort;
  if (!port) throw new Error('runScanWorker must run inside a worker thread');
  const init = workerData as ScanWorkerInit;
  const opts = {
    cap: init.cap,
    maxFile: init.maxFile,
    signatures: init.signatures ? new SignatureSet(init.signatures) : undefined,
  };
  // Batches run one after another: the scanner reuses its read buffers.
  let chain: Promise<void> = Promise.resolve();
  port.on('message', (msg: ScanWorkerRequest) => {
    chain = chain.then(async () => {
      const out: FileOutcome[] = [];
      for (const f of msg.files) out.push(await scanFileSync(f, opts));
      port.postMessage({ id: msg.id, out } satisfies ScanWorkerReply);
    });
  });
}
