# @threatcrush/av: CrushAV

Free, open-source (MIT) antivirus engine behind CrushAV on every ThreatCrush
surface: the CLI, the desktop app, the mobile app and the in-browser scanner at
[threatcrush.com/antivirus](https://threatcrush.com/antivirus).

```sh
curl -fsSL https://threatcrush.com/install.sh | sh
threatcrush av scan              # quick scan: downloads, desktop, temp, startup items
threatcrush av scan --full       # whole home folder
threatcrush av scan ~/Downloads --quarantine
threatcrush av watch             # real-time protection
threatcrush av quarantine list   # restore <id> | delete <id>
threatcrush av status            # engines, ClamAV version, quarantine
```

## Engines

- **Heuristics** (`src/rules.ts`): rules for disguised executables, droppers,
  booby-trapped shortcuts, Office macros, PDF launch actions, reverse shells,
  webshells, miners, ransomware behaviour and notes, credential dumpers, macOS
  stealers, ClickFix pages and HTML smuggling. Each rule is scoped to the file
  types where its pattern means an attack, to keep false positives near zero.
- **ClamAV** (`src/node/clamav.ts`): used automatically when `clamscan` or a
  running `clamd` is installed.
- **Hash reputation** (`lookupHashes`): SHA-256 fingerprints, never files, are
  checked at `POST https://threatcrush.com/api/av/lookup` (CIRCL hashlookup, plus
  MalwareBazaar when the server has a key). Known-good files never get flagged
  as merely suspicious.

## Use it in code

```ts
import { scanBytes } from '@threatcrush/av';          // browser, React Native, Node
import { scanPaths, quickScanTargets } from '@threatcrush/av/node';

const r = await scanBytes({ name: 'invoice.pdf', bytes });
r.verdict; // 'malicious' | 'suspicious' | 'clean'
const report = await scanPaths(quickScanTargets(), { clamav: 'auto' });
```

Big scans: bundle a file that calls `runScanWorker()` and pass it as
`workerScript`. Files are then read, hashed and checked in worker threads (one
per CPU by default, `concurrency` to change) with blocking I/O, which avoids
libuv's 4-thread file pool. Add `keepClean: false` to count clean files instead
of keeping them, so memory stays flat on millions of files. Without a worker
script everything runs on the calling thread with async I/O, which is what an
Electron main process wants.

```ts
// av-worker.ts, built next to your entry
import { runScanWorker } from '@threatcrush/av/node';
runScanWorker();

// caller
await scanPaths(fullScanTargets(), { workerScript: join(__dirname, 'av-worker.js'), keepClean: false });
```

Custom signatures: put `sha256 Name` lines in `~/.threatcrush/av/signatures.txt`.
