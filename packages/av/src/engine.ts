import { sniffKind } from './magic';
import { buildContext, runRules, RULES, type AvRule } from './rules';
import { sha256Hex, SHA256_RE } from './sha256';
import type { AvDetection, AvFileResult, AvVerdict, HashReputation } from './types';

/** Heuristics read at most this much of a file. Hashing always covers all of it. */
export const DEFAULT_HEURISTIC_BYTES = 16 * 1024 * 1024;

/**
 * Exact-hash signatures: lower-case SHA-256 to malware name. Built-in entries
 * are test files only; real coverage comes from ClamAV and hash reputation,
 * and users can load their own list with {@link SignatureSet.load}.
 */
export class SignatureSet {
  private map = new Map<string, string>();

  constructor(entries: Iterable<[string, string]> = BUILTIN_SIGNATURES) {
    for (const [h, n] of entries) this.add(h, n);
  }

  add(sha256: string, name: string): void {
    const h = sha256.trim().toLowerCase();
    if (SHA256_RE.test(h)) this.map.set(h, name || 'Malware');
  }

  /** Load `sha256 [name]` lines; `#` starts a comment. Returns how many were added. */
  load(text: string): number {
    let n = 0;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      if (!line) continue;
      const [h, ...rest] = line.split(/[\s,;]+/);
      if (SHA256_RE.test(h.toLowerCase())) {
        this.add(h, rest.join(' '));
        n++;
      }
    }
    return n;
  }

  get(sha256: string): string | undefined {
    return this.map.get(sha256.toLowerCase());
  }

  get size(): number {
    return this.map.size;
  }
}

export const BUILTIN_SIGNATURES: Array<[string, string]> = [
  ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR-Test-File'],
];

export interface ScanBytesInput {
  /** Path or display name; only used for extension checks and display. */
  name: string;
  /** The file, or its first N bytes when it is large. */
  bytes: Uint8Array;
  /** Real size when `bytes` is a prefix. Defaults to bytes.length. */
  size?: number;
  /** Precomputed SHA-256 of the whole file (when bytes is a prefix, pass it). */
  sha256?: string | null;
}

export interface ScanBytesOptions {
  rules?: AvRule[];
  signatures?: SignatureSet;
}

const IMPACT_RANK = { info: 0, suspicious: 1, malicious: 2 } as const;

export function verdictOf(detections: AvDetection[]): AvVerdict {
  let worst = 0;
  for (const d of detections) worst = Math.max(worst, IMPACT_RANK[d.impact]);
  return worst === 2 ? 'malicious' : worst === 1 ? 'suspicious' : 'clean';
}

/** Scan one in-memory file with signatures and heuristics. Pure; no I/O. */
export async function scanBytes(input: ScanBytesInput, opts: ScanBytesOptions = {}): Promise<AvFileResult> {
  const size = input.size ?? input.bytes.length;
  const complete = input.bytes.length >= size;
  const sha256 = input.sha256 ?? (complete ? await sha256Hex(input.bytes) : null);
  const kind = sniffKind(input.bytes);
  const detections: AvDetection[] = [];

  const sigs = opts.signatures ?? DEFAULT_SIGNATURES;
  const known = sha256 ? sigs.get(sha256) : undefined;
  if (known) {
    detections.push({
      engine: 'signature',
      id: `CrushAV.Signature.${known.replace(/[^\w.-]+/g, '_')}`,
      name: known,
      severity: known.startsWith('EICAR') ? 'low' : 'critical',
      impact: 'malicious',
      description: known.startsWith('EICAR')
        ? 'The harmless standard antivirus test file. Seeing this means the scanner works.'
        : `This exact file is known malware (${known}). Quarantine or delete it.`,
    });
  }

  const ctx = buildContext(input.name, input.bytes, kind, size);
  for (const d of runRules(ctx, opts.rules ?? RULES)) {
    // The signature already said EICAR; don't list it twice.
    if (known && d.id === 'CrushAV.Test.EICAR') continue;
    detections.push(d);
  }

  return {
    path: input.name,
    size,
    sha256,
    kind,
    verdict: verdictOf(detections),
    detections,
    note: complete ? undefined : `heuristics read the first ${Math.round(input.bytes.length / 1048576)} MB`,
  };
}

const DEFAULT_SIGNATURES = new SignatureSet();

/** Trust score at or above which CIRCL treats a hash as a known-good file. */
export const TRUSTED_SCORE = 50;

/**
 * Fold hash reputation into a result.
 *
 * Known-malicious adds a detection. Known-good (in NSRL or a major distro's
 * package set) downgrades merely *suspicious* heuristics to info, because a
 * file shipped by Microsoft, Apple or Debian is not a dropper because it
 * contains the word "powershell". Malicious heuristics are left alone: a known
 * good program renamed to `.pdf` is still a trap.
 */
export function applyReputation(result: AvFileResult, rep: HashReputation | undefined): AvFileResult {
  if (!rep) return result;
  const detections = [...result.detections];
  if (rep.knownMalicious) {
    detections.push({
      engine: 'reputation',
      id: `CrushAV.Reputation.${(rep.malwareName ?? 'KnownMalware').replace(/[^\w.-]+/g, '_')}`,
      name: rep.malwareName ?? 'Known malware',
      severity: 'critical',
      impact: 'malicious',
      description: `This exact file is listed as malware by ${rep.knownMalicious}. Quarantine or delete it.`,
    });
  } else if ((rep.trust ?? 0) >= TRUSTED_SCORE) {
    for (let i = 0; i < detections.length; i++) {
      const d = detections[i];
      if (d.engine === 'heuristic' && d.impact === 'suspicious') {
        detections[i] = { ...d, impact: 'info', description: `${d.description} (Downgraded: this exact file is a known, published file from a trusted software source.)` };
      }
    }
  }
  return { ...result, detections, verdict: verdictOf(detections) };
}
