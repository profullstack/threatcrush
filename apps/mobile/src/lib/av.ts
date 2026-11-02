import { applyReputation, lookupHashes, scanBytes, type AvFileResult } from '@threatcrush/av';
import { config } from '../config';

/** Largest file the phone reads into memory to scan. */
export const MAX_MOBILE_BYTES = 30 * 1024 * 1024;

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOOKUP = new Uint8Array(256).fill(255);
for (let i = 0; i < B64.length; i++) LOOKUP[B64.charCodeAt(i)] = i;

/** Base64 to bytes without atob/Buffer (Hermes has neither reliably). */
export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let o = 0;
  for (let i = 0; i + 1 < clean.length; i += 4) {
    const a = LOOKUP[clean.charCodeAt(i)];
    const b = LOOKUP[clean.charCodeAt(i + 1)];
    const c = i + 2 < clean.length ? LOOKUP[clean.charCodeAt(i + 2)] : 0;
    const d = i + 3 < clean.length ? LOOKUP[clean.charCodeAt(i + 3)] : 0;
    out[o++] = (a << 2) | (b >> 4);
    if (i + 2 < clean.length) out[o++] = ((b & 15) << 4) | (c >> 2);
    if (i + 3 < clean.length) out[o++] = ((c & 3) << 6) | d;
  }
  return out.subarray(0, o);
}

/** Human file name from a file:// or Android SAF content:// URI. */
export function nameFromUri(uri: string): string {
  let s = uri;
  try {
    s = decodeURIComponent(uri);
  } catch {
    /* keep raw */
  }
  return s.split(/[/:]/).filter(Boolean).pop() ?? uri;
}

export async function scanBase64(name: string, b64: string): Promise<AvFileResult> {
  const bytes = base64ToBytes(b64);
  return scanBytes({ name, bytes });
}

/** Fold hash reputation into results; offline-safe. */
export async function withReputation(results: AvFileResult[]): Promise<AvFileResult[]> {
  const hashes = results.map((r) => r.sha256).filter((h): h is string => !!h);
  if (!hashes.length) return results;
  const reps = await lookupHashes(hashes, { endpoint: `${config.apiUrl}/api/av/lookup`, timeoutMs: 15000 });
  return results.map((r) => (r.sha256 ? applyReputation(r, reps.get(r.sha256)) : r));
}
