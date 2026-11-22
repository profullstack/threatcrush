/**
 * UPX awareness for CrushAV.
 *
 * Malware authors run their binaries through UPX because it hides every string
 * a byte-level heuristic looks for: the stealer's database password, its
 * `INSERT INTO api_keys`, its exchange URLs. This module finds the UPX pack
 * header and inflates the payload so the heuristics see what the program will
 * see once it runs.
 *
 * Only the NRV2B/NRV2D/NRV2E codecs (UPX methods 2-10, the default for
 * Windows, Linux and macOS executables) are decoded, in pure TypeScript so it
 * works in the browser and on phones. LZMA-packed files (`upx --lzma`) are
 * reported as packed but not inflated.
 *
 * The output is the raw unpacked image (sections back to back), not a
 * runnable file, and x86 call/jump filters are not undone: both are fine for
 * string heuristics, which is all this is for. Every input byte is hostile,
 * so every read and every back-reference is bounds-checked and output is
 * capped.
 */

export type UpxMethod = 'nrv2b' | 'nrv2d' | 'nrv2e' | 'lzma' | 'unknown';

export interface UpxInfo {
  /** Byte offset of the `UPX!` pack header. */
  headerOffset: number;
  /** UPX pack-header format version (13 for UPX 3.9x-4.x). */
  version: number;
  /** UPX target format id (e.g. 36 win64/pe, 22 linux/amd64). */
  format: number;
  method: UpxMethod;
  methodId: number;
  level: number;
  /** Uncompressed and compressed length of the main block, from the header. */
  uLen: number;
  cLen: number;
}

export interface UpxUnpacked {
  info: UpxInfo;
  /** Inflated payload, or null when it could not be decoded (e.g. LZMA). */
  bytes: Uint8Array | null;
}

/** Never inflate more than this, whatever the header claims. */
export const UPX_MAX_OUTPUT = 64 * 1024 * 1024;

const MAGIC = [0x55, 0x50, 0x58, 0x21]; // "UPX!"

function methodName(id: number): UpxMethod {
  if (id === 2 || id === 3 || id === 4) return 'nrv2b';
  if (id === 5 || id === 6 || id === 7) return 'nrv2d';
  if (id === 8 || id === 9 || id === 10) return 'nrv2e';
  if (id === 14) return 'lzma';
  return 'unknown';
}

const le32 = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

/**
 * Find a valid UPX pack header. Real packers put it in the first few KB (PE)
 * or the last few KB (ELF/Mach-O), so only those windows are searched; a
 * "UPX!" string inside some document's text is not a packed program.
 */
export function findUpxHeader(b: Uint8Array): UpxInfo | null {
  const windows: Array<[number, number]> = [
    [0, Math.min(b.length, 8192)],
    [Math.max(0, b.length - 8192), b.length],
  ];
  for (const [from, to] of windows) {
    for (let i = from; i + 32 <= to; i++) {
      if (b[i] !== MAGIC[0] || b[i + 1] !== MAGIC[1] || b[i + 2] !== MAGIC[2] || b[i + 3] !== MAGIC[3]) continue;
      const version = b[i + 4];
      const format = b[i + 5];
      const methodId = b[i + 6];
      const level = b[i + 7];
      if (version < 10 || version > 20 || level > 10 || format === 0) continue;
      const uLen = le32(b, i + 16);
      const cLen = le32(b, i + 20);
      if (cLen === 0 || uLen === 0 || cLen >= uLen || uLen > 0x7fffffff) continue;
      return { headerOffset: i, version, format, method: methodName(methodId), methodId, level, uLen, cLen };
    }
  }
  return null;
}

/** Bounded LE32 bit reader shared by the NRV decoders. */
class Bits {
  bb = 0;
  bc = 0;
  constructor(
    readonly src: Uint8Array,
    public pos: number,
  ) {}
  bit(): number {
    if (this.bc > 0) return (this.bb >>> --this.bc) & 1;
    if (this.pos + 4 > this.src.length) throw new RangeError('upx: input overrun');
    this.bb = le32(this.src, this.pos);
    this.pos += 4;
    this.bc = 31;
    return (this.bb >>> 31) & 1;
  }
  byte(): number {
    if (this.pos >= this.src.length) throw new RangeError('upx: input overrun');
    return this.src[this.pos++];
  }
}

/**
 * Inflate one NRV2B/2D/2E LE32 stream starting at `start`. Returns the bytes
 * written, or throws on corrupt input. Stops at the end-of-stream marker or at
 * `maxOut`, whichever comes first.
 */
export function nrvDecompress(method: 'nrv2b' | 'nrv2d' | 'nrv2e', src: Uint8Array, start: number, maxOut: number): Uint8Array {
  const out = new Uint8Array(Math.min(maxOut, UPX_MAX_OUTPUT));
  const r = new Bits(src, start);
  let o = 0;
  let lastOff = 1;
  for (;;) {
    while (r.bit()) {
      if (o >= out.length) return out;
      out[o++] = r.byte();
    }
    let off = 1;
    let len: number;
    if (method === 'nrv2b') {
      do {
        off = off * 2 + r.bit();
        if (off > 0x1000002) throw new RangeError('upx: bad offset');
      } while (!r.bit());
      if (off === 2) off = lastOff;
      else {
        off = ((off - 3) * 256 + r.byte()) >>> 0;
        if (off === 0xffffffff) break;
        lastOff = ++off;
      }
      len = r.bit();
      len = len * 2 + r.bit();
      if (len === 0) {
        len = 1;
        do {
          len = len * 2 + r.bit();
          if (len > out.length) throw new RangeError('upx: bad length');
        } while (!r.bit());
        len += 2;
      }
      len += off > 0xd00 ? 1 : 0;
    } else {
      for (;;) {
        off = off * 2 + r.bit();
        if (r.bit()) break;
        off = (off - 1) * 2 + r.bit();
        if (off > 0x1000002) throw new RangeError('upx: bad offset');
      }
      if (off === 2) {
        off = lastOff;
        len = r.bit();
      } else {
        off = ((off - 3) * 256 + r.byte()) >>> 0;
        if (off === 0xffffffff) break;
        len = (off ^ 0xffffffff) & 1;
        off >>>= 1;
        lastOff = ++off;
      }
      if (method === 'nrv2d') {
        len = len * 2 + r.bit();
        if (len === 0) {
          len = 1;
          do {
            len = len * 2 + r.bit();
            if (len > out.length) throw new RangeError('upx: bad length');
          } while (!r.bit());
          len += 2;
        }
      } else if (len) {
        len = 1 + r.bit();
      } else if (r.bit()) {
        len = 3 + r.bit();
      } else {
        len = 1;
        do {
          len = len * 2 + r.bit();
          if (len > out.length) throw new RangeError('upx: bad length');
        } while (!r.bit());
        len += 3;
      }
      len += off > 0x500 ? 1 : 0;
    }
    if (off > o) throw new RangeError('upx: back-reference before start');
    const n = len + 1;
    for (let k = 0; k < n; k++) {
      if (o >= out.length) return out;
      out[o] = out[o - off];
      o++;
    }
  }
  return out.subarray(0, o);
}

/**
 * Where the compressed stream starts. PE stubs put it at the start of the
 * second section's raw data (UPX1); ELF and Mach-O wrap each block in an
 * 12-byte `b_info` (sz_unc, sz_cpr, method, filter, cto, 0). Both are tried,
 * and a candidate only counts when it decodes to the exact length the header
 * promised, so a wrong guess can never produce garbage "strings".
 */
function candidateStarts(b: Uint8Array, info: UpxInfo): number[] {
  // Windows PE: the stream follows the 32-byte pack header directly
  // (measured on UPX 4.2.4 win64/pe: header at 0x205, data at 0x225).
  const starts: number[] = [info.headerOffset + 32];
  // PE: section table → raw pointer of each section with data.
  if (b[0] === 0x4d && b[1] === 0x5a && b.length > 0x40) {
    const pe = le32(b, 0x3c);
    if (pe + 24 < b.length && le32(b, pe) === 0x00004550) {
      const nSec = b[pe + 6] | (b[pe + 7] << 8);
      const optSize = b[pe + 20] | (b[pe + 21] << 8);
      const sec = pe + 24 + optSize;
      for (let s = 0; s < nSec && s < 16; s++) {
        const e = sec + s * 40;
        if (e + 40 > b.length) break;
        const rawSize = le32(b, e + 16);
        const rawPtr = le32(b, e + 20);
        if (rawSize >= info.cLen && rawPtr < b.length) starts.push(rawPtr);
      }
    }
  }
  // b_info headers: sz_unc == uLen, sz_cpr == cLen, method byte matches.
  for (let i = 0; i + 12 <= b.length; i += 4) {
    if (le32(b, i) === info.uLen && le32(b, i + 4) === info.cLen && b[i + 8] === info.methodId) starts.push(i + 12);
  }
  return starts;
}

/** Unpack a UPX-packed executable for scanning. Returns null if it is not one. */
export function upxUnpack(b: Uint8Array): UpxUnpacked | null {
  const info = findUpxHeader(b);
  if (!info) return null;
  if (info.method !== 'nrv2b' && info.method !== 'nrv2d' && info.method !== 'nrv2e') return { info, bytes: null };
  if (info.uLen > UPX_MAX_OUTPUT) return { info, bytes: null };
  for (const start of candidateStarts(b, info)) {
    try {
      const out = nrvDecompress(info.method, b, start, info.uLen);
      if (out.length === info.uLen) return { info, bytes: out };
    } catch {
      // Wrong start or corrupt stream; try the next candidate.
    }
  }
  const blocks = decodeBlockChain(b, info);
  return { info, bytes: blocks };
}

/**
 * ELF and Mach-O: the payload is a run of `b_info` blocks, one per segment
 * (and some per 512 KB chunk), each `{sz_unc, sz_cpr, method, filter, cto, 0}`
 * followed by `sz_cpr` bytes. Walk the file for headers whose method matches
 * the pack header and keep each block that inflates to exactly `sz_unc`.
 */
function decodeBlockChain(b: Uint8Array, info: UpxInfo): Uint8Array | null {
  const method = info.method as 'nrv2b' | 'nrv2d' | 'nrv2e';
  const parts: Uint8Array[] = [];
  let total = 0;
  for (let i = 0; i + 12 <= b.length; ) {
    const unc = le32(b, i);
    const cpr = le32(b, i + 4);
    // A segment that did not compress is stored as-is (sz_cpr == sz_unc).
    // Only trusted right after a block that decoded, so random bytes that
    // happen to repeat a number never count as one.
    if (parts.length && cpr === unc && unc > 0 && unc <= info.uLen && i + 12 + cpr <= b.length && total + unc <= UPX_MAX_OUTPUT) {
      parts.push(b.subarray(i + 12, i + 12 + cpr));
      total += unc;
      i += 12 + cpr;
      continue;
    }
    if (
      b[i + 8] === info.methodId && b[i + 11] === 0 &&
      cpr > 0 && cpr < unc && unc <= info.uLen && i + 12 + cpr <= b.length && total + unc <= UPX_MAX_OUTPUT
    ) {
      try {
        const out = nrvDecompress(method, b, i + 12, unc);
        if (out.length === unc) {
          parts.push(out);
          total += unc;
          i += 12 + cpr;
          continue;
        }
      } catch {
        // Not a block header after all.
      }
    }
    i++;
  }
  if (!total) return null;
  const all = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    all.set(p, o);
    o += p.length;
  }
  return all;
}
