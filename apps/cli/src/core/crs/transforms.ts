// ModSecurity v2 transformation functions (apache2/re_tfns.c, msc_util.c),
// ported one-for-one for the transformations the ported CRS rules use. Input
// and output are byte strings (one char per byte). Character classes are the C
// locale's: isspace is \t \n \v \f \r and space, tolower touches A-Z only.

import type { CrsTransform } from './types.js';

const NBSP = 0xa0;

function isHex(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

function hexValue(c: number): number {
  return c >= 0x61 ? c - 0x61 + 10 : c >= 0x41 ? c - 0x41 + 10 : c - 0x30;
}

/** ModSecurity's x2c: two hex digits to a byte. */
function x2c(s: string, at: number): number {
  return (hexValue(s.charCodeAt(at)) << 4) | hexValue(s.charCodeAt(at + 1));
}

function fromCodes(codes: number[]): string {
  let out = '';
  for (let i = 0; i < codes.length; i += 8192) {
    out += String.fromCharCode.apply(null, codes.slice(i, i + 8192));
  }
  return out;
}

/** strtol(digits, base) cast to unsigned char, including strtol's clamp on overflow. */
function strtolByte(digits: string, base: 10 | 16): number {
  if (digits.length <= 12) return parseInt(digits, base) & 0xff;
  let v = 0n;
  const b = BigInt(base);
  for (const ch of digits) v = v * b + BigInt(parseInt(ch, base));
  const LONG_MAX = (1n << 63n) - 1n;
  if (v > LONG_MAX) v = LONG_MAX;
  return Number(v & 0xffn);
}

export function lowercase(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

export function removeNulls(s: string): string {
  return s.includes('\0') ? s.replace(/\0/g, '') : s;
}

export function removeWhitespace(s: string): string {
  return s.replace(/[\t-\r \xa0]+/g, '');
}

export function compressWhitespace(s: string): string {
  return s.replace(/[\t-\r \xa0]+/g, ' ');
}

/** urldecode_uni_nonstrict_inplace_ex, without a unicode map configured. */
export function urlDecodeUni(s: string): string {
  if (!s.includes('%') && !s.includes('+')) return s;
  const n = s.length;
  const out: number[] = [];
  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    if (c === 0x25 /* % */) {
      const u = s.charCodeAt(i + 1);
      if (i + 1 < n && (u === 0x75 || u === 0x55)) {
        if (i + 5 < n) {
          if (isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3)) && isHex(s.charCodeAt(i + 4)) && isHex(s.charCodeAt(i + 5))) {
            // The lower byte, ignoring the higher; full-width ASCII
            // (U+FF01-U+FF5E) is shifted back down to ASCII.
            let d = x2c(s, i + 4);
            const h1 = s.charCodeAt(i + 2);
            const h2 = s.charCodeAt(i + 3);
            if (d > 0x00 && d < 0x5f && (h1 === 0x66 || h1 === 0x46) && (h2 === 0x66 || h2 === 0x46)) d += 0x20;
            out.push(d);
            i += 6;
          } else {
            out.push(c, u);
            i += 2;
          }
        } else {
          out.push(c, u);
          i += 2;
        }
      } else if (i + 2 < n && isHex(s.charCodeAt(i + 1)) && isHex(s.charCodeAt(i + 2))) {
        out.push(x2c(s, i + 1));
        i += 3;
      } else {
        out.push(c);
        i++;
      }
    } else {
      out.push(c === 0x2b /* + */ ? 0x20 : c);
      i++;
    }
  }
  return fromCodes(out);
}

/** html_entities_decode_inplace. */
export function htmlEntityDecode(s: string): string {
  if (!s.includes('&')) return s;
  const n = s.length;
  const out: number[] = [];
  let i = 0;
  while (i < n) {
    let copy = 1;
    if (s.charCodeAt(i) === 0x26 /* & */ && i + 1 < n) {
      let j = i + 1;
      if (s.charCodeAt(j) === 0x23 /* # */) {
        copy++;
        if (j + 1 < n) {
          j++;
          const x = s.charCodeAt(j);
          if (x === 0x78 || x === 0x58) {
            copy++;
            if (j + 1 < n) {
              j++;
              const k = j;
              while (j < n && isHex(s.charCodeAt(j))) j++;
              if (j > k) {
                out.push(strtolByte(s.slice(k, j), 16));
                i = j < n && s.charCodeAt(j) === 0x3b ? j + 1 : j;
                continue;
              }
            }
          } else {
            const k = j;
            while (j < n && s.charCodeAt(j) >= 0x30 && s.charCodeAt(j) <= 0x39) j++;
            if (j > k) {
              out.push(strtolByte(s.slice(k, j), 10));
              i = j < n && s.charCodeAt(j) === 0x3b ? j + 1 : j;
              continue;
            }
          }
        }
      } else {
        const k = j;
        while (j < n && /[0-9A-Za-z]/.test(s[j])) j++;
        if (j > k) {
          const name = s.slice(k, j).toLowerCase();
          const decoded = name === 'quot' ? 0x22 : name === 'amp' ? 0x26 : name === 'lt' ? 0x3c : name === 'gt' ? 0x3e : name === 'nbsp' ? NBSP : -1;
          if (decoded !== -1) {
            out.push(decoded);
            i = j < n && s.charCodeAt(j) === 0x3b ? j + 1 : j;
            continue;
          }
          copy = j - k + 1;
        }
      }
    }
    for (let z = 0; z < copy && i < n; z++) out.push(s.charCodeAt(i++));
  }
  return fromCodes(out);
}

/** js_decode_nonstrict_inplace. */
export function jsDecode(s: string): string {
  if (!s.includes('\\')) return s;
  const n = s.length;
  const out: number[] = [];
  let i = 0;
  while (i < n) {
    const c = s.charCodeAt(i);
    if (c !== 0x5c /* \ */) {
      out.push(c);
      i++;
      continue;
    }
    const e = s.charCodeAt(i + 1);
    if (i + 5 < n && e === 0x75 /* u */ && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3)) && isHex(s.charCodeAt(i + 4)) && isHex(s.charCodeAt(i + 5))) {
      let d = x2c(s, i + 4);
      const h1 = s.charCodeAt(i + 2);
      const h2 = s.charCodeAt(i + 3);
      if (d > 0x00 && d < 0x5f && (h1 === 0x66 || h1 === 0x46) && (h2 === 0x66 || h2 === 0x46)) d += 0x20;
      out.push(d);
      i += 6;
    } else if (i + 3 < n && e === 0x78 /* x */ && isHex(s.charCodeAt(i + 2)) && isHex(s.charCodeAt(i + 3))) {
      out.push(x2c(s, i + 2));
      i += 4;
    } else if (i + 1 < n && e >= 0x30 && e <= 0x37) {
      let j = 0;
      let buf = '';
      while (i + 1 + j < n && j < 3) {
        buf += s[i + 1 + j];
        j++;
        if (!/[0-7]/.test(s[i + 1 + j] ?? '')) break;
      }
      if (j === 3 && buf.charCodeAt(0) > 0x33 /* '3' */) {
        j = 2;
        buf = buf.slice(0, 2);
      }
      out.push(parseInt(buf, 8) & 0xff);
      i += 1 + j;
    } else if (i + 1 < n) {
      const map: Record<number, number> = { 0x61: 0x07, 0x62: 0x08, 0x66: 0x0c, 0x6e: 0x0a, 0x72: 0x0d, 0x74: 0x09, 0x76: 0x0b };
      out.push(map[e] ?? e);
      i += 2;
    } else {
      while (i < n) out.push(s.charCodeAt(i++));
    }
  }
  return fromCodes(out);
}

/** css_decode_inplace. */
export function cssDecode(s: string): string {
  if (!s.includes('\\')) return s;
  const n = s.length;
  const out: number[] = [];
  let i = 0;
  while (i < n) {
    if (s.charCodeAt(i) !== 0x5c) {
      out.push(s.charCodeAt(i++));
      continue;
    }
    if (i + 1 >= n) {
      i++; // a trailing backslash is dropped
      continue;
    }
    i++;
    let j = 0;
    while (j < 6 && i + j < n && isHex(s.charCodeAt(i + j))) j++;
    if (j > 0) {
      let d: number;
      let fullcheck = false;
      let push = true;
      switch (j) {
        case 1:
          d = hexValue(s.charCodeAt(i));
          break;
        case 2:
        case 3:
          d = x2c(s, i + j - 2);
          break;
        case 4:
          d = x2c(s, i + j - 2);
          fullcheck = true;
          push = false;
          break;
        case 5:
          d = x2c(s, i + j - 2);
          if (s[i] === '0') { fullcheck = true; push = false; }
          break;
        default:
          d = x2c(s, i + j - 2);
          if (s[i] === '0' && s[i + 1] === '0') { fullcheck = true; push = false; }
          break;
      }
      if (push) out.push(d);
      if (fullcheck) {
        const a = s.charCodeAt(i + j - 3);
        const b = s.charCodeAt(i + j - 4);
        if (d > 0x00 && d < 0x5f && (a === 0x66 || a === 0x46) && (b === 0x66 || b === 0x46)) d += 0x20;
        out.push(d);
      }
      // A single whitespace after a hex escape is part of it.
      if (i + j < n && /[\t-\r ]/.test(s[i + j])) j++;
      i += j;
    } else if (s.charCodeAt(i) === 0x0a) {
      i++;
    } else {
      out.push(s.charCodeAt(i++));
    }
  }
  return fromCodes(out);
}

/** msre_fn_replaceComments_execute. */
export function replaceComments(s: string): string {
  if (!s.includes('/*')) return s;
  const n = s.length;
  let out = '';
  let i = 0;
  let inComment = false;
  while (i < n) {
    if (!inComment) {
      if (s[i] === '/' && i + 1 < n && s[i + 1] === '*') {
        inComment = true;
        i += 2;
      } else {
        out += s[i++];
      }
    } else if (s[i] === '*' && i + 1 < n && s[i + 1] === '/') {
      inComment = false;
      i += 2;
      out += ' ';
    } else {
      i++;
    }
  }
  if (inComment) out += ' ';
  return out;
}

/** msre_fn_removeCommentsChar_execute. */
export function removeCommentsChar(s: string): string {
  const n = s.length;
  let out = '';
  let i = 0;
  while (i < n) {
    const c = s[i];
    const c1 = s[i + 1];
    if (c === '/' && c1 === '*') i += 2;
    else if (c === '*' && c1 === '/') i += 2;
    else if (c === '<' && c1 === '!' && s[i + 2] === '-' && s[i + 3] === '-') i += 4;
    else if (c === '-' && c1 === '-' && s[i + 2] === '>') i += 3;
    else if (c === '-' && c1 === '-') i += 2;
    else if (c === '#') i++;
    else out += s[i++];
  }
  return out;
}

/** msre_fn_cmdline_execute. It walks a NUL-terminated string, so stops at the first NUL. */
export function cmdLine(s: string): string {
  const out: number[] = [];
  let space = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) break;
    switch (c) {
      case 0x22: case 0x27: case 0x5c: case 0x5e: // " ' \ ^
        continue;
      case 0x20: case 0x2c: case 0x3b: case 0x09: case 0x0d: case 0x0a: // space , ; \t \r \n
        if (!space) {
          out.push(0x20);
          space = true;
        }
        break;
      case 0x2f: case 0x28: // / (
        if (space) out.pop();
        space = false;
        out.push(c);
        break;
      default:
        out.push(c >= 0x41 && c <= 0x5a ? c + 0x20 : c);
        space = false;
    }
  }
  return fromCodes(out);
}

/** normalize_path_inplace, a direct port of its pointer walk. */
function normalizePathImpl(s: string, win: boolean): string {
  const len = s.length;
  if (len <= 0) return s;
  const buf: number[] = new Array(len);
  for (let k = 0; k < len; k++) buf[k] = s.charCodeAt(k);
  const SL = 0x2f;
  const BS = 0x5c;
  const DOT = 0x2e;

  let src = 0;
  let dst = 0;
  const end = len - 1;
  let hitroot = false;
  let done = false;
  const relative = !(buf[0] === SL || (win && buf[0] === BS));
  const trailing = buf[end] === SL || (win && buf[end] === BS);

  while (!done && src <= end && dst <= end) {
    if (win) {
      if (buf[src] === BS) buf[src] = SL;
      if (src < end && buf[src + 1] === BS) buf[src + 1] = SL;
    }

    let skipCopy = false;
    let normalize = true;
    if (src === end) {
      done = true;
    } else if (buf[src + 1] !== SL) {
      normalize = false;
    }

    if (normalize) {
      if (src !== end && buf[src] === SL) {
        // empty segment: the copy step collapses it
      } else if (buf[src] === DOT) {
        if (dst > 0 && buf[dst - 1] === DOT) {
          if (relative && (hitroot || dst - 2 <= 0)) {
            hitroot = true;
          } else {
            dst -= 3;
            while (dst > 0 && buf[dst] !== SL) dst--;
            if (dst <= 0) {
              hitroot = true;
              dst = 0;
              if (!relative && src === end) dst++;
            }
            if (done) {
              skipCopy = true;
            } else {
              src++;
            }
          }
        } else if (dst === 0) {
          if (done) skipCopy = true;
          else src++;
        } else if (buf[dst - 1] === SL) {
          if (done) {
            skipCopy = true;
          } else {
            dst--;
            src++;
          }
        }
      } else if (dst > 0) {
        hitroot = false;
      }
    }

    if (!skipCopy) {
      let skipByte = false;
      if (buf[src] === SL) {
        while (src < end && (buf[src + 1] === SL || (win && buf[src + 1] === BS))) src++;
        if (relative && dst === 0) {
          src++;
          skipByte = true;
        }
      }
      if (!skipByte) buf[dst++] = buf[src++];
    }
  }

  if (!trailing && dst > 0 && buf[dst - 1] === SL) dst--;
  return fromCodes(buf.slice(0, dst));
}

export function normalizePath(s: string): string {
  return normalizePathImpl(s, false);
}

export function normalizePathWin(s: string): string {
  return normalizePathImpl(s, true);
}

/**
 * utf8_unicode_inplace_ex: each valid UTF-8 sequence becomes `%uXXXX`. Its
 * length checks compare against the whole input, not what is left, and it
 * reads the NUL terminator past the end — both reproduced (reads past the end
 * see 0).
 */
export function utf8toUnicode(s: string): string {
  const n = s.length;
  let hasHigh = false;
  for (let k = 0; k < n; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0x80 || c === 0) { hasHigh = true; break; }
  }
  if (!hasHigh) return s;
  const at = (k: number) => (k < n ? s.charCodeAt(k) : 0);
  let out = '';
  let i = 0;
  while (i < n) {
    let len = 0;
    let d = 0;
    const c = at(i);
    if ((c & 0x80) === 0) {
      if (c === 0) {
        len = 2;
        d = at(i + 1);
      }
    } else if ((c & 0xe0) === 0xc0) {
      if (n < 2) len = -1;
      else if ((at(i + 1) & 0xc0) !== 0x80) len = -1;
      else {
        len = 2;
        d = ((c & 0x1f) << 6) | (at(i + 1) & 0x3f);
      }
    } else if ((c & 0xf0) === 0xe0) {
      if (n < 3) len = -1;
      else if ((at(i + 1) & 0xc0) !== 0x80 || (at(i + 2) & 0xc0) !== 0x80) len = -1;
      else {
        len = 3;
        d = ((c & 0x0f) << 12) | ((at(i + 1) & 0x3f) << 6) | (at(i + 2) & 0x3f);
      }
    } else if ((c & 0xf8) === 0xf0) {
      if (c >= 0xf5) len = -1;
      else if (n < 4) len = -1;
      else if ((at(i + 1) & 0xc0) !== 0x80 || (at(i + 2) & 0xc0) !== 0x80 || (at(i + 3) & 0xc0) !== 0x80) len = -1;
      else {
        len = 4;
        d = ((c & 0x07) << 18) | ((at(i + 1) & 0x3f) << 12) | ((at(i + 2) & 0x3f) << 6) | (at(i + 3) & 0x3f);
      }
    }
    if (d >= 0xd800 && d <= 0xdfff) len = -1;
    if (len === 4 && d < 0x10000) len = -1;
    if (len === 3 && d < 0x800) len = -1;
    if (len === 2 && d < 0x80) len = -1;

    if (len > 0) {
      i += len;
      out += `%u${d.toString(16).padStart(4, '0')}`;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

const B64: Int16Array = (() => {
  const t = new Int16Array(256).fill(64);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let k = 0; k < alphabet.length; k++) t[alphabet.charCodeAt(k)] = k;
  return t;
})();

/** apr_base64_decode: decodes the leading run of base64 characters, ignoring the rest. */
export function base64Decode(s: string): string {
  let np = 0;
  while (np < s.length && B64[s.charCodeAt(np)] <= 63) np++;
  const v = (k: number) => B64[s.charCodeAt(k)];
  const out: number[] = [];
  let p = 0;
  let left = np;
  while (left > 4) {
    out.push(((v(p) << 2) | (v(p + 1) >> 4)) & 0xff);
    out.push(((v(p + 1) << 4) | (v(p + 2) >> 2)) & 0xff);
    out.push(((v(p + 2) << 6) | v(p + 3)) & 0xff);
    p += 4;
    left -= 4;
  }
  if (left > 1) out.push(((v(p) << 2) | (v(p + 1) >> 4)) & 0xff);
  if (left > 2) out.push(((v(p + 1) << 4) | (v(p + 2) >> 2)) & 0xff);
  if (left > 3) out.push(((v(p + 2) << 6) | v(p + 3)) & 0xff);
  return fromCodes(out);
}

export const TRANSFORMS: Record<CrsTransform, (s: string) => string> = {
  lowercase,
  urlDecodeUni,
  htmlEntityDecode,
  jsDecode,
  cssDecode,
  removeNulls,
  removeWhitespace,
  compressWhitespace,
  replaceComments,
  removeCommentsChar,
  cmdLine,
  normalizePath,
  normalizePathWin,
  utf8toUnicode,
  base64Decode,
};
