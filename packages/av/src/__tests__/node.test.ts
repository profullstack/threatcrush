import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { EICAR } from '../index';
import {
  clamDetection,
  deleteQuarantined,
  listQuarantine,
  parseClamOutput,
  quarantineFile,
  quickScanTargets,
  restoreQuarantined,
  scanFileSync,
  scanPaths,
  walkFiles,
  walkTargets,
  watchTargets,
} from '../node/index';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'crushav-test-'));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('walkTargets', () => {
  it('respects depth and skips package caches', async () => {
    mkdirSync(join(dir, 'a', 'b', 'c'), { recursive: true });
    mkdirSync(join(dir, 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(dir, 'top.txt'), '1');
    writeFileSync(join(dir, 'a', 'one.txt'), '1');
    writeFileSync(join(dir, 'a', 'b', 'c', 'deep.txt'), '1');
    writeFileSync(join(dir, 'node_modules', 'x', 'i.js'), '1');
    const found: string[] = [];
    for await (const f of walkTargets([{ path: dir, depth: 2 }])) found.push(f.path.slice(dir.length + 1));
    expect(found.sort()).toEqual([join('a', 'one.txt'), 'top.txt']);
  });
});

describe('walkFiles', () => {
  const collect = async (targets: Array<{ path: string; depth: number }>) => {
    const found: string[] = [];
    for await (const p of walkFiles(targets, { concurrency: 3 })) found.push(p.slice(dir.length + 1));
    return found.sort();
  };

  it('matches walkTargets on depth and skipped caches', async () => {
    mkdirSync(join(dir, 'a', 'b', 'c'), { recursive: true });
    mkdirSync(join(dir, 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(dir, 'top.txt'), '1');
    writeFileSync(join(dir, 'a', 'one.txt'), '1');
    writeFileSync(join(dir, 'a', 'b', 'c', 'deep.txt'), '1');
    writeFileSync(join(dir, 'node_modules', 'x', 'i.js'), '1');
    expect(await collect([{ path: dir, depth: 2 }])).toEqual([join('a', 'one.txt'), 'top.txt']);
  });

  it('lists each file once across overlapping targets of any depth order', async () => {
    mkdirSync(join(dir, 'a', 'b', 'c'), { recursive: true });
    writeFileSync(join(dir, 'top.txt'), '1');
    writeFileSync(join(dir, 'a', 'one.txt'), '1');
    writeFileSync(join(dir, 'a', 'b', 'two.txt'), '1');
    writeFileSync(join(dir, 'a', 'b', 'c', 'deep.txt'), '1');
    const all = [join('a', 'b', 'c', 'deep.txt'), join('a', 'b', 'two.txt'), join('a', 'one.txt'), 'top.txt'];
    expect(await collect([{ path: join(dir, 'a'), depth: 1 }, { path: dir, depth: Infinity }, { path: join(dir, 'top.txt'), depth: 1 }])).toEqual(all);
    // A shallow walk first, then a deeper one over the same tree: only the unseen part is added.
    expect(await collect([{ path: dir, depth: 2 }, { path: join(dir, 'a'), depth: 3 }])).toEqual(all);
  });

  it('walks a wide tree completely', async () => {
    for (let i = 0; i < 40; i++) {
      mkdirSync(join(dir, `d${i}`, 'sub'), { recursive: true });
      for (let j = 0; j < 30; j++) writeFileSync(join(dir, `d${i}`, 'sub', `f${j}`), 'x');
    }
    expect((await collect([{ path: dir, depth: Infinity }])).length).toBe(1200);
  });
});

describe('scanFileSync', () => {
  it('hashes past the heuristic cap and flags EICAR', async () => {
    writeFileSync(join(dir, 'eicar.com'), EICAR);
    const big = Buffer.alloc(3 * 1024 * 1024 + 7, 0x61);
    writeFileSync(join(dir, 'big.txt'), big);
    const opts = { cap: 1024 * 1024, maxFile: 1024 ** 3 };
    const e = await scanFileSync(join(dir, 'eicar.com'), opts);
    expect(e.kind === 'result' && e.result.verdict).toBe('malicious');
    const b = await scanFileSync(join(dir, 'big.txt'), opts);
    const { createHash } = await import('node:crypto');
    expect(b.kind === 'result' && b.result.sha256).toBe(createHash('sha256').update(big).digest('hex'));
    expect(b.kind === 'result' && b.result.size).toBe(big.length);
    expect(await scanFileSync(join(dir, 'big.txt'), { cap: 1024, maxFile: 1024 })).toMatchObject({ kind: 'skip' });
    expect(await scanFileSync(join(dir, 'missing'), opts)).toEqual({ kind: 'none' });
  });
});

describe('scanPaths', () => {
  it('counts clean files without keeping them when keepClean is false', async () => {
    writeFileSync(join(dir, 'eicar.com'), EICAR);
    for (let i = 0; i < 20; i++) writeFileSync(join(dir, `n${i}.txt`), `note ${i}`);
    const report = await scanPaths([{ path: dir, depth: Infinity }], { clamav: 'off', reputation: false, keepClean: false });
    expect(report.summary).toMatchObject({ scanned: 21, malicious: 1, clean: 20 });
    expect(report.results.map((r) => r.verdict)).toEqual(['malicious']);
  });

  it('finds EICAR among clean files offline', async () => {
    writeFileSync(join(dir, 'eicar.com'), EICAR);
    writeFileSync(join(dir, 'notes.txt'), 'shopping list');
    writeFileSync(join(dir, 'empty.txt'), '');
    const report = await scanPaths([{ path: dir, depth: Infinity }], { clamav: 'off', reputation: false });
    expect(report.summary.scanned).toBe(2);
    expect(report.summary.malicious).toBe(1);
    expect(report.results.find((r) => r.path.endsWith('eicar.com'))?.verdict).toBe('malicious');
  });
});

describe('quarantine', () => {
  it('neutralises, lists, restores and deletes', async () => {
    const q = join(dir, 'q');
    const f = join(dir, 'eicar.com');
    writeFileSync(f, EICAR);
    const entry = await quarantineFile(f, [], q);
    expect(existsSync(f)).toBe(false);
    // The stored bytes are not the original (so they cannot run or re-trigger scanners).
    expect(readFileSync(join(q, `${entry.id}.bin`), 'latin1')).not.toContain('EICAR');
    expect((await listQuarantine(q)).map((e) => e.id)).toEqual([entry.id]);
    await restoreQuarantined(entry.id, undefined, q);
    expect(readFileSync(f, 'latin1')).toBe(EICAR);
    const again = await quarantineFile(f, [], q);
    await deleteQuarantined(again.id, q);
    expect(await listQuarantine(q)).toEqual([]);
    await expect(deleteQuarantined('../etc', q)).rejects.toThrow();
  });
  it('refuses to restore over an existing file', async () => {
    const q = join(dir, 'q');
    const f = join(dir, 'x.bin');
    writeFileSync(f, 'abc');
    const e = await quarantineFile(f, [], q);
    writeFileSync(f, 'new');
    await expect(restoreQuarantined(e.id, undefined, q)).rejects.toThrow(/already exists/);
  });
});

describe('clamav output', () => {
  it('parses FOUND lines including paths with colons', () => {
    const m = parseClamOutput('/home/a/eicar.com: Win.Test.EICAR_HDB-1 FOUND\nC:\\x\\odd: name.exe: Win.Trojan.Agent-1 FOUND\n/home/a/ok: OK\n');
    expect(m.get('/home/a/eicar.com')).toEqual(['Win.Test.EICAR_HDB-1']);
    expect(m.get('C:\\x\\odd: name.exe')).toEqual(['Win.Trojan.Agent-1']);
    expect(m.size).toBe(2);
  });
  it('maps PUA to suspicious and trojans to malicious', () => {
    expect(clamDetection('PUA.Win.Adware.X').impact).toBe('suspicious');
    expect(clamDetection('Win.Trojan.Agent-1').impact).toBe('malicious');
  });
});

describe.skipIf(process.platform === 'win32')('clamav bridge end to end (stand-in clamscan)', () => {
  it('detects, runs once over a file list and merges ClamAV detections', async () => {
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    // Behaves like clamscan: --version line, then FOUND lines for listed files containing EVIL.
    writeFileSync(
      join(bin, 'clamscan'),
      '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "ClamAV 1.4.2/27447/Sun Nov  2 08:00:00 2026"; exit 0; fi\n' +
        'for a in "$@"; do case "$a" in --file-list=*) list="${a#--file-list=}";; esac; done\n' +
        'found=0; while IFS= read -r f; do if grep -q EVIL "$f"; then echo "$f: Win.Trojan.Fake-1 FOUND"; found=1; fi; done < "$list"; exit $found\n',
      { mode: 0o755 },
    );
    const data = join(dir, 'data');
    mkdirSync(data);
    writeFileSync(join(data, 'bad: name.bin'), 'EVIL payload');
    writeFileSync(join(data, 'ok.txt'), 'fine');
    const oldPath = process.env.PATH;
    process.env.PATH = `${bin}:${oldPath}`;
    try {
      const report = await scanPaths([{ path: data, depth: Infinity }], { reputation: false });
      expect(report.clamav?.version).toContain('ClamAV 1.4.2');
      expect(report.clamav?.signaturesDate).toContain('Nov');
      expect(report.summary.engines).toContain('clamav');
      const bad = report.results.find((r) => r.path.endsWith('bad: name.bin'));
      expect(bad?.verdict).toBe('malicious');
      expect(bad?.detections.map((d) => d.id)).toContain('ClamAV.Win.Trojan.Fake-1');
      expect(report.results.find((r) => r.path.endsWith('ok.txt'))?.verdict).toBe('clean');
    } finally {
      process.env.PATH = oldPath;
    }
  });
});

describe('watchTargets', () => {
  it('scans a file dropped into a watched folder, ignoring partial downloads', async () => {
    const seen: string[] = [];
    let resolveHit: () => void;
    const hit = new Promise<void>((r) => (resolveHit = r));
    const stop = watchTargets([{ path: dir, depth: 3 }], {
      settleMs: 50,
      reputation: false,
      onResult: (r) => {
        seen.push(`${r.path.slice(dir.length + 1)}:${r.verdict}`);
        if (r.verdict === 'malicious') resolveHit();
      },
    });
    try {
      await new Promise((r) => setTimeout(r, 100));
      writeFileSync(join(dir, 'setup.exe.crdownload'), EICAR);
      writeFileSync(join(dir, 'eicar.com'), EICAR);
      await Promise.race([hit, new Promise((_, rej) => setTimeout(() => rej(new Error(`no detection; saw ${seen.join(',')}`)), 5000))]);
      expect(seen).toContain('eicar.com:malicious');
      expect(seen.some((s) => s.includes('crdownload'))).toBe(false);
    } finally {
      stop();
    }
  });
});

describe('quickScanTargets', () => {
  it('includes startup folders on Windows when they exist', () => {
    const home = dir;
    mkdirSync(join(home, 'Downloads'));
    const appData = join(home, 'AppData', 'Roaming');
    mkdirSync(join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'), { recursive: true });
    const t = quickScanTargets('win32', { APPDATA: appData, LOCALAPPDATA: join(home, 'nope') }, home).map((x) => x.path);
    expect(t).toContain(join(home, 'Downloads'));
    expect(t).toContain(join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'));
    expect(t).not.toContain(join(home, 'nope'));
  });
});
