import { describe, it, expect } from 'vitest';
import { appendFileSync, mkdtempSync, renameSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LogTail } from '../log-tail.js';

const fresh = () => {
  const file = join(mkdtempSync(join(tmpdir(), 'tc-tail-')), 'access.log');
  writeFileSync(file, 'old line that predates the tail\n');
  return file;
};

const collect = (tail: LogTail, maxBytes?: number) => {
  const lines: string[] = [];
  tail.poll((l) => lines.push(l), maxBytes);
  return lines;
};

describe('LogTail', () => {
  it('starts at the end and hands over each new line exactly once', () => {
    const file = fresh();
    const tail = new LogTail(file);
    expect(collect(tail)).toEqual([]);
    appendFileSync(file, 'a\nb\n');
    expect(collect(tail)).toEqual(['a', 'b']);
    // Polling again with nothing new must not replay anything: the old reader
    // re-read from a stale offset whenever a read outlived the poll interval.
    expect(collect(tail)).toEqual([]);
    expect(collect(tail)).toEqual([]);
  });

  it('holds a line until its newline arrives', () => {
    const file = fresh();
    const tail = new LogTail(file);
    appendFileSync(file, 'half a li');
    expect(collect(tail)).toEqual([]);
    appendFileSync(file, 'ne\nnext\n');
    expect(collect(tail)).toEqual(['half a line', 'next']);
  });

  it('follows rotation: a new file (new inode) or a truncated one starts from the top', () => {
    const file = fresh();
    const tail = new LogTail(file);
    appendFileSync(file, 'before\n');
    expect(collect(tail)).toEqual(['before']);
    renameSync(file, `${file}.1`);
    writeFileSync(file, 'first in the new file\n');
    expect(collect(tail)).toEqual(['first in the new file']);
    writeFileSync(file, 'x\n'); // truncated in place
    expect(collect(tail)).toEqual(['x']);
  });

  it('spreads a burst over polls instead of reading it all at once', () => {
    const file = fresh();
    const tail = new LogTail(file);
    appendFileSync(file, Array.from({ length: 100 }, (_, i) => `line ${String(i).padStart(3, '0')}`).join('\n') + '\n');
    const first = collect(tail, 300); // ~33 lines' worth
    expect(first.length).toBeGreaterThan(0);
    expect(first.length).toBeLessThan(100);
    const all = [...first];
    for (let i = 0; i < 10; i++) all.push(...collect(tail, 300));
    expect(all).toHaveLength(100);
    expect(new Set(all).size).toBe(100);
  });

  it('a missing file is not an error', () => {
    const tail = new LogTail('/nonexistent/threatcrush/test.log');
    expect(collect(tail)).toEqual([]);
  });
});
