import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * `threatcrush init </dev/null` printed "Sign in now? (Y/n): " and exited 0
 * having written nothing: `rl.question` never calls back when stdin ends, so
 * the event loop simply drained. `ask` must settle with null instead.
 */
const realStdin = Object.getOwnPropertyDescriptor(process, 'stdin')!;

function pipeStdin(): PassThrough {
  const stdin = new PassThrough();
  Object.defineProperty(process, 'stdin', { value: stdin, configurable: true });
  return stdin;
}

async function loadAsk() {
  // The piped reader is per-process state; each test gets a fresh one.
  vi.resetModules();
  return (await import('../prompt.js')).ask;
}

beforeEach(() => {
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
});

afterEach(() => {
  Object.defineProperty(process, 'stdin', realStdin);
  vi.restoreAllMocks();
});

describe('ask on a non-terminal stdin', () => {
  it('resolves null when stdin is already at EOF (</dev/null)', async () => {
    const ask = await loadAsk();
    pipeStdin().end();
    await expect(ask('Sign in now? (Y/n): ')).resolves.toBeNull();
  });

  it('resolves null when stdin closes while the question is waiting', async () => {
    const ask = await loadAsk();
    const stdin = pipeStdin();
    const answer = ask('Email: ');
    stdin.end();
    await expect(answer).resolves.toBeNull();
  });

  it('hands piped lines to successive questions in order', async () => {
    // One readline per question used to swallow the second line with the first.
    const ask = await loadAsk();
    pipeStdin().end('me@example.com\nhunter2\n');
    await expect(ask('Email: ')).resolves.toBe('me@example.com');
    await expect(ask('Password: ', { mask: true })).resolves.toBe('hunter2');
    await expect(ask('Again? ')).resolves.toBeNull();
  });
});
