import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { once } from 'node:events';
import { afterEach, describe, expect, it } from 'vitest';
import { isProcessAlive, procStatState } from '../pidfile.js';

describe('procStatState', () => {
  it('reads the state after the command name', () => {
    expect(procStatState('4242 (node) Z 1 4242 4242 0 -1 4194560')).toBe('Z');
    expect(procStatState('4242 (node) S 1 4242 4242 0 -1 4194560')).toBe('S');
  });

  it('is not fooled by spaces or parentheses in the command name', () => {
    expect(procStatState('77 (evil ) R (x) Z 1 77 77 0 -1')).toBe('Z');
  });

  it('returns null for something that is not a stat line', () => {
    expect(procStatState('')).toBeNull();
  });
});

/**
 * In a container whose PID 1 does not reap orphans, a daemon that shut down
 * cleanly lingers as a zombie. `kill(pid, 0)` still succeeds on it, so `stop`
 * waited, SIGKILLed it to no effect, and reported it "still running".
 */
describe.runIf(existsSync('/proc/self/stat'))('isProcessAlive on a zombie', () => {
  let parent: ChildProcess | undefined;

  afterEach(() => {
    parent?.kill('SIGKILL');
  });

  it('treats an exited but unreaped process as gone', async () => {
    // The shell backgrounds a short sleep and `exec`s into a process that never
    // waits, so once the child exits it stays a zombie for the life of the test.
    // The child must outlive the exec: a `true` that exits first is reaped by sh.
    parent = spawn('sh', ['-c', 'sleep 0.5 & echo $!; exec sleep 30'], { stdio: ['ignore', 'pipe', 'ignore'] });
    const [chunk] = (await once(parent.stdout!, 'data')) as [Buffer];
    const pid = Number.parseInt(chunk.toString(), 10);

    // The child exits on its own schedule; the zombie state is the signal to wait on.
    const deadline = Date.now() + 5000;
    const state = () => {
      try {
        return procStatState(readFileSync(`/proc/${pid}/stat`, 'utf-8'));
      } catch {
        return null;
      }
    };
    while (state() !== 'Z' && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
    expect(state()).toBe('Z');

    expect(() => process.kill(pid, 0)).not.toThrow();
    expect(isProcessAlive(pid)).toBe(false);
  });

  it('still reports a running process as alive', () => {
    expect(isProcessAlive(process.pid)).toBe(true);
  });
});
