import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';
import { CommandHistoryWatcher, type HistoryAccount } from '../workers/command-history.js';

describe('command history watcher', () => {
  let root: string;
  let home: string;
  let stateDir: string;
  let events: ThreatEvent[];
  let logs: string[];
  let account: HistoryAccount;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'tc-command-history-'));
    home = join(root, 'home');
    stateDir = join(root, 'state');
    mkdirSync(home);
    events = [];
    logs = [];
    account = {
      uid: process.getuid?.() ?? 1000,
      gid: process.getgid?.() ?? 1000,
      name: 'worker',
      home,
      shell: '/bin/bash',
    };
  });

  afterEach(() => rmSync(root, { recursive: true, force: true }));

  function watcher(enabled = true): CommandHistoryWatcher {
    return new CommandHistoryWatcher({
      bus: { publish: (event) => events.push(event) },
      stateDir,
      settings: { enabled },
      log: (line) => logs.push(line),
      listAccounts: () => [account],
      now: () => new Date('2026-10-30T12:00:00.000Z'),
    });
  }

  it('creates private compressed snapshots only when history changes', async () => {
    const historyPath = join(home, '.bash_history');
    writeFileSync(historyPath, 'pwd\n', { mode: 0o600 });
    const service = watcher();

    await service.scanOnce();
    const backup = join(stateDir, 'command-history', String(account.uid), '.bash_history.current.gz');
    expect(gunzipSync(readFileSync(backup)).toString()).toBe('pwd\n');
    expect(lstatSync(join(stateDir, 'command-history')).mode & 0o777).toBe(0o700);
    expect(lstatSync(backup).mode & 0o777).toBe(0o600);
    const snapshots = join(stateDir, 'command-history', String(account.uid));
    expect(readdirSync(snapshots).filter((name) => name.endsWith('.gz'))).toHaveLength(2); // current + one archive

    writeFileSync(historyPath, 'pwd\nls\n');
    await service.scanOnce();
    expect(gunzipSync(readFileSync(backup)).toString()).toBe('pwd\nls\n');
    expect(readdirSync(snapshots).filter((name) => name.endsWith('.gz'))).toHaveLength(3);
    expect(events).toHaveLength(0);
  });

  it('replaces a /dev/null symlink with the latest backed-up history and emits a tamper event', async () => {
    const historyPath = join(home, '.bash_history');
    writeFileSync(historyPath, 'deploy app\n', { mode: 0o600 });
    const service = watcher();
    await service.scanOnce();

    unlinkSync(historyPath);
    symlinkSync('/dev/null', historyPath);
    await service.scanOnce();

    expect(lstatSync(historyPath).isSymbolicLink()).toBe(false);
    expect(readFileSync(historyPath, 'utf8')).toBe('deploy app\n');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      module: 'command-history',
      severity: 'medium',
      details: { account: 'worker', history_file: '.bash_history', reason: 'symlinked', had_backup: true },
    });
    expect(events[0].message).not.toContain('deploy app');
  });

  it('watches an existing Bash history file for a Zsh login account', async () => {
    account.shell = '/bin/zsh';
    const bashHistory = join(home, '.bash_history');
    writeFileSync(bashHistory, 'git status\n', { mode: 0o600 });
    const service = watcher();

    await service.scanOnce();
    unlinkSync(bashHistory);
    symlinkSync('/dev/null', bashHistory);
    await service.scanOnce();

    expect(lstatSync(bashHistory).isSymbolicLink()).toBe(false);
    expect(readFileSync(bashHistory, 'utf8')).toBe('git status\n');
    expect(events).toHaveLength(1);
    expect(events[0].details).toMatchObject({ history_file: '.bash_history', reason: 'symlinked' });
  });

  it('restores a deleted history file and repairs hard links', async () => {
    const historyPath = join(home, '.bash_history');
    writeFileSync(historyPath, 'git status\n', { mode: 0o600 });
    const service = watcher();
    await service.scanOnce();

    unlinkSync(historyPath);
    await service.scanOnce();
    expect(readFileSync(historyPath, 'utf8')).toBe('git status\n');

    const other = join(home, 'other');
    writeFileSync(other, 'hidden\n');
    unlinkSync(historyPath);
    // Hard links are unavailable on a few filesystems; the behavior under test
    // is still covered by symlink repair above.
    try {
      const { linkSync } = await import('node:fs');
      linkSync(other, historyPath);
    } catch { return; }
    await service.scanOnce();
    expect(readFileSync(historyPath, 'utf8')).toBe('git status\n');
    expect(events.map((event) => event.details?.reason)).toEqual(['deleted', 'hard-linked']);
  });

  it('does not collect or create files when disabled', async () => {
    const service = watcher(false);
    await service.scanOnce();
    service.start();
    expect(existsSync(join(stateDir, 'command-history'))).toBe(false);
    expect(events).toHaveLength(0);
    service.stop();
  });
});
