import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { IpcServer } from '../ipc-server.js';
import { IpcClient } from '../../core/ipc-client.js';
import { PATHS } from '../paths.js';
import type { ModuleHost } from '../module-host.js';
import type { RemediationManager } from '../firewall/remediation.js';
import type * as Paths from '../paths.js';

/**
 * `threatcrush respond ip` bans with `strict`: an intruder on a stolen key is a
 * live SSH peer and a remembered operator, and only our own addresses may
 * protect it. Plain `threatcrush block` keeps the full protected set.
 */
const dir: string = vi.hoisted(() => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tc-ipc-strict-'));
});

vi.mock('../paths.js', async (importOriginal) => {
  const actual = await importOriginal<typeof Paths>();
  return { ...actual, PATHS: { ...actual.PATHS, runDir: dir, socket: join(dir, 'threatcrushd.sock') } };
});

describe('block over IPC', () => {
  const calls: Array<{ ip: string; opts: Record<string, unknown> }> = [];
  const remediation = {
    ban: async (ip: string, _reason: string, opts: Record<string, unknown>) => {
      calls.push({ ip, opts });
      return { ok: true, entry: { ip, reason: 'x', blocked_at: 1, expires_at: 2, strikes: 1, source: 'manual', dry_run: false } };
    },
  } as unknown as RemediationManager;
  const server = new IpcServer('test', { summary: () => [] } as unknown as ModuleHost, remediation);

  beforeAll(async () => { await server.start(); });
  afterAll(async () => {
    await server.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  it('passes strict through only when asked', async () => {
    const client = new IpcClient({ socketPath: PATHS.socket });
    await client.connect();
    try {
      await client.block('203.0.113.7', 'respond', '30d', { strict: true });
      await client.block('203.0.113.8', 'cli');
    } finally {
      client.close();
    }
    expect(calls[0]).toMatchObject({ ip: '203.0.113.7', opts: { strict: true, ttlSeconds: 30 * 86400 } });
    expect(calls[1].opts.strict).toBeUndefined();
  });
});
