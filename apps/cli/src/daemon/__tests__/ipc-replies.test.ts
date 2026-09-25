import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IpcServer } from '../ipc-server.js';
import { IpcClient } from '../../core/ipc-client.js';
import { PATHS } from '../paths.js';
import type { ModuleHost } from '../module-host.js';
import type * as Paths from '../paths.js';

/**
 * A client hung against a 0.12.8 daemon: the newer CLI asked for a method the
 * daemon did not know, and the daemon's switch had no default, so no reply was
 * ever written. Every frame must now get an answer, and the client must not
 * wait forever when one never comes.
 *
 * A missing reply shows up here as the test timing out.
 */

// vi.mock is hoisted above the imports, so the temp dir has to be made in a
// hoisted block, which can only reach node builtins through require.
const dir: string = vi.hoisted(() => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  return fs.mkdtempSync(path.join(os.tmpdir(), 'tc-ipc-'));
});

vi.mock('../paths.js', async (importOriginal) => {
  const actual = await importOriginal<typeof Paths>();
  return {
    ...actual,
    PATHS: { ...actual.PATHS, runDir: dir, socket: join(dir, 'threatcrushd.sock') },
  };
});

type Reply = { id: number; ok: boolean; error?: string; result?: unknown };

/** Send raw lines and resolve once `count` replies have arrived. */
function exchange(lines: string[], count: number): Promise<Reply[]> {
  return new Promise((resolve, reject) => {
    const sock = createConnection(PATHS.socket);
    const replies: Reply[] = [];
    let buf = '';
    sock.setEncoding('utf-8');
    sock.on('data', (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        replies.push(JSON.parse(buf.slice(0, idx)));
        buf = buf.slice(idx + 1);
      }
      if (replies.length >= count) {
        sock.destroy();
        resolve(replies);
      }
    });
    sock.on('error', reject);
    sock.on('connect', () => sock.write(lines.map((l) => l + '\n').join('')));
  });
}

describe('daemon answers every frame', () => {
  const moduleHost = { summary: () => [] } as unknown as ModuleHost;
  const server = new IpcServer('test', moduleHost);

  beforeAll(async () => { await server.start(); });
  afterAll(async () => {
    await server.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  it('replies to a method it does not know instead of staying silent', async () => {
    const [reply] = await exchange([JSON.stringify({ id: 7, method: 'frobnicate' })], 1);
    expect(reply.id).toBe(7);
    expect(reply.ok).toBe(false);
    expect(reply.error).toMatch(/^unknown method/);
    expect(reply.error).toContain('frobnicate');
  });

  it('replies to malformed frames, on the id when it has one', async () => {
    const replies = await exchange([
      'not json',
      JSON.stringify({ method: 'ping' }),
      JSON.stringify({ id: 3 }),
      JSON.stringify({ id: 4, method: 42 }),
      'null',
    ], 5);
    for (const r of replies) expect(r.ok).toBe(false);
    expect(replies.map((r) => r.id).sort()).toEqual([0, 0, 0, 3, 4]);
  });

  it('answers on the request id when a known method throws', async () => {
    // subscribe without params throws; that used to be answered on id 0,
    // which no client was waiting on.
    const [reply] = await exchange([JSON.stringify({ id: 9, method: 'subscribe' })], 1);
    expect(reply).toMatchObject({ id: 9, ok: false });
  });

  it('still serves known methods', async () => {
    const [reply] = await exchange([JSON.stringify({ id: 1, method: 'ping' })], 1);
    expect(reply).toEqual({ id: 1, ok: true, result: 'pong' });
  });

  it('the client rejects an unknown method and tells the operator to update the daemon', async () => {
    const client = new IpcClient({ socketPath: PATHS.socket });
    await client.connect();
    try {
      const err = await client.request('frobnicate' as never).then(() => null, (e: Error) => e);
      expect(err?.message).toContain('frobnicate');
      expect(err?.message).toMatch(/update/);
    } finally {
      client.close();
    }
  });
});

describe('client never waits forever', () => {
  let fake: Server | null = null;
  let fakeDir = '';

  afterEach(async () => {
    vi.useRealTimers();
    await new Promise<void>((r) => (fake ? fake.close(() => r()) : r()));
    fake = null;
    rmSync(fakeDir, { recursive: true, force: true });
  });

  /** A socket server that hands each connection's first frame to `onFrame`. */
  async function fakeDaemon(onFrame: (sock: Socket) => void): Promise<IpcClient> {
    fakeDir = mkdtempSync(join(tmpdir(), 'tc-ipc-fake-'));
    const path = join(fakeDir, 'd.sock');
    fake = createServer((sock) => sock.once('data', () => onFrame(sock)));
    await new Promise<void>((r) => fake!.listen(path, r));
    const client = new IpcClient({ socketPath: path });
    await client.connect();
    return client;
  }

  it('rejects a pending request when the daemon closes mid-request', async () => {
    const client = await fakeDaemon((sock) => sock.destroy());
    await expect(client.ping()).rejects.toThrow(/closed/);
  });

  it('times out a request the daemon never answers, as an older daemon does', async () => {
    let received!: () => void;
    const frameArrived = new Promise<void>((r) => { received = r; });
    const client = await fakeDaemon(() => received());
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const pending = client.request('frobnicate' as never);
      const settled = pending.then(() => null, (e: Error) => e);
      await frameArrived;
      await vi.advanceTimersByTimeAsync(60_000);
      const err = await settled;
      expect(err?.message).toMatch(/did not answer/);
    } finally {
      client.close();
    }
  });
});
