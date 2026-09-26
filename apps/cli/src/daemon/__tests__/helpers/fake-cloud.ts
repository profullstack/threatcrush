import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, vi } from 'vitest';

export interface RecordedRequest {
  method: string;
  path: string;
  auth: string | undefined;
  body: RequestBody | undefined;
}

/** The fields the tests read, from ingest, PATCH and refresh bodies alike. */
export interface RequestBody {
  events?: Array<Record<string, unknown>>;
  status?: string;
  error?: string;
  dry_run?: boolean;
  refresh_token?: string;
  name?: string;
  hostname?: string;
}

export type FakeReply = { status: number; body?: unknown } | 'network-down';

/**
 * Point `os.homedir()` (and so ~/.threatcrush/config.json and the user-mode
 * daemon paths) at a fresh directory, removed after the file's tests. Call
 * before importing anything that reads the CLI config, which captures its
 * path at import time.
 */
export function isolateHome(): string {
  const home = mkdtempSync(join(tmpdir(), 'tc-cloud-test-'));
  process.env.HOME = home;
  process.env.THREATCRUSH_API_URL = 'http://cloud.test';
  afterAll(() => rmSync(home, { recursive: true, force: true, maxRetries: 3 }));
  return home;
}

/** Replace global `fetch` with a scripted dashboard that records every request. */
export function fakeCloud(handler: (req: RecordedRequest) => FakeReply | Promise<FakeReply>) {
  const requests: RecordedRequest[] = [];
  vi.stubGlobal('fetch', async (url: string, init: RequestInit = {}) => {
    const headers = (init.headers ?? {}) as Record<string, string>;
    const req: RecordedRequest = {
      method: init.method ?? 'GET',
      path: new URL(url).pathname,
      auth: headers.Authorization,
      body: typeof init.body === 'string' ? JSON.parse(init.body) as RequestBody : undefined,
    };
    requests.push(req);
    const reply = await handler(req);
    if (reply === 'network-down') throw new TypeError('fetch failed');
    return new Response(JSON.stringify(reply.body ?? {}), {
      status: reply.status,
      headers: { 'content-type': 'application/json' },
    });
  });
  return {
    requests,
    to: (path: string) => requests.filter((r) => r.path === path),
  };
}

/** Let queued immediates, timers-turned-promises and fetch chains run out. */
export async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((resolve) => setImmediate(resolve));
}
