import { vi } from 'vitest';

export const API = 'https://api.test';

export interface RecordedRequest {
  method: string;
  path: string;
  auth: string | null;
  body: unknown;
}

type Reply = { status?: number; body?: unknown } | Promise<{ status?: number; body?: unknown }>;
type Handler = (req: RecordedRequest) => Reply;

/**
 * Stubs global fetch with a tiny router keyed by "METHOD /path?query".
 * Unrouted requests fail the test loudly with a 599.
 */
export function mockHttp(routes: Record<string, Handler> = {}) {
  const requests: RecordedRequest[] = [];
  const table = { ...routes };

  const fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input);
    const headers = (init.headers ?? {}) as Record<string, string>;
    const req: RecordedRequest = {
      method: init.method ?? 'GET',
      path: `${url.pathname}${url.search}`,
      auth: headers.Authorization ?? null,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : null,
    };
    requests.push(req);
    const handler = table[`${req.method} ${req.path}`];
    const reply = handler ? await handler(req) : { status: 599, body: { error: `unrouted ${req.method} ${req.path}` } };
    return new Response(JSON.stringify(reply.body ?? {}), {
      status: reply.status ?? 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });

  vi.stubGlobal('fetch', fetchMock);

  return {
    requests,
    fetchMock,
    on(route: string, handler: Handler) {
      table[route] = handler;
    },
  };
}
