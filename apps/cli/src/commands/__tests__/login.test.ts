import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../core/cli-config.js', () => ({
  CLI_CONFIG_PATH: '/nonexistent/config.json',
  apiUrl: () => 'https://threatcrush.com',
  authHeaders: () => ({}),
  clearCliConfig: vi.fn(),
  isLoggedIn: () => false,
  readCliConfig: () => ({}),
  updateCliConfig: vi.fn(),
}));

const realStdin = Object.getOwnPropertyDescriptor(process, 'stdin')!;

function pipeStdin(content: string): void {
  const stdin = new PassThrough();
  Object.defineProperty(process, 'stdin', { value: stdin, configurable: true });
  stdin.end(content);
}

async function loadLoginCommand() {
  // A fresh module graph, so prompt.ts's piped reader binds to this test's stdin.
  vi.resetModules();
  return (await import('../login.js')).loginCommand;
}

let output: string;

beforeEach(() => {
  output = '';
  process.exitCode = undefined;
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    output += `${args.join(' ')}\n`;
  });
});

afterEach(() => {
  Object.defineProperty(process, 'stdin', realStdin);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

describe('threatcrush login', () => {
  it('prints a link to approve by default and never asks for a password', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (String(url).endsWith('/api/auth/cli/start')) {
        return new Response(JSON.stringify({
          request_id: '00000000-0000-4000-8000-000000000000',
          user_code: 'ABCD-EFGH',
          verification_url: 'https://threatcrush.com/cli/login?request=00000000-0000-4000-8000-000000000000',
          expires_at: new Date(Date.now() + 600_000).toISOString(),
          interval: 0,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ error: 'access_denied' }), { status: 400 });
    }));

    await (await loadLoginCommand())();

    expect(output).toContain('https://threatcrush.com/cli/login?request=00000000-0000-4000-8000-000000000000');
    expect(output).toContain('ABCD-EFGH');
    expect(output).not.toMatch(/Password:/);
    expect(process.exitCode).toBe(1);
  });

  it('exits non-zero when the credentials are rejected', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Invalid login credentials' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    )));
    pipeStdin('nobody@example.invalid\nwrong\n');

    await (await loadLoginCommand())({ password: true });

    expect(output).toContain('Invalid login credentials');
    expect(process.exitCode).toBe(1);
  });

  it('exits non-zero when stdin ends before a password is entered', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    pipeStdin('nobody@example.invalid\n');

    await (await loadLoginCommand())({ password: true });

    expect(fetch).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });

  it('points a forgotten password at the sign-in page, which has the reset flow', async () => {
    // /auth/forgot-password is not a page; it 404s.
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 400 })));
    pipeStdin('nobody@example.invalid\nwrong\n');

    await (await loadLoginCommand())({ password: true });

    expect(output).toMatch(/Forgot password\? \S+\/auth\/login\b/);
    expect(output).not.toContain('/auth/forgot-password');
  });
});
