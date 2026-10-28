import { apiUrl } from './cli-config.js';
import { PKG_VERSION } from './version.js';

// Node's fetch says "node" and nothing else, so threatcrush.com cannot tell a
// CLI on 0.13.40 from one on 0.13.51, or the CLI from any other Node script.
// The CLI and the daemon both call installUserAgent() once at startup; every
// request to our own API that does not set a User-Agent then carries
// `threatcrush/<version>`. Third-party hosts (abuse.ch, Discord, PagerDuty, a
// scan target) are left alone: they get Node's default, as before.

export const USER_AGENT = `threatcrush/${PKG_VERSION} (node ${process.version}; ${process.platform})`;

/** True for the configured API host and threatcrush.com or any of its subdomains. */
export function isOurHost(url: string, api = apiUrl()): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  let apiHost = '';
  try {
    apiHost = new URL(api).hostname.toLowerCase();
  } catch {}
  return host === apiHost || host === 'threatcrush.com' || host.endsWith('.threatcrush.com');
}

function urlOf(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** Wraps `target.fetch` so requests to our API carry the CLI's user agent. Idempotent. */
export function installUserAgent(target: { fetch: typeof fetch } = globalThis): void {
  const base = target.fetch as typeof fetch & { __threatcrushUA?: true };
  if (!base || base.__threatcrushUA) return;
  const wrapped = ((input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    if (!isOurHost(urlOf(input))) return base(input, init);
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (headers.has('user-agent')) return base(input, init);
    headers.set('user-agent', USER_AGENT);
    return base(input, { ...init, headers });
  }) as typeof fetch & { __threatcrushUA?: true };
  wrapped.__threatcrushUA = true;
  target.fetch = wrapped;
}
