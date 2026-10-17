import { describe, it, expect, vi, afterEach } from 'vitest';
import { formSpamIdentity, summarizeEvidence } from '../workers/abuse-evidence.js';
import { buildPayload, dispatch, reportToStopForumSpam } from '../workers/abuse-destinations.js';
import type { ThreatEvent } from '../../types/events.js';

const NOW = Date.UTC(2026, 0, 1, 12, 0, 0);

function ev(module: string, ageMs: number, details?: Record<string, unknown>): ThreatEvent {
  return {
    timestamp: new Date(NOW - ageMs),
    module,
    category: 'web',
    severity: 'high',
    message: 'spam signup',
    source_ip: '198.51.100.9',
    details,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('formSpamIdentity', () => {
  it('reads the username + email a form submission used', () => {
    expect(formSpamIdentity(ev('form-guard', 0, { form_spam: { username: ' spambot99 ', email: 'x@spam.example' } })))
      .toEqual({ username: 'spambot99', email: 'x@spam.example' });
  });

  it('refuses half an identity or a non-email', () => {
    expect(formSpamIdentity(ev('form-guard', 0, { form_spam: { username: 'spambot99' } }))).toBeUndefined();
    expect(formSpamIdentity(ev('form-guard', 0, { form_spam: { username: 'a', email: 'not-an-email' } }))).toBeUndefined();
    expect(formSpamIdentity(ev('form-guard', 0, { form_spam: { username: '', email: 'x@spam.example' } }))).toBeUndefined();
    expect(formSpamIdentity(ev('rule-engine', 0, { rule_id: 'sqli' }))).toBeUndefined();
  });

  it('summarizeEvidence keeps the most recent identity', () => {
    const e = summarizeEvidence([
      ev('form-guard', 9_000, { form_spam: { username: 'old', email: 'old@spam.example' } }),
      ev('form-guard', 1_000, { form_spam: { username: 'new', email: 'new@spam.example' } }),
      ev('rule-engine', 5_000),
    ]);
    expect(e.formSpam).toEqual({ username: 'new', email: 'new@spam.example' });
  });
});

describe('StopForumSpam submitter', () => {
  const withForm = buildPayload(
    '198.51.100.9',
    summarizeEvidence([
      ev('form-guard', 7_200_000, { form_spam: { username: 'spambot99', email: 'x@spam.example' } }),
      ev('rule-engine', 7_000_000),
    ]),
  );
  const noForm = buildPayload('198.51.100.9', summarizeEvidence([ev('rule-engine', 7_200_000), ev('ssh-guard', 7_000_000)]));

  it('POSTs add.php with api_key, ip_addr, username, email and evidence; 200 is success', async () => {
    const fetchMock = vi.fn(async () => new Response('', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const r = await reportToStopForumSpam(withForm, 'KEY');
    expect(r).toEqual({ destination: 'stopforumspam', ok: true, detail: 'reported' });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://www.stopforumspam.com/add.php');
    expect(init.method).toBe('POST');
    const body = new URLSearchParams(String(init.body));
    expect(body.get('api_key')).toBe('KEY');
    expect(body.get('ip_addr')).toBe('198.51.100.9');
    expect(body.get('username')).toBe('spambot99');
    expect(body.get('email')).toBe('x@spam.example');
    expect(body.get('evidence')).toContain('Automated report from ThreatCrush');
    expect(body.has('ip')).toBe(false);
  });

  it('surfaces the <p> reason on a 403 refusal', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html><p>Invalid API key</p></html>', { status: 403 })));
    const r = await reportToStopForumSpam(withForm, 'KEY');
    expect(r.ok).toBe(false);
    expect(r.detail).toBe('HTTP 403 Invalid API key');
  });

  it('never calls SFS without a real form-spam identity', async () => {
    const fetchMock = vi.fn(async () => new Response('', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    expect((await reportToStopForumSpam(noForm, 'KEY')).detail).toMatch(/^skipped/);
    expect(await dispatch(noForm, ['stopforumspam'], { stopforumspam: 'KEY' })).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('dispatch sends a form-spam source to SFS', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 200 })));
    const results = await dispatch(withForm, ['stopforumspam'], { stopforumspam: 'KEY' });
    expect(results.map((r) => r.destination)).toEqual(['stopforumspam']);
  });
});
