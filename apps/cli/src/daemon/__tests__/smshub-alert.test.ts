import { describe, it, expect } from 'vitest';
import { smshubChannel, smshubText } from '../alerts/smshub.js';
import type { ThreatEvent } from '../../types/events.js';

const tor: ThreatEvent = {
  timestamp: new Date(), module: 'ssh-intrusion', category: 'auth', severity: 'critical',
  message: 'SSH from Tor exit 185.129.61.4 (LOGGED IN as anthony): banned', source_ip: '185.129.61.4',
  details: { rule_id: 'ssh-from-tor', evidence: { message: 'Accepted publickey for anthony from 185.129.61.4 port 65366 ssh2' } },
};

describe('[alerts.smshub]', () => {
  it('pages critical events while the dashboard is down, once per 10 minutes per source', async () => {
    const calls: Array<{ url: string; body: string; key: string }> = [];
    const fetchImpl = (async (url: string, init: RequestInit) => {
      calls.push({ url, body: String(init.body), key: (init.headers as Record<string, string>)['X-API-Key'] });
      return new Response('{}', { status: 201 });
    }) as unknown as typeof fetch;
    let healthy = true;
    const ch = smshubChannel({ api_key: 'smshub_test' }, { cloudHealthy: () => healthy, fetchImpl });
    await ch(tor);
    expect(calls).toHaveLength(0); // the dashboard pages while it is reachable
    healthy = false;
    await ch(tor);
    await ch(tor);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://smshub.dev/api/v1/alerts');
    expect(calls[0].key).toBe('smshub_test');
    expect(JSON.parse(calls[0].body).severity).toBe('critical');
    await ch({ ...tor, severity: 'high', source_ip: '1.2.3.4' });
    expect(calls).toHaveLength(1);
  });

  it('says what happened and where', () => {
    expect(smshubText(tor, 'dev2')).toContain('ThreatCrush CRITICAL on dev2: SSH from Tor exit 185.129.61.4');
    expect(smshubText(tor, 'dev2')).toContain('Accepted publickey');
  });

  it('names the source address of a login page that did not already (2026-11-02)', () => {
    const login = { ...tor, message: '[DETECTION] SSH Login Accepted', source_ip: '40.76.239.105', details: { evidence: { message: 'SSH login accepted for anthony' } } };
    expect(smshubText(login, 'dev2')).toBe('ThreatCrush CRITICAL on dev2: [DETECTION] SSH Login Accepted | SSH login accepted for anthony from 40.76.239.105');
    expect(smshubText(tor, 'dev2').match(/185\.129\.61\.4/g)?.length).toBe(smshubText({ ...tor, source_ip: undefined }, 'dev2').match(/185\.129\.61\.4/g)?.length);
  });
});
