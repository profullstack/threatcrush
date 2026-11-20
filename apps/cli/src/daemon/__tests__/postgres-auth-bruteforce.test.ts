import { describe, it, expect, vi } from 'vitest';
import type { ClientRequest } from 'node:http';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_RULES } from '../rules/default-rules.js';
import { RuleEngine } from '../rules/engine.js';

vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const {
  parsePostgresAuthFailure,
  postgresAuthEvent,
  cleanPgHost,
  DockerLogDecoder,
  DockerLogsWatch,
  dockerLogsSettings,
} = await import('../workers/docker-logs.js');

// The dev2 incident's lines, verbatim apart from the addresses.
const PW = '45.156.87.10 2026-11-19 16:42:07.224 UTC [585901] postgres@postgres FATAL:  password authentication failed for user "postgres"';
const HBA = '1.2.3.4 2026-11-19 16:42:08.001 UTC [585902] x@y FATAL:  no pg_hba.conf entry for host "1.2.3.4", user "x", database "y", no encryption';

function fire(events: ThreatEvent[]): Array<{ rule_id: string; source_ip?: string; action?: string }> {
  const fired: Array<{ rule_id: string; source_ip?: string; action?: string }> = [];
  const engine = new RuleEngine((d) => fired.push({
    rule_id: d.rule_id,
    source_ip: d.source_ip,
    action: (d.raw_metadata?.remediation as { action?: string } | undefined)?.action,
  }));
  engine.loadRules(DEFAULT_RULES);
  for (const e of events) engine.evaluate(e);
  return fired;
}

describe('parsePostgresAuthFailure', () => {
  it('reads a password failure with the client first in log_line_prefix', () => {
    expect(parsePostgresAuthFailure(PW)).toEqual({ kind: 'password', ip: '45.156.87.10', user: 'postgres', database: 'postgres' });
  });

  it('reads a pg_hba reject, taking the host from the message', () => {
    expect(parsePostgresAuthFailure(HBA)).toEqual({ kind: 'pg_hba', ip: '1.2.3.4', user: 'x', database: 'y' });
    const noPrefix = '2026-11-19 16:42:08 UTC [1] FATAL:  no pg_hba.conf entry for host "203.0.113.7", user "admin", database "app", SSL off';
    expect(parsePostgresAuthFailure(noPrefix)?.ip).toBe('203.0.113.7');
  });

  it('handles %r host(port), IPv6 and v4-mapped forms', () => {
    expect(cleanPgHost('198.51.100.4(51234)')).toBe('198.51.100.4');
    expect(cleanPgHost('::ffff:198.51.100.4')).toBe('198.51.100.4');
    expect(cleanPgHost('2001:db8::5')).toBe('2001:db8::5');
    expect(cleanPgHost('[local]')).toBeUndefined();
  });

  it('knows no client when the prefix carries none', () => {
    const bare = '2026-11-19 16:42:07.224 UTC [585901] FATAL:  password authentication failed for user "postgres"';
    expect(parsePostgresAuthFailure(bare)).toEqual({ kind: 'password', user: 'postgres' });
    expect(postgresAuthEvent(bare, 'supabase-db')).toBeNull();
  });

  it('ignores other lines', () => {
    expect(parsePostgresAuthFailure('45.156.87.10 2026-11-19 UTC [1] LOG:  connection received: host=45.156.87.10 port=1')).toBeNull();
    expect(parsePostgresAuthFailure('172.18.0.5 2026-11-19 UTC [1] authenticator@postgres LOG:  connection authorized')).toBeNull();
  });
});

describe('postgresAuthEvent', () => {
  it('puts the client in source_ip, below the ban floor on its own', () => {
    const e = postgresAuthEvent(PW, 'supabase-db')!;
    expect(e.module).toBe('postgres-guard');
    expect(e.source_ip).toBe('45.156.87.10');
    expect(e.severity).toBe('low');
    expect(e.details).toMatchObject({ container: 'supabase-db', kind: 'password', user: 'postgres' });
  });

  it('never names a private, loopback, docker-bridge or protected source', () => {
    for (const ip of ['10.1.2.3', '172.18.0.1', '192.168.1.9', '127.0.0.1', '::1']) {
      expect(postgresAuthEvent(PW.replace('45.156.87.10', ip), 'supabase-db')).toBeNull();
    }
    expect(postgresAuthEvent(PW, 'supabase-db', ['45.156.87.0/24'])).toBeNull();
    expect(postgresAuthEvent(HBA, 'supabase-db', ['1.2.3.4'])).toBeNull();
  });
});

describe('postgres-auth-bruteforce rule', () => {
  const rule = DEFAULT_RULES.find((r) => r.id === 'postgres-auth-bruteforce')!;

  it('is high, 5 in 600s, and blocks', () => {
    expect(rule).toMatchObject({ severity: 'high', threshold: 5, window_seconds: 600, remediation: { action: 'block' }, enabled: true });
  });

  it('fires on the fifth failure from one address and names it', () => {
    const four = Array.from({ length: 4 }, () => postgresAuthEvent(PW, 'supabase-db')!);
    expect(fire(four).filter((d) => d.rule_id === rule.id)).toEqual([]);
    const five = [...four, postgresAuthEvent(PW, 'supabase-db')!];
    expect(fire(five).filter((d) => d.rule_id === rule.id)).toEqual([{ rule_id: rule.id, source_ip: '45.156.87.10', action: 'block' }]);
  });

  it('counts pg_hba rejects and password failures together', () => {
    const mixed = [
      ...Array.from({ length: 3 }, () => postgresAuthEvent(PW.replace('45.156.87.10', '1.2.3.4'), 'a-supabase-db')!),
      ...Array.from({ length: 2 }, () => postgresAuthEvent(HBA, 'b-supabase-db')!),
    ];
    expect(fire(mixed).map((d) => d.rule_id)).toContain(rule.id);
  });

  it('does not fire across different addresses', () => {
    const spread = ['1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5', '1.1.1.6'].map((ip) => postgresAuthEvent(PW.replace('45.156.87.10', ip), 'supabase-db')!);
    expect(fire(spread).map((d) => d.rule_id)).not.toContain(rule.id);
  });

  it('is not claimed by any other default block rule', () => {
    const five = Array.from({ length: 5 }, () => postgresAuthEvent(PW, 'supabase-db')!);
    expect(fire(five).map((d) => d.rule_id)).toEqual([rule.id]);
  });
});

describe('DockerLogDecoder', () => {
  const frame = (stream: number, text: string) => {
    const payload = Buffer.from(text);
    const head = Buffer.alloc(8);
    head[0] = stream;
    head.writeUInt32BE(payload.length, 4);
    return Buffer.concat([head, payload]);
  };

  it('demultiplexes framed stdout/stderr, across chunk boundaries', () => {
    const lines: string[] = [];
    const d = new DockerLogDecoder(false, (l) => lines.push(l));
    const all = Buffer.concat([frame(2, `${PW}\n${HBA.slice(0, 20)}`), frame(2, `${HBA.slice(20)}\n`), frame(1, 'ok\n')]);
    for (let i = 0; i < all.length; i += 7) d.push(all.subarray(i, i + 7));
    expect(lines).toEqual([PW, HBA, 'ok']);
  });

  it('reads TTY streams raw', () => {
    const lines: string[] = [];
    const d = new DockerLogDecoder(true, (l) => lines.push(l));
    d.push(Buffer.from(`${PW}\r\nsecond\n`));
    expect(lines).toEqual([PW, 'second']);
  });
});

describe('DockerLogsWatch', () => {
  function harness(containers: () => Array<{ Id: string; Names: string[]; Image: string }>) {
    const streams: Array<{ path: string; onData: (b: Buffer) => void; onEnd: () => void; destroyed: boolean }> = [];
    const published: ThreatEvent[] = [];
    const watch = new DockerLogsWatch({
      bus: { publish: (e) => published.push(e) },
      settings: dockerLogsSettings({}),
      log: () => {},
      deps: {
        getJson: async (path) => (path === '/containers/json' ? containers() : { Config: { Tty: true } }),
        stream: (path, onData, onEnd) => {
          const s = { path, onData, onEnd, destroyed: false };
          streams.push(s);
          return { destroy: () => { s.destroyed = true; onEnd(); } } as unknown as ClientRequest;
        },
      },
    });
    return { watch, streams, published };
  }

  it('follows supabase-db and postgres images only', async () => {
    const { watch } = harness(() => [
      { Id: 'a', Names: ['/supabase-db'], Image: 'supabase/postgres:15.8.1' },
      { Id: 'b', Names: ['/nichedb-supabase-db'], Image: 'x' },
      { Id: 'c', Names: ['/plain-pg'], Image: 'postgres:16' },
      { Id: 'd', Names: ['/supabase-rest'], Image: 'postgrest/postgrest:v12' },
      { Id: 'e', Names: ['/web'], Image: 'nginx' },
    ]);
    await watch.poll();
    expect(watch.following()).toEqual(['nichedb-supabase-db', 'plain-pg', 'supabase-db']);
  });

  it('publishes parsed events and picks up restarts and recreates', async () => {
    let list = [{ Id: 'a', Names: ['/supabase-db'], Image: 'supabase/postgres:15' }];
    const { watch, streams, published } = harness(() => list);
    await watch.poll();
    streams[0].onData(Buffer.from(`${PW}\n`));
    expect(published.map((e) => e.source_ip)).toEqual(['45.156.87.10']);

    // Restart: the stream ends, the same container is running again.
    streams[0].onEnd();
    expect(watch.following()).toEqual([]);
    await watch.poll();
    expect(streams).toHaveLength(2);
    expect(streams[1].path).toMatch(/^\/containers\/a\/logs\?follow=1&stdout=1&stderr=1&since=\d+$/);

    // Recreate: a new id under the same name; the old one is dropped.
    list = [{ Id: 'z', Names: ['/supabase-db'], Image: 'supabase/postgres:15' }];
    await watch.poll();
    expect(streams[1].destroyed).toBe(true);
    expect(streams[2].path).toContain('/containers/z/logs');
    expect(watch.following()).toEqual(['supabase-db']);
    watch.stop();
  });
});
