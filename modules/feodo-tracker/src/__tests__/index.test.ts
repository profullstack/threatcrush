import { describe, expect, it } from 'vitest';

import {
  indicatorKey,
  parseFeodoCsv,
  toThreatEvent,
} from '../index.js';

const FEED = `
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2026-02-10 12:00:00","203.0.113.8","443","online","2026-08-10","QakBot"
"2026-02-11 12:00:00","198.51.100.4","8080","offline","2026-08-01","Emotet"
# END 2 entries
`;

describe('parseFeodoCsv', () => {
  it('parses valid data rows and skips metadata', () => {
    const indicators = parseFeodoCsv(FEED);

    expect(indicators).toHaveLength(2);
    expect(indicators[0]).toEqual({
      firstSeenUtc: '2026-02-10 12:00:00',
      destinationIp: '203.0.113.8',
      destinationPort: 443,
      status: 'online',
      lastOnline: '2026-08-10',
      malware: 'QakBot',
    });
  });

  it('rejects invalid IP addresses and ports', () => {
    const invalid = `
"2026-02-10 12:00:00","999.0.0.1","443","online","2026-08-10","QakBot"
"2026-02-10 12:00:00","203.0.113.8","70000","online","2026-08-10","QakBot"
`;

    expect(parseFeodoCsv(invalid)).toEqual([]);
  });
});

describe('event mapping', () => {
  it('builds a stable key for a re-observed endpoint', () => {
    const [first] = parseFeodoCsv(FEED);

    expect(indicatorKey(first)).toBe(
      '203.0.113.8:443:2026-02-10 12:00:00',
    );
  });

  it('creates a high-severity network event for active C2', () => {
    const [first] = parseFeodoCsv(FEED);
    const event = toThreatEvent(first);

    expect(event).toMatchObject({
      module: 'feodo-tracker',
      category: 'network',
      severity: 'high',
      source_ip: '203.0.113.8',
    });
    expect(event.timestamp.toISOString()).toBe('2026-02-10T12:00:00.000Z');
  });
});
