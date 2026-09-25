import { describe, it, expect, vi } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';

// The modules import ../../core/state for insertEvent; there is no DB in a unit
// test, and insertEvent is best-effort by design.
vi.mock('../../core/state.js', () => ({ insertEvent: () => {} }));

const { NetworkMonitor } = await import('../../modules/network-monitor/index.js');
const { DnsMonitor } = await import('../../modules/dns-monitor/index.js');

function capturingBus() {
  const events: ThreatEvent[] = [];
  return { events, bus: { publish: (e: ThreatEvent) => events.push(e) } as never };
}

describe('dns-monitor', () => {
  it('counts queries it parses and reports them in a proof-of-life heartbeat', () => {
    const { events, bus } = capturingBus();
    const mon = new DnsMonitor(bus) as any;
    // Our own resolver's line format: [dns] udp <client> <name> <qtype> <action>
    mon.parseDnsLine('[dns] udp 10.0.0.5 shop.moshpit 1 registry 4ms');
    mon.parseDnsLine('[dns] udp 10.0.0.6 app.moshcode.sh 28 forwarded 11ms');
    mon.heartbeat();

    const hb = events.find((e) => (e.details as any)?.heartbeat);
    expect(hb, 'a heartbeat event should be emitted').toBeTruthy();
    expect(hb!.severity).toBe('info'); // never bannable
    expect((hb!.details as any).observed).toBe(2);
    // The counter resets, so the next quiet window reports zero rather than re-counting.
    mon.heartbeat();
    const last = events.filter((e) => (e.details as any)?.heartbeat).at(-1)!;
    expect((last.details as any).observed).toBe(0);
  });

  it('still detects DNS tunneling (TXT flood) as high severity', () => {
    const { events, bus } = capturingBus();
    const mon = new DnsMonitor(bus) as any;
    for (let i = 0; i < 25; i++) {
      mon.parseDnsLine('query[TXT] exfil.evil.example from 203.0.113.9');
    }
    mon.analyzeBuffer();
    const alert = events.find((e) => e.severity === 'high' && /tunnel/i.test(e.message));
    expect(alert, 'TXT flood should still alert').toBeTruthy();
  });
});

describe('network-monitor', () => {
  const conns = (ip: string, ports: number[]) =>
    ports.map((p) => ({ source_ip: ip, dest_port: p, timestamp: Date.now() }));

  it('surfaces a smaller scan (5-9 ports) at medium, which never bans', () => {
    const { events, bus } = capturingBus();
    const mon = new NetworkMonitor(bus) as any;
    mon.analyzePortScans(conns('198.51.100.7', [1, 2, 3, 4, 5]));
    const notice = events.find((e) => e.severity === 'medium' && /possible port scan/i.test(e.message));
    expect(notice, 'a medium notice should fire at 5 listening ports').toBeTruthy();
    // Not banned: nothing at high severity yet.
    expect(events.some((e) => e.severity === 'high')).toBe(false);
  });

  it('still bans a real scan (10+ ports) at high severity', () => {
    const { events, bus } = capturingBus();
    const mon = new NetworkMonitor(bus) as any;
    mon.analyzePortScans(conns('198.51.100.8', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
    const alert = events.find((e) => e.severity === 'high' && /port scan detected/i.test(e.message));
    expect(alert, '10 ports should still be a high-severity detection').toBeTruthy();
  });

  it('emits a proof-of-life heartbeat at info severity', () => {
    const { events, bus } = capturingBus();
    const mon = new NetworkMonitor(bus) as any;
    mon.obsConnections = 3;
    mon.obsSources = new Set(['a', 'b']);
    mon.heartbeat();
    const hb = events.find((e) => (e.details as any)?.heartbeat);
    expect(hb).toBeTruthy();
    expect(hb!.severity).toBe('info');
    expect((hb!.details as any).inbound).toBe(3);
  });
});
