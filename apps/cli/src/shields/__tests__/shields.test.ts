import { describe, expect, it } from 'vitest';
import {
  allServicePorts,
  COMMON_PORTS,
  FILE_SHARING_PORTS,
  HIGH_RISK_OPEN,
  parsePortList,
} from '../ports.js';
import { scanPorts, summarizeShields, type PortProber, type PortState } from '../scan.js';
import { buildShieldsReport, renderGrid } from '../report.js';
import { portsForTest, runShields } from '../index.js';

/** A prober driven by a fixed map of port→state (default stealth). */
function fakeProber(states: Record<number, PortState>): PortProber {
  return async (_host, port) => states[port] ?? 'stealth';
}

describe('port catalogues', () => {
  it('common ports include the classic file-sharing and modern services', () => {
    const nums = COMMON_PORTS.map((p) => p.port);
    for (const p of [21, 23, 80, 135, 139, 443, 445, 3389]) expect(nums).toContain(p);
  });

  it('all-service sweep is 0–1055 inclusive (1056 ports)', () => {
    const all = allServicePorts();
    expect(all).toHaveLength(1056);
    expect(all[0].port).toBe(0);
    expect(all[all.length - 1].port).toBe(1055);
  });

  it('parsePortList handles ranges, dedupes, and drops junk', () => {
    const got = parsePortList('22, 80 443 8000-8002 80 70000 abc');
    expect(got.map((p) => p.port)).toEqual([22, 80, 443, 8000, 8001, 8002]);
  });

  it('parsePortList labels a known port', () => {
    expect(parsePortList('443')[0].name).toBe('HTTPS');
  });
});

describe('scanPorts', () => {
  it('maps each port to the prober result', async () => {
    const prober = fakeProber({ 80: 'open', 22: 'closed' });
    const results = await scanPorts('1.2.3.4', parsePortList('22,80,443'), prober, { concurrency: 2 });
    const byPort = Object.fromEntries(results.map((r) => [r.port, r.state]));
    expect(byPort).toEqual({ 22: 'closed', 80: 'open', 443: 'stealth' });
  });

  it('never throws when the prober rejects — treats it as stealth', async () => {
    const prober: PortProber = async () => { throw new Error('boom'); };
    const results = await scanPorts('1.2.3.4', parsePortList('80'), prober);
    expect(results[0].state).toBe('stealth');
  });

  it('reports progress for every port', async () => {
    const seen: number[] = [];
    await scanPorts('h', parsePortList('1,2,3,4'), fakeProber({}), {
      onPort: (_r, done, total) => { expect(total).toBe(4); seen.push(done); },
    });
    expect(seen.sort((a, b) => a - b)).toEqual([1, 2, 3, 4]);
  });
});

describe('summarizeShields grading', () => {
  it('all stealth → perfect stealth', () => {
    const s = summarizeShields([
      { port: 80, name: 'HTTP', state: 'stealth' },
      { port: 443, name: 'HTTPS', state: 'stealth' },
    ], HIGH_RISK_OPEN);
    expect(s.grade).toBe('stealth');
    expect(s.open).toBe(0);
  });

  it('closed-but-not-open → good (visible)', () => {
    const s = summarizeShields([{ port: 80, name: 'HTTP', state: 'closed' }], HIGH_RISK_OPEN);
    expect(s.grade).toBe('good');
  });

  it('open non-risky port → warning', () => {
    const s = summarizeShields([{ port: 8080, name: '', state: 'open' }], HIGH_RISK_OPEN);
    expect(s.grade).toBe('warning');
  });

  it('open high-risk port (SMB) → danger', () => {
    const s = summarizeShields([{ port: 445, name: 'SMB', state: 'open' }], HIGH_RISK_OPEN);
    expect(s.grade).toBe('danger');
    expect(s.openPorts.map((p) => p.port)).toContain(445);
  });
});

describe('buildShieldsReport', () => {
  it('grades an open SMB port as high and emits a RunResult of type shields', () => {
    const { result } = buildShieldsReport('1.2.3.4', [
      { port: 445, name: 'SMB', state: 'open' },
      { port: 80, name: 'HTTP', state: 'stealth' },
    ]);
    expect(result.type).toBe('shields');
    const smb = result.findings.find((f) => f.type === 'open-port');
    expect(smb?.severity).toBe('high');
    expect(result.severity_summary.high).toBe(1);
  });

  it('grades an open non-risky port as medium', () => {
    const { result } = buildShieldsReport('h', [{ port: 8080, name: 'HTTP-alt', state: 'open' }]);
    expect(result.findings[0].severity).toBe('medium');
  });

  it('flags a visible (closed, not stealth) machine as a low finding', () => {
    const { result, summary } = buildShieldsReport('h', [{ port: 80, name: 'HTTP', state: 'closed' }]);
    expect(summary.grade).toBe('good');
    expect(result.findings.some((f) => f.type === 'not-stealth')).toBe(true);
  });

  it('a fully stealth host has no findings', () => {
    const { result } = buildShieldsReport('h', [{ port: 80, name: 'HTTP', state: 'stealth' }]);
    expect(result.findings).toHaveLength(0);
  });
});

describe('renderGrid', () => {
  it('renders one glyph per port with the leading port number', () => {
    const grid = renderGrid([
      { port: 80, name: 'HTTP', state: 'open' },
      { port: 81, name: '', state: 'stealth' },
    ]);
    expect(grid).toContain('80');
    expect(grid.split('\n')).toHaveLength(1);
  });
});

describe('portsForTest / runShields', () => {
  it('selects the file-sharing set', () => {
    expect(portsForTest({ test: 'file-sharing' })).toEqual(FILE_SHARING_PORTS);
  });

  it('explicit ports override the named test', () => {
    expect(portsForTest({ test: 'all', ports: '22,80' }).map((p) => p.port)).toEqual([22, 80]);
  });

  it('runShields end-to-end with a fake prober', async () => {
    const { result, summary } = await runShields('1.2.3.4', fakeProber({ 22: 'open' }), { ports: '22,80,443' });
    expect(result.type).toBe('shields');
    expect(summary.open).toBe(1);
    expect(result.target).toBe('1.2.3.4');
  });
});
