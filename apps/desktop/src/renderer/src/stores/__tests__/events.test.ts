import { describe, expect, it } from 'vitest'
import { fromDaemon, fromDetection, levelFor, mergeEvents, topSources } from '../events'

describe('levelFor', () => {
  it('maps daemon/fleet severities onto the three UI levels', () => {
    expect(levelFor('critical')).toBe('threat')
    expect(levelFor('high')).toBe('threat')
    expect(levelFor('medium')).toBe('warning')
    expect(levelFor('low')).toBe('warning')
    expect(levelFor('info')).toBe('info')
    expect(levelFor(undefined)).toBe('info')
  })
})

describe('fromDaemon / fromDetection', () => {
  it('keeps the daemon row id so a pushed copy of a fetched event dedupes', () => {
    const e = fromDaemon({ id: 7, timestamp: '2026-11-03T10:00:00Z', module: 'ssh-guard', severity: 'high', message: 'brute force', source_ip: '203.0.113.9' })
    expect(e).toMatchObject({ id: 'local-7', level: 'threat', module: 'ssh-guard', sourceIP: '203.0.113.9', origin: 'this machine' })
  })

  it('labels fleet detections with their server', () => {
    const e = fromDetection({
      id: 'a', server_id: 's', rule_id: 'ssh-brute', severity: 'medium', title: 'SSH brute force',
      description: null, source_ip: null, detected_at: '2026-11-03T10:00:00Z', status: 'new',
    }, 'dev2')
    expect(e).toMatchObject({ id: 'fleet-a', origin: 'dev2', level: 'warning', module: 'ssh-brute' })
    expect(e.sourceIP).toBeUndefined()
  })
})

describe('mergeEvents', () => {
  const ev = (id: string, at: number) => ({ id, at, timestamp: '', level: 'info' as const, module: 'm', message: '', origin: 'o', summary: '', detail: { id, at } })

  it('drops ids already shown and sorts newest first', () => {
    const merged = mergeEvents([ev('a', 2)], [ev('a', 2), ev('b', 3), ev('c', 1), ev('b', 3)])
    expect(merged.map((e) => e.id)).toEqual(['b', 'a', 'c'])
  })

  it('returns the same array when nothing is new (no re-render)', () => {
    const cur = [ev('a', 1)]
    expect(mergeEvents(cur, [ev('a', 1)])).toBe(cur)
  })
})

describe('topSources', () => {
  it('ranks warning/threat source IPs and ignores info', () => {
    const base = { timestamp: 't', at: 0, module: 'm', message: '', origin: 'o', summary: '', detail: { id: 'x', at: 0 } }
    const out = topSources([
      { ...base, id: '1', level: 'threat', sourceIP: '1.1.1.1' },
      { ...base, id: '2', level: 'warning', sourceIP: '1.1.1.1' },
      { ...base, id: '3', level: 'threat', sourceIP: '2.2.2.2' },
      { ...base, id: '4', level: 'info', sourceIP: '3.3.3.3' },
    ])
    expect(out.map((s) => [s.ip, s.hits])).toEqual([['1.1.1.1', 2], ['2.2.2.2', 1]])
  })
})

// RFC 5737 documentation addresses only.
const sshContext = {
  v: 1, at: '2026-11-22T03:58:33.000Z', host: 'web-1', user: 'deploy', auth_method: 'publickey',
  key: { found: true, type: 'ssh-ed25519', fingerprint: 'SHA256:fixture', comment: 'deploy@example/app', command: '/usr/local/bin/ci-deploy example/app', options: ['restrict'], restrict: true },
  source: { ip: '192.0.2.10', kind: 'github-actions' },
  verdict: { level: 'likely-ci', severity: 'low', summary: 'Likely CI deploy: GitHub Actions IP, forced-command deploy key', reasons: [] },
}

describe('SSH login context in the event log', () => {
  it('shows a fleet CI deploy as a quiet row with who, key and source', () => {
    const e = fromDetection({
      id: '00000000-0000-4000-8000-000000000001', server_id: 's', rule_id: 'ssh-success-after-failures', severity: 'critical',
      title: 'SSH Login Accepted', description: null, source_ip: '192.0.2.10', detected_at: '2026-11-22T03:58:33Z', status: 'new',
      raw_metadata: { evidence: { module: 'ssh-guard', ssh_context: sshContext } },
    }, 'web-1')
    expect(e.level).toBe('warning')
    expect(e.detectionId).toBe('00000000-0000-4000-8000-000000000001')
    expect(e.summary).toBe('SSH Login Accepted · deploy@web-1 · publickey ED25519 forced-command key "deploy@example/app" · from 192.0.2.10 (GitHub Actions)')
  })

  it('keeps an old dashboard response (no raw_metadata) working', () => {
    const e = fromDetection({
      id: 'b', server_id: 's', rule_id: 'ssh-success-after-failures', severity: 'critical', title: 'SSH Login Accepted',
      description: null, source_ip: '192.0.2.10', detected_at: '2026-11-22T03:58:33Z', status: 'new',
    }, 'web-1')
    expect(e.level).toBe('threat')
    expect(e.summary).toBe('SSH Login Accepted')
  })

  it('reads a pushed local rule-engine detection with its details', () => {
    const e = fromDaemon({
      timestamp: '2026-11-22T03:58:33Z', module: 'rule-engine', severity: 'low', message: '[DETECTION] SSH Login Accepted', source_ip: '192.0.2.10',
      details: { rule_id: 'ssh-success-after-failures', evidence: { ssh_context: sshContext } },
    })
    expect(e.module).toBe('ssh-success-after-failures')
    expect(e.message).toBe('SSH Login Accepted')
    expect(e.detail.metadata).toBeTruthy()
    expect(e.summary).toContain('from 192.0.2.10 (GitHub Actions)')
  })

  it('parses details stored as JSON text', () => {
    const e = fromDaemon({ id: 9, timestamp: 0, module: 'ssh-guard', message: 'x', details: JSON.stringify({ fingerprint: 'SHA256:a' }) })
    expect(e.detail.metadata).toEqual({ fingerprint: 'SHA256:a' })
  })
})
