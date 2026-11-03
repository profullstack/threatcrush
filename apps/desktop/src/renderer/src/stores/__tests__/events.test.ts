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
  const ev = (id: string, at: number) => ({ id, at, timestamp: '', level: 'info' as const, module: 'm', message: '', origin: 'o' })

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
    const base = { timestamp: 't', at: 0, module: 'm', message: '', origin: 'o' }
    const out = topSources([
      { ...base, id: '1', level: 'threat', sourceIP: '1.1.1.1' },
      { ...base, id: '2', level: 'warning', sourceIP: '1.1.1.1' },
      { ...base, id: '3', level: 'threat', sourceIP: '2.2.2.2' },
      { ...base, id: '4', level: 'info', sourceIP: '3.3.3.3' },
    ])
    expect(out.map((s) => [s.ip, s.hits])).toEqual([['1.1.1.1', 2], ['2.2.2.2', 1]])
  })
})
