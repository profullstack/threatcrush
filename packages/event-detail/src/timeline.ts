import type { EventLike } from './types';
import { fingerprintOf, hostKeyOf, rowSummary, ruleOf, sourceIpOf, toMs, effectiveSeverity } from './model';

export type Relation = 'ip' | 'key' | 'host' | 'rule';
export const RELATIONS: Relation[] = ['ip', 'key', 'host', 'rule'];
export const RELATION_LABEL: Record<Relation, string> = {
  ip: 'Same source IP',
  key: 'Same key',
  host: 'Same host',
  rule: 'Same rule',
};

export interface TimelineItem {
  event: EventLike;
  at: number;
  relations: Relation[];
  current: boolean;
  summary: string;
  severity: string;
}

/** How `other` relates to `primary`: same source address, key fingerprint, host, rule. */
export function relationsBetween(primary: EventLike, other: EventLike): Relation[] {
  const out: Relation[] = [];
  const ip = sourceIpOf(primary);
  if (ip && sourceIpOf(other) === ip) out.push('ip');
  const fp = fingerprintOf(primary);
  if (fp && fingerprintOf(other) === fp) out.push('key');
  const host = hostKeyOf(primary);
  if (host && hostKeyOf(other) === host) out.push('host');
  const rule = ruleOf(primary);
  if (rule && ruleOf(other) === rule) out.push('rule');
  return out;
}

/**
 * The event's history: every candidate related to it by address, key, host
 * or rule, newest first, with the event itself marked current. Candidates
 * with no relation are dropped; duplicates (same id) are kept once.
 */
export function buildTimeline(primary: EventLike, candidates: EventLike[], limit = 300): TimelineItem[] {
  const seen = new Set<string>();
  const items: TimelineItem[] = [];
  for (const e of [primary, ...candidates]) {
    if (!e?.id || seen.has(e.id)) continue;
    seen.add(e.id);
    const current = e.id === primary.id;
    const relations = current ? RELATIONS.filter((r) => relationsBetween(primary, primary).includes(r)) : relationsBetween(primary, e);
    if (!current && relations.length === 0) continue;
    items.push({ event: e, at: toMs(e.at), relations, current, summary: rowSummary(e).text, severity: effectiveSeverity(e) });
  }
  return items.sort((a, b) => (b.at || 0) - (a.at || 0)).slice(0, limit);
}

export function filterTimeline(items: TimelineItem[], filter: Relation | 'all'): TimelineItem[] {
  return filter === 'all' ? items : items.filter((i) => i.current || i.relations.includes(filter));
}

export function relationCounts(items: TimelineItem[]): Record<Relation | 'all', number> {
  const out = { all: 0, ip: 0, key: 0, host: 0, rule: 0 } as Record<Relation | 'all', number>;
  for (const i of items) {
    if (i.current) continue;
    out.all++;
    for (const r of i.relations) out[r]++;
  }
  return out;
}
