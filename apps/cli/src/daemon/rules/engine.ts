import type { ThreatEvent, EventSeverity } from '../../types/events.js';

export interface DetectionRule {
  id: string;
  title: string;
  description: string;
  version: string;
  category: string;
  severity: EventSeverity;
  source_types: string[];
  match: RuleMatch;
  threshold: number;
  window_seconds: number;
  cooldown_seconds: number;
  /**
   * What the threshold counts within. Default `source_ip` keeps the original
   * per-address behaviour: N events from ONE address. `endpoint` and `global`
   * count across ALL addresses, which is the only way to see a distributed
   * swarm — 100k IPs asking once each never trips a per-address rule (the
   * paywall-hammering case). An aggregate detection names no single offender,
   * so it fires as an alert and never bans one arbitrary IP out of the crowd.
   */
  group_by?: 'source_ip' | 'endpoint' | 'global';
  tags: string[];
  remediation?: {
    action?: string;
    ttl_seconds?: number;
    description?: string;
  };
  enabled: boolean;
}

export interface RuleMatch {
  field: string;
  operator: 'contains' | 'regex' | 'equals' | 'starts_with' | 'ends_with';
  value: string;
  and?: RuleMatch[];
  or?: RuleMatch[];
}

interface EventWindow {
  events: Array<{ timestamp: number; event: ThreatEvent }>;
  lastAlert: number;
}

export class RuleEngine {
  private rules: DetectionRule[] = [];
  private windows = new Map<string, EventWindow>();

  constructor(private onDetection: (detection: {
    rule_id: string;
    severity: EventSeverity;
    title: string;
    description: string;
    source_ip?: string;
    username?: string;
    raw_metadata?: Record<string, unknown>;
  }) => void) {}

  loadRules(rules: DetectionRule[]): void {
    this.rules = rules.filter(r => r.enabled !== false);
  }

  getRules(): DetectionRule[] {
    return [...this.rules];
  }

  evaluate(event: ThreatEvent): void {
    const now = Date.now();

    for (const rule of this.rules) {
      // Check source type match
      if (rule.source_types.length > 0 && !rule.source_types.includes(event.module) && !rule.source_types.includes(event.category)) {
        continue;
      }

      // Check match conditions
      if (!this.matchesCondition(event, rule.match)) continue;

      // Window key: rule_id + the dimension the threshold counts within.
      //   source_ip (default) — N events from one address
      //   endpoint            — N events to one path across every address
      //   global              — N events anywhere across every address
      // The endpoint/global keys are what catch a distributed swarm that a
      // per-address rule structurally cannot see.
      const groupBy = rule.group_by ?? 'source_ip';
      const groupValue =
        groupBy === 'endpoint'
          ? (event.details?.path as string | undefined) || 'unknown'
          : groupBy === 'global'
            ? 'all'
            : event.source_ip || 'global';
      const windowKey = `${rule.id}:${groupBy}:${groupValue}`;
      let window = this.windows.get(windowKey);
      if (!window) {
        window = { events: [], lastAlert: 0 };
        this.windows.set(windowKey, window);
      }

      // Add event to window
      window.events.push({ timestamp: now, event });

      // Prune old events outside window
      const cutoff = now - (rule.window_seconds * 1000);
      window.events = window.events.filter(e => e.timestamp >= cutoff);

      // Check threshold
      if (window.events.length < rule.threshold) continue;

      // Check cooldown
      if (window.lastAlert > 0 && (now - window.lastAlert) < (rule.cooldown_seconds * 1000)) continue;

      // Fire detection.
      const hits = window.events.length;
      const distinctIps = new Set(
        window.events.map((e) => e.event.source_ip).filter(Boolean),
      ).size;
      window.lastAlert = now;
      window.events = []; // Reset window after detection

      // An aggregate detection has no single culprit — attributing it to the
      // last event's IP would ban one arbitrary member of the crowd (often the
      // one legitimate crawler in it) and imply the other 100k were handled.
      // Report the crowd instead: no source_ip, the count, and what was hit.
      const aggregate = groupBy !== 'source_ip';
      const spread = aggregate
        ? ` from ${distinctIps} address${distinctIps === 1 ? '' : 'es'}${groupBy === 'endpoint' ? ` against ${groupValue}` : ''}`
        : '';

      this.onDetection({
        rule_id: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: `${rule.description} (${hits} events in ${rule.window_seconds}s${spread})`,
        source_ip: aggregate ? undefined : event.source_ip,
        username: event.details?.user as string || undefined,
        raw_metadata: {
          rule_version: rule.version,
          tags: rule.tags,
          category: rule.category,
          remediation: rule.remediation,
          ...(aggregate
            ? { group_by: groupBy, group: groupValue, distinct_ips: distinctIps, hits }
            : {}),
        },
      });
    }
  }

  private matchesCondition(event: ThreatEvent, match: RuleMatch): boolean {
    const fieldValue = this.getFieldValue(event, match.field);
    if (fieldValue === undefined) return false;

    const strValue = String(fieldValue);
    let result = false;

    switch (match.operator) {
      case 'contains':
        result = strValue.toLowerCase().includes(String(match.value).toLowerCase());
        break;
      case 'regex':
        try { result = new RegExp(String(match.value), 'i').test(strValue); } catch { result = false; }
        break;
      case 'equals':
        result = strValue === String(match.value);
        break;
      case 'starts_with':
        result = strValue.startsWith(String(match.value));
        break;
      case 'ends_with':
        result = strValue.endsWith(String(match.value));
        break;
    }

    // AND conditions
    if (result && match.and) {
      result = match.and.every(m => this.matchesCondition(event, m));
    }

    // OR conditions
    if (!result && match.or) {
      result = match.or.some(m => this.matchesCondition(event, m));
    }

    return result;
  }

  private getFieldValue(event: ThreatEvent, field: string): unknown {
    switch (field) {
      case 'message': return event.message;
      case 'severity': return event.severity;
      case 'module': return event.module;
      case 'category': return event.category;
      case 'source_ip': return event.source_ip;
      default:
        return event.details?.[field];
    }
  }

  // Periodic cleanup of stale windows
  cleanup(): void {
    const now = Date.now();
    for (const [key, window] of this.windows.entries()) {
      if (window.events.length === 0 && (now - window.lastAlert) > 3600_000) {
        this.windows.delete(key);
      }
    }
  }
}
