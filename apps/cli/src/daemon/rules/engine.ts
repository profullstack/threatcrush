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
  /**
   * `action: 'block'` lets auto-defence ban the source. How long for is not
   * the rule's call: every ban follows the escalation ladder (auto-defence.md).
   */
  remediation?: {
    action?: string;
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

/**
 * What a window keeps per event: when, and from where. Never the event itself:
 * a window used to hold every matching ThreatEvent (URL, user agent, details),
 * and a window whose address never came back kept its events forever, because
 * old ones were only dropped when a new one arrived for the same key and
 * cleanup() only removed windows that were already empty. On dev2 (hundreds of
 * thousands of addresses a day) that was ~280 MB an hour of heap.
 */
interface EventWindow {
  times: number[];
  ips: Array<string | undefined>;
  /** Index of the oldest entry still inside the rule's window. */
  head: number;
  lastAlert: number;
  /** The rule's window and cooldown, so cleanup() can expire it alone. */
  windowMs: number;
  cooldownMs: number;
}

/** Per-window ceiling. A threshold is the most any rule needs to see. */
export const MAX_WINDOW_ENTRIES = 1000;

function live(window: EventWindow): number {
  return window.times.length - window.head;
}

/** Drop entries older than the window; compact now and then. */
function expire(window: EventWindow, now: number): void {
  const cutoff = now - window.windowMs;
  while (window.head < window.times.length && window.times[window.head] < cutoff) window.head++;
  if (window.head > 64 && window.head * 2 > window.times.length) {
    window.times = window.times.slice(window.head);
    window.ips = window.ips.slice(window.head);
    window.head = 0;
  }
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
        window = {
          times: [],
          ips: [],
          head: 0,
          lastAlert: 0,
          windowMs: rule.window_seconds * 1000,
          cooldownMs: rule.cooldown_seconds * 1000,
        };
        this.windows.set(windowKey, window);
      }

      // Add the event, drop what fell out of the window, and keep at most
      // MAX_WINDOW_ENTRIES (the newest): past that, more entries change nothing
      // but the reported count, which then reads "1000+".
      window.times.push(now);
      window.ips.push(event.source_ip);
      expire(window, now);
      const cap = Math.max(rule.threshold, MAX_WINDOW_ENTRIES);
      let capped = false;
      if (live(window) > cap) {
        window.head = window.times.length - cap;
        capped = true;
        expire(window, now);
      }

      // Check threshold
      if (live(window) < rule.threshold) continue;

      // Check cooldown
      if (window.lastAlert > 0 && (now - window.lastAlert) < window.cooldownMs) continue;

      // Fire detection.
      const hits = live(window);
      const distinctIps = new Set(window.ips.slice(window.head).filter(Boolean)).size;
      window.lastAlert = now;
      // Reset window after detection
      window.times = [];
      window.ips = [];
      window.head = 0;
      const hitsLabel = capped ? `${hits}+` : String(hits);

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
        description: `${rule.description} (${hitsLabel} events in ${rule.window_seconds}s${spread})`,
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

  /**
   * Expire every window by its own rule's length, and forget windows with
   * nothing left in them once their cooldown is over (a cooldown must outlive
   * an empty window, or a source could re-trigger the moment it was forgotten).
   * Without the expiry, a window whose address never came back was kept forever.
   */
  cleanup(now: number = Date.now()): number {
    let removed = 0;
    for (const [key, window] of this.windows) {
      expire(window, now);
      if (live(window) === 0 && (window.lastAlert === 0 || now - window.lastAlert >= window.cooldownMs)) {
        this.windows.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /** How many windows are open, for tests and the status report. */
  windowCount(): number {
    return this.windows.size;
  }
}
