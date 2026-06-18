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

      // Window key: rule_id + source_ip (or 'global')
      const windowKey = `${rule.id}:${event.source_ip || 'global'}`;
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

      // Fire detection
      window.lastAlert = now;
      window.events = []; // Reset window after detection

      this.onDetection({
        rule_id: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: `${rule.description} (${rule.threshold} events in ${rule.window_seconds}s)`,
        source_ip: event.source_ip,
        username: event.details?.user as string || undefined,
        raw_metadata: {
          rule_version: rule.version,
          tags: rule.tags,
          category: rule.category,
          remediation: rule.remediation,
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
