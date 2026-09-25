/**
 * DNS Monitor Module (PRD 05)
 *
 * Observes DNS query activity for tunneling and DGA indicators.
 * Sources: resolver logs, systemd-resolved, dnsmasq logs, passive :53 observation.
 */

import { existsSync, statSync, createReadStream, accessSync, constants } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import type { EventBus } from '../../daemon/event-bus.js';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

interface DnsQuery {
  domain: string;
  type: string;
  source_ip?: string;
  timestamp: number;
}

const DNS_LOG_SOURCES = [
  '/var/log/syslog',           // systemd-resolved logs here
  '/var/log/dnsmasq.log',      // dnsmasq
  '/var/log/named/queries.log', // bind9
  '/var/log/pihole.log',       // Pi-hole
];

/**
 * DNS query types arrive as numbers in some resolver logs — `1` and `28` are
 * simply A and AAAA, not counts, which is a reliable source of confusion when
 * the raw lines reach a human.
 */
export function qtypeName(qtype: number): string {
  const names: Record<number, string> = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS', 48: 'DNSKEY', 65: 'HTTPS',
    255: 'ANY',
  };
  return names[qtype] ?? `TYPE${qtype}`;
}

export class DnsMonitor {
  private active = false;
  private timers = new Map<string, NodeJS.Timeout>();
  private positions = new Map<string, number>();

  // Tracking windows
  private txtQueryCounts = new Map<string, { count: number; firstSeen: number }>();
  private domainBuffer: DnsQuery[] = [];

  // Config
  private txtRateThreshold = 20;      // TXT queries per source per window
  private txtWindowMs = 60_000;
  private dgaBurstThreshold = 15;     // unique high-entropy domains per window
  private dgaWindowMs = 60_000;
  private entropyThreshold = 3.5;     // Shannon entropy threshold for DGA

  /** Extra files and journal units from `[modules.dns-monitor]` in the config. */
  private extraPaths: string[] = [];
  private journalUnits: string[] = [];
  private journalTails: ChildProcess[] = [];

  constructor(private bus: EventBus, options: { log_paths?: string[]; journal_units?: string[] } = {}) {
    this.extraPaths = options.log_paths ?? [];
    this.journalUnits = options.journal_units ?? [];
  }

  start(): boolean {
    const sources = [...DNS_LOG_SOURCES, ...this.extraPaths].filter(p => {
      if (!existsSync(p)) return false;
      try { accessSync(p, constants.R_OK); return true; }
      catch { return false; }
    });

    // A resolver that logs to journald — ours does — has no file to tail, and
    // was therefore invisible to this module however much DNS it served.
    for (const unit of this.journalUnits) this.tailJournalUnit(unit);

    if (sources.length === 0 && this.journalTails.length === 0) return false;

    this.active = true;
    for (const src of sources) {
      this.tailLog(src);
    }

    // Periodic analysis
    setInterval(() => this.analyzeBuffer(), 10_000);
    return true;
  }

  stop(): void {
    for (const t of this.timers.values()) clearInterval(t);
    this.timers.clear();
    for (const child of this.journalTails) {
      try { child.kill('SIGTERM'); } catch { /* already gone */ }
    }
    this.journalTails = [];
    this.active = false;
  }

  /** Follow one systemd unit's journal, feeding its lines to the same parser. */
  private tailJournalUnit(unit: string): void {
    try {
      const child = spawn('journalctl', ['-u', unit, '-f', '-n', '0', '--output=cat'], {
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      if (!child.stdout) return;
      const rl = createInterface({ input: child.stdout });
      rl.on('line', (line) => this.parseDnsLine(line));
      child.on('error', () => { /* journalctl missing or not permitted */ });
      this.journalTails.push(child);
    } catch {
      // No journalctl, or we cannot read that unit. Files still work.
    }
  }

  isActive(): boolean { return this.active; }

  private tailLog(path: string): void {
    try {
      this.positions.set(path, statSync(path).size);
    } catch {
      this.positions.set(path, 0);
    }

    const timer = setInterval(() => this.pollLog(path), 2000);
    this.timers.set(path, timer);
  }

  private pollLog(path: string): void {
    let stat;
    try { stat = statSync(path); } catch { return; }
    const prev = this.positions.get(path) ?? 0;

    if (stat.size < prev) { this.positions.set(path, 0); return; }
    if (stat.size === prev) return;

    const stream = createReadStream(path, { start: prev, encoding: 'utf-8' });
    stream.on('error', () => this.positions.set(path, stat.size));
    const rl = createInterface({ input: stream });
    rl.on('line', (line) => this.parseDnsLine(line));
    rl.on('close', () => this.positions.set(path, stat.size));
  }

  private parseDnsLine(line: string): void {
    // Our own resolver (moshpit-dns), which logs every query it answers:
    //   [dns] udp 127.0.0.1 app.moshcode.sh 28 forwarded 11ms
    //   [dns] udp 10.0.0.5 shop.moshpit 1 registry 4ms
    // proto, client, name, numeric qtype, action, latency. Without this the
    // box's only DNS source was invisible to the DNS monitor: the lines went
    // to the journal watcher instead, which has no idea they are DNS and
    // reported thousands of them as unlabelled INFO.
    const moshpit = line.match(
      /\[dns\]\s+(?:udp|tcp|doh)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\w+)/i,
    );
    if (moshpit) {
      this.domainBuffer.push({
        type: qtypeName(Number.parseInt(moshpit[3], 10)),
        domain: moshpit[2],
        source_ip: moshpit[1],
        timestamp: Date.now(),
      });
      return;
    }

    // systemd-resolved pattern: "query[TXT] suspicious.domain.com from 192.168.1.1"
    const resolvedMatch = line.match(/query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/i);
    if (resolvedMatch) {
      this.domainBuffer.push({
        type: resolvedMatch[1],
        domain: resolvedMatch[2],
        source_ip: resolvedMatch[3],
        timestamp: Date.now(),
      });
      return;
    }

    // dnsmasq pattern: "query[TXT] suspicious.domain.com from 192.168.1.1"
    const dnsmasqMatch = line.match(/query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/i);
    if (dnsmasqMatch) {
      this.domainBuffer.push({
        type: dnsmasqMatch[1],
        domain: dnsmasqMatch[2],
        source_ip: dnsmasqMatch[3],
        timestamp: Date.now(),
      });
      return;
    }

    // Generic DNS query log pattern
    const genericMatch = line.match(/(?:query|lookup|resolve)[:\s]+(\S+)/i);
    if (genericMatch) {
      const typeMatch = line.match(/type[:\s]+(\w+)/i);
      this.domainBuffer.push({
        type: typeMatch?.[1] || 'A',
        domain: genericMatch[1],
        timestamp: Date.now(),
      });
    }
  }

  private analyzeBuffer(): void {
    const now = Date.now();
    const cutoff = now - this.txtWindowMs;

    // Prune old entries
    this.domainBuffer = this.domainBuffer.filter(q => q.timestamp > cutoff);

    this.detectTunneling();
    this.detectDga();
  }

  private detectTunneling(): void {
    // Check for high TXT query volume from single source
    const txtBySource = new Map<string, number>();
    const longLabelDomains: string[] = [];

    for (const q of this.domainBuffer) {
      if (q.type === 'TXT') {
        const key = q.source_ip || 'unknown';
        txtBySource.set(key, (txtBySource.get(key) || 0) + 1);
      }

      // DNS tunneling uses abnormally long subdomain labels
      const labels = q.domain.split('.');
      const maxLabel = Math.max(...labels.map(l => l.length));
      if (maxLabel > 50) {
        longLabelDomains.push(q.domain);
      }
    }

    for (const [source, count] of txtBySource) {
      if (count >= this.txtRateThreshold) {
        this.emitEvent(
          'high',
          `DNS tunneling indicators: ${count} TXT queries from ${source} in ${this.txtWindowMs / 1000}s`,
          source !== 'unknown' ? source : undefined,
          { txt_query_count: count, type: 'tunneling' },
        );
      }
    }

    if (longLabelDomains.length >= 5) {
      this.emitEvent(
        'high',
        `DNS tunneling: ${longLabelDomains.length} queries with abnormally long labels detected`,
        undefined,
        { domains: longLabelDomains.slice(0, 5), type: 'tunneling-labels' },
      );
    }
  }

  private detectDga(): void {
    // Find domains with high entropy (DGA-like)
    const highEntropyDomains: string[] = [];

    for (const q of this.domainBuffer) {
      const domain = q.domain.toLowerCase();
      // Extract the second-level domain
      const parts = domain.split('.');
      if (parts.length < 2) continue;
      const sld = parts[parts.length - 2];

      if (sld.length >= 8 && this.shannonEntropy(sld) >= this.entropyThreshold) {
        highEntropyDomains.push(domain);
      }
    }

    // Deduplicate
    const unique = [...new Set(highEntropyDomains)];
    if (unique.length >= this.dgaBurstThreshold) {
      this.emitEvent(
        'critical',
        `DGA-like domain burst: ${unique.length} unique high-entropy domains detected`,
        undefined,
        { sample_domains: unique.slice(0, 10), type: 'dga', unique_count: unique.length },
      );
    }
  }

  private shannonEntropy(str: string): number {
    const freq = new Map<string, number>();
    for (const ch of str) {
      freq.set(ch, (freq.get(ch) || 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  private emitEvent(severity: EventSeverity, message: string, sourceIp?: string, details?: Record<string, unknown>): void {
    const event: ThreatEvent = {
      timestamp: new Date(),
      module: 'dns-monitor',
      category: 'network',
      severity,
      message,
      source_ip: sourceIp,
      details,
    };
    try { insertEvent(event); } catch { /* db optional */ }
    this.bus.publish(event);
  }
}
