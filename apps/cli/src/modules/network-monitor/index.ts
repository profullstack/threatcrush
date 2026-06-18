/**
 * Network Monitor Module (PRD 04)
 *
 * Observes TCP/UDP connections via conntrack / ss / /proc/net.
 * Detects port scans and SYN-flood-style patterns.
 * Emits detections through the event bus for the rule engine.
 */

import { execSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import type { EventBus } from '../../daemon/event-bus.js';
import { insertEvent } from '../../core/state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

interface ConnectionRecord {
  source_ip: string;
  dest_port: number;
  timestamp: number;
}

interface ScanTracker {
  ports: Set<number>;
  firstSeen: number;
  lastSeen: number;
  count: number;
}

export class NetworkMonitor {
  private active = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private scanTrackers = new Map<string, ScanTracker>();
  private halfOpenTrackers = new Map<string, { count: number; firstSeen: number }>();
  private lastConnections = new Set<string>();

  // Config
  private pollIntervalMs = 5000;
  private portScanThreshold = 10;  // unique ports in window
  private portScanWindowMs = 30_000;
  private synFloodThreshold = 50;  // half-open connections
  private synFloodWindowMs = 10_000;

  constructor(private bus: EventBus) {}

  start(): boolean {
    if (!this.hasConntrackOrSs()) {
      return false;
    }
    this.active = true;
    this.pollTimer = setInterval(() => this.poll(), this.pollIntervalMs);
    return true;
  }

  stop(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = null;
    this.active = false;
  }

  isActive(): boolean { return this.active; }

  private hasConntrackOrSs(): boolean {
    const ss = spawnSync('ss', ['--version'], { stdio: 'pipe' });
    if (ss.status === 0) return true;
    // Try /proc/net/tcp
    return existsSync('/proc/net/tcp');
  }

  private poll(): void {
    try {
      const connections = this.getConnections();
      this.analyzePortScans(connections);
      this.analyzeSynFlood(connections);
      this.cleanupTrackers();
    } catch {
      // Graceful degradation
    }
  }

  private getConnections(): ConnectionRecord[] {
    const records: ConnectionRecord[] = [];
    const now = Date.now();

    try {
      // Try conntrack first
      const ct = spawnSync('conntrack', ['-L', '-p', 'tcp', '-o', 'extended'], {
        encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 3000,
      });
      if (ct.status === 0 && ct.stdout) {
        for (const line of ct.stdout.split('\n')) {
          const srcMatch = line.match(/src=(\d+\.\d+\.\d+\.\d+)/);
          const dportMatch = line.match(/dport=(\d+)/);
          if (srcMatch && dportMatch) {
            records.push({ source_ip: srcMatch[1], dest_port: parseInt(dportMatch[1]), timestamp: now });
          }
        }
        if (records.length > 0) return records;
      }
    } catch { /* fallthrough */ }

    try {
      // Fallback to ss
      const ss = spawnSync('ss', ['-tnp', '-H'], {
        encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 3000,
      });
      if (ss.status === 0 && ss.stdout) {
        for (const line of ss.stdout.split('\n')) {
          // ss output: State  Recv-Q  Send-Q  Local:Port  Peer:Port  Process
          const parts = line.trim().split(/\s+/);
          if (parts.length < 5) continue;
          const peerParts = parts[4].split(':');
          const localParts = parts[3].split(':');
          if (peerParts.length >= 2 && localParts.length >= 2) {
            const sourceIp = peerParts.slice(0, -1).join(':');
            const destPort = parseInt(localParts[localParts.length - 1]);
            if (sourceIp && !isNaN(destPort) && !this.isLocalIp(sourceIp)) {
              records.push({ source_ip: sourceIp, dest_port: destPort, timestamp: now });
            }
          }
        }
      }
    } catch { /* fallthrough */ }

    return records;
  }

  private analyzePortScans(connections: ConnectionRecord[]): void {
    const now = Date.now();

    for (const conn of connections) {
      const key = conn.source_ip;
      let tracker = this.scanTrackers.get(key);

      if (!tracker) {
        tracker = { ports: new Set(), firstSeen: now, lastSeen: now, count: 0 };
        this.scanTrackers.set(key, tracker);
      }

      tracker.ports.add(conn.dest_port);
      tracker.lastSeen = now;
      tracker.count++;

      // Check threshold within window
      if (tracker.ports.size >= this.portScanThreshold &&
          (now - tracker.firstSeen) <= this.portScanWindowMs) {
        this.emitEvent(
          'high',
          `Port scan detected: ${conn.source_ip} probed ${tracker.ports.size} ports in ${Math.round((now - tracker.firstSeen) / 1000)}s`,
          conn.source_ip,
          { ports_scanned: tracker.ports.size, window_seconds: Math.round((now - tracker.firstSeen) / 1000) },
        );
        // Reset tracker after alert
        this.scanTrackers.delete(key);
      }
    }
  }

  private analyzeSynFlood(connections: ConnectionRecord[]): void {
    // Count SYN_RECV (half-open) states via ss
    try {
      const ss = spawnSync('ss', ['-tn', 'state', 'syn-recv', '-H'], {
        encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 3000,
      });
      if (ss.status !== 0 || !ss.stdout) return;

      const now = Date.now();
      const perSource = new Map<string, number>();

      for (const line of ss.stdout.split('\n')) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) continue;
        const peer = parts[4].split(':');
        const ip = peer.slice(0, -1).join(':');
        if (ip) perSource.set(ip, (perSource.get(ip) || 0) + 1);
      }

      for (const [ip, count] of perSource) {
        if (count >= this.synFloodThreshold) {
          this.emitEvent(
            'critical',
            `SYN flood indicators: ${count} half-open connections from ${ip}`,
            ip,
            { half_open_count: count },
          );
        }
      }
    } catch { /* graceful */ }
  }

  private emitEvent(severity: EventSeverity, message: string, sourceIp?: string, details?: Record<string, unknown>): void {
    const event: ThreatEvent = {
      timestamp: new Date(),
      module: 'network-monitor',
      category: 'network',
      severity,
      message,
      source_ip: sourceIp,
      details,
    };
    try { insertEvent(event); } catch { /* db optional */ }
    this.bus.publish(event);
  }

  private cleanupTrackers(): void {
    const now = Date.now();
    for (const [key, tracker] of this.scanTrackers) {
      if (now - tracker.lastSeen > this.portScanWindowMs * 2) {
        this.scanTrackers.delete(key);
      }
    }
  }

  private isLocalIp(ip: string): boolean {
    return ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip.startsWith('::ffff:127.');
  }
}
