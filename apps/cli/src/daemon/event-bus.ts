import { EventEmitter } from 'node:events';
import type { ThreatEvent } from '../types/events.js';

export interface DaemonEvents {
  event: (event: ThreatEvent) => void;
  alert: (event: ThreatEvent) => void;
  module: (info: { name: string; status: string; detail?: string }) => void;
  /** Every sshd log line that names a remote address, accepted or not (Tor exit checks). */
  sshd: (line: SshdLine) => void;
}

export interface SshdLine {
  timestamp: Date;
  /** sshd's message, without the syslog prefix. */
  message: string;
  /** The remote peer the line is about. */
  ip: string;
  /** The raw line as logged (auth.log line or journal MESSAGE). */
  raw: string;
}

export class EventBus extends EventEmitter {
  publish(event: ThreatEvent): void {
    this.emit('event', event);
    if (event.severity === 'high' || event.severity === 'critical') {
      this.emit('alert', event);
    }
  }

  /** A raw sshd line with a peer address; not an event, nothing is stored or uploaded. */
  sshdLine(line: SshdLine): void {
    this.emit('sshd', line);
  }

  announceModule(name: string, status: string, detail?: string): void {
    this.emit('module', { name, status, detail });
  }
}

export const bus = new EventBus();
bus.setMaxListeners(50);
