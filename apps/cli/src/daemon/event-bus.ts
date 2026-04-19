import { EventEmitter } from 'node:events';
import type { ThreatEvent } from '../types/events.js';

export interface DaemonEvents {
  event: (event: ThreatEvent) => void;
  alert: (event: ThreatEvent) => void;
  module: (info: { name: string; status: string; detail?: string }) => void;
}

export class EventBus extends EventEmitter {
  publish(event: ThreatEvent): void {
    this.emit('event', event);
    if (event.severity === 'high' || event.severity === 'critical') {
      this.emit('alert', event);
    }
  }

  announceModule(name: string, status: string, detail?: string): void {
    this.emit('module', { name, status, detail });
  }
}

export const bus = new EventBus();
bus.setMaxListeners(50);
