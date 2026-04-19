import { createServer, Server, Socket } from 'node:net';
import { existsSync, unlinkSync } from 'node:fs';
import type { ThreatEvent } from '../types/events.js';
import { PATHS } from './paths.js';
import { bus } from './event-bus.js';
import { getRecentEvents, getTopSources, getEventCount, getThreatCount } from '../core/state.js';
import type {
  IpcRequest,
  IpcResponse,
  IpcPush,
  DaemonStatusReply,
} from './ipc-protocol.js';
import type { ModuleHost } from './module-host.js';

interface ClientState {
  id: number;
  socket: Socket;
  buffer: string;
  subscriptions: Set<'event' | 'module'>;
}

export class IpcServer {
  private server: Server | null = null;
  private clients = new Map<number, ClientState>();
  private nextClientId = 1;
  private startedAt = new Date();
  private counters = { events: 0, threats: 0, alerts: 0 };

  constructor(
    private version: string,
    private moduleHost: ModuleHost,
  ) {
    bus.on('event', (event: ThreatEvent) => {
      this.counters.events++;
      if (event.severity === 'medium' || event.severity === 'high' || event.severity === 'critical') {
        this.counters.threats++;
      }
      this.broadcast({ push: 'event', payload: event }, 'event');
    });
    bus.on('alert', () => {
      this.counters.alerts++;
    });
    bus.on('module', (info) => {
      this.broadcast({ push: 'module', payload: info }, 'module');
    });
  }

  async start(): Promise<void> {
    if (existsSync(PATHS.socket)) {
      try { unlinkSync(PATHS.socket); } catch {}
    }
    return new Promise((resolve, reject) => {
      this.server = createServer((sock) => this.handleClient(sock));
      this.server.on('error', reject);
      this.server.listen(PATHS.socket, () => {
        try { require('node:fs').chmodSync(PATHS.socket, 0o660); } catch {}
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    for (const c of this.clients.values()) {
      try { c.socket.destroy(); } catch {}
    }
    this.clients.clear();
    return new Promise((resolve) => {
      if (!this.server) {
        try { if (existsSync(PATHS.socket)) unlinkSync(PATHS.socket); } catch {}
        return resolve();
      }
      this.server.close(() => {
        try { if (existsSync(PATHS.socket)) unlinkSync(PATHS.socket); } catch {}
        resolve();
      });
    });
  }

  private handleClient(socket: Socket): void {
    const id = this.nextClientId++;
    const state: ClientState = { id, socket, buffer: '', subscriptions: new Set() };
    this.clients.set(id, state);

    socket.setEncoding('utf-8');
    socket.on('data', (chunk) => {
      state.buffer += chunk.toString();
      let idx;
      while ((idx = state.buffer.indexOf('\n')) >= 0) {
        const line = state.buffer.slice(0, idx);
        state.buffer = state.buffer.slice(idx + 1);
        if (!line.trim()) continue;
        this.handleLine(state, line).catch((err) => {
          this.send(state, { id: 0, ok: false, error: String(err?.message || err) });
        });
      }
    });

    socket.on('close', () => { this.clients.delete(id); });
    socket.on('error', () => { this.clients.delete(id); });
  }

  private async handleLine(client: ClientState, line: string): Promise<void> {
    let req: IpcRequest;
    try {
      req = JSON.parse(line) as IpcRequest;
    } catch {
      return this.send(client, { id: 0, ok: false, error: 'invalid json' });
    }

    switch (req.method) {
      case 'ping':
        return this.send(client, { id: req.id, ok: true, result: 'pong' });

      case 'status': {
        const status: DaemonStatusReply = {
          pid: process.pid,
          startedAt: this.startedAt.toISOString(),
          uptimeSeconds: Math.floor((Date.now() - this.startedAt.getTime()) / 1000),
          version: this.version,
          mode: PATHS.mode,
          paths: {
            config: PATHS.configFile,
            log: PATHS.logFile,
            state: PATHS.stateDb,
            socket: PATHS.socket,
          },
          modules: this.moduleHost.summary(),
          counters: { ...this.counters },
        };
        return this.send(client, { id: req.id, ok: true, result: status });
      }

      case 'recent_events': {
        const limit = req.params?.limit ?? 50;
        const events = getRecentEvents(limit);
        return this.send(client, { id: req.id, ok: true, result: events });
      }

      case 'top_sources': {
        const limit = req.params?.limit ?? 10;
        return this.send(client, { id: req.id, ok: true, result: getTopSources(limit) });
      }

      case 'counters': {
        return this.send(client, {
          id: req.id,
          ok: true,
          result: {
            total: getEventCount(),
            threats: getThreatCount(),
            last24h: getEventCount(new Date(Date.now() - 86400000)),
            threats24h: getThreatCount(new Date(Date.now() - 86400000)),
          },
        });
      }

      case 'module_list':
        return this.send(client, { id: req.id, ok: true, result: this.moduleHost.summary() });

      case 'subscribe':
        for (const ch of req.params.channels) client.subscriptions.add(ch);
        return this.send(client, { id: req.id, ok: true, result: { subscribed: [...client.subscriptions] } });

      case 'shutdown':
        this.send(client, { id: req.id, ok: true, result: 'shutting down' });
        setTimeout(() => process.emit('SIGTERM' as NodeJS.Signals), 50);
        return;
    }
  }

  private send(client: ClientState, msg: IpcResponse | IpcPush): void {
    try {
      client.socket.write(JSON.stringify(msg) + '\n');
    } catch {
      // client gone
    }
  }

  private broadcast(msg: IpcPush, channel: 'event' | 'module'): void {
    for (const client of this.clients.values()) {
      if (!client.subscriptions.has(channel)) continue;
      this.send(client, msg);
    }
  }
}
