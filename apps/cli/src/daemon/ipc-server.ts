import { createServer, Server, Socket } from 'node:net';
import { existsSync, unlinkSync } from 'node:fs';
import type { ThreatEvent } from '../types/events.js';
import { PATHS } from './paths.js';
import { issueControlToken, tokensMatch } from './control-token.js';
import { bus } from './event-bus.js';
import { getRecentEvents, getTopSources, getEventCount, getThreatCount, isStateDbAvailable } from '../core/state.js';
import type {
  IpcRequest,
  IpcResponse,
  IpcPush,
  DaemonStatusReply,
  BlocklistReply,
} from './ipc-protocol.js';
import type { ModuleHost } from './module-host.js';
import type { RemediationManager } from './firewall/remediation.js';
import { parseDuration } from './firewall/backoff.js';

interface ClientState {
  id: number;
  socket: Socket;
  buffer: string;
  subscriptions: Set<'event' | 'module' | 'firewall'>;
}

export class IpcServer {
  private server: Server | null = null;
  private clients = new Map<number, ClientState>();
  private nextClientId = 1;
  private startedAt = new Date();
  private counters = { events: 0, threats: 0, alerts: 0 };
  private controlToken = '';

  constructor(
    private version: string,
    private moduleHost: ModuleHost,
    private remediation?: RemediationManager,
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
    // Rotated per start, so a token leaked from a previous run is useless.
    this.controlToken = issueControlToken();

    if (existsSync(PATHS.socket)) {
      try { unlinkSync(PATHS.socket); } catch {}
    }
    return new Promise((resolve, reject) => {
      this.server = createServer((sock) => this.handleClient(sock));
      this.server.on('error', reject);
      this.server.listen(PATHS.socket, () => {
        const nodeFs = require('node:fs') as typeof import('node:fs');
        try { nodeFs.chmodSync(PATHS.socket, 0o660); } catch {}
        // When the daemon runs as root (system mode under systemd), regroup
        // the socket to `adm` so users in that group can talk to the daemon
        // without sudo. We use this group because it's the same one that
        // already governs read access to /var/log/{auth,syslog,nginx} — the
        // intent is "people who can already inspect logs can talk to the
        // agent that watches them."
        const isRoot = process.platform === 'linux'
          && typeof process.getuid === 'function'
          && process.getuid() === 0;
        if (isRoot) {
          try {
            const { gid } = nodeFs.statSync('/var/log/auth.log');
            nodeFs.chownSync(PATHS.socket, 0, gid);
          } catch {
            // adm group not present, or /var/log/auth.log missing — leave as root:root
          }
        }
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
    let frame: unknown;
    try {
      frame = JSON.parse(line);
    } catch {
      return this.send(client, { id: 0, ok: false, error: 'invalid json' });
    }

    // Every frame gets an answer. A client waits on the id it sent, so an
    // unanswered frame is a hung CLI; when the id itself is unusable, fall back
    // to 0 as for invalid JSON.
    const { id, method } = (frame ?? {}) as { id?: unknown; method?: unknown };
    if (typeof id !== 'number' || typeof method !== 'string') {
      return this.send(client, {
        id: typeof id === 'number' ? id : 0,
        ok: false,
        error: 'invalid request: expected {"id": number, "method": string}',
      });
    }

    try {
      await this.dispatch(client, frame as IpcRequest);
    } catch (err) {
      // e.g. a known method with missing params. Answer on the request's id so
      // the client gets the error instead of waiting for a reply.
      this.send(client, { id, ok: false, error: String((err as Error)?.message || err) });
    }
  }

  private async dispatch(client: ClientState, req: IpcRequest): Promise<void> {
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
          stateDb: isStateDbAvailable(),
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

      case 'blocklist': {
        if (!this.remediation) {
          return this.send(client, { id: req.id, ok: false, error: 'remediation is not running' });
        }
        const status = this.remediation.status();
        const reply: BlocklistReply = {
          entries: this.remediation.getBlocklist().map((entry) => ({
            ip: entry.ip,
            reason: entry.reason,
            blocked_at: entry.blocked_at,
            expires_at: entry.expires_at,
            strikes: entry.strikes,
            source: entry.source,
            dry_run: entry.dry_run,
          })),
          protected: this.remediation.getProtected(),
          enabled: status.enabled,
          dry_run: status.dry_run,
          backend: status.backend,
          min_severity: status.min_severity,
          warning: status.warning,
        };
        return this.send(client, { id: req.id, ok: true, result: reply });
      }

      case 'block': {
        // No token here, deliberately. The privilege that matters belongs to
        // the *daemon*, which is what writes the firewall rule; the client only
        // asks. Requiring the root-only token meant an operator watching the
        // dashboard as themselves could not ban anything a root daemon was
        // perfectly able to block.
        //
        // The gate is the socket itself: 0660 root:adm, so the OS has already
        // decided who may connect, and `adm` is the group that can read the
        // logs these decisions are made from. `shutdown` keeps the token,
        // because a ban is reversible and expires within a day while stopping
        // the daemon disables protection entirely.
        if (!this.remediation) {
          return this.send(client, { id: req.id, ok: false, error: 'remediation is not running' });
        }
        const ttl = parseDuration(req.params?.ttl) ?? undefined;
        const result = await this.remediation.ban(req.params.ip, req.params.reason || 'banned by operator', {
          ttlSeconds: ttl,
          source: 'manual',
        });
        if (!result.ok) {
          return this.send(client, { id: req.id, ok: false, error: result.error || 'ban failed' });
        }
        return this.send(client, { id: req.id, ok: true, result: result.entry });
      }

      case 'unblock': {
        // Same reasoning as `block`. Lifting a ban must never be harder than
        // placing one: an operator who can see a wrong ban has to be able to
        // undo it immediately, which is the whole point of PRD 0010 R12.
        if (!this.remediation) {
          return this.send(client, { id: req.id, ok: false, error: 'remediation is not running' });
        }
        const result = await this.remediation.unban(req.params.ip, { forget: req.params.forget !== false });
        if (!result.ok) {
          return this.send(client, { id: req.id, ok: false, error: result.error || 'unban failed' });
        }
        return this.send(client, { id: req.id, ok: true, result: { ip: req.params.ip } });
      }

      case 'shutdown':
        // TC-33: reads are open to the adm group by design; stopping the
        // security daemon is not. Requires the root-only control token.
        if (!tokensMatch(this.controlToken, (req as { params?: { token?: unknown } }).params?.token)) {
          return this.send(client, {
            id: req.id,
            ok: false,
            error: 'shutdown requires the daemon control token (run as root, or use systemctl)',
          });
        }
        this.send(client, { id: req.id, ok: true, result: 'shutting down' });
        setTimeout(() => process.emit('SIGTERM' as NodeJS.Signals), 50);
        return;

      default: {
        // A newer CLI talking to an older daemon. Staying silent here left
        // the client hanging; name the method so the CLI can say what is wrong.
        const unknown = req as { id: number; method: string };
        return this.send(client, { id: unknown.id, ok: false, error: `unknown method: ${unknown.method}` });
      }
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
