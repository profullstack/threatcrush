import { createConnection, Socket } from 'node:net';
import { existsSync } from 'node:fs';
import { PATHS } from '../daemon/paths.js';
import type {
  IpcRequest,
  IpcResponse,
  IpcPush,
  DaemonStatusReply,
} from '../daemon/ipc-protocol.js';
import type { ThreatEvent } from '../types/events.js';

export interface IpcClientOptions {
  socketPath?: string;
  onEvent?: (event: ThreatEvent) => void;
  onModule?: (info: { name: string; status: string; detail?: string }) => void;
}

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

export class IpcClient {
  private socket: Socket | null = null;
  private buffer = '';
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private socketPath: string;

  constructor(private opts: IpcClientOptions = {}) {
    this.socketPath = opts.socketPath || PATHS.socket;
  }

  static isDaemonRunning(socketPath = PATHS.socket): boolean {
    return existsSync(socketPath);
  }

  async connect(timeoutMs = 2000): Promise<void> {
    if (!existsSync(this.socketPath)) {
      throw new Error(`threatcrushd socket not found at ${this.socketPath}`);
    }

    return new Promise((resolve, reject) => {
      const sock = createConnection(this.socketPath);
      const timer = setTimeout(() => {
        sock.destroy();
        reject(new Error('ipc connect timeout'));
      }, timeoutMs);

      sock.once('connect', () => {
        clearTimeout(timer);
        this.socket = sock;
        sock.setEncoding('utf-8');
        sock.on('data', (chunk) => this.onData(chunk.toString()));
        sock.on('close', () => this.onClose());
        sock.on('error', () => this.onClose());
        resolve();
      });

      sock.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  close(): void {
    this.socket?.destroy();
    this.socket = null;
  }

  async request<T>(method: IpcRequest['method'], params?: Record<string, unknown>): Promise<T> {
    if (!this.socket) throw new Error('not connected');
    const id = this.nextId++;
    const frame: IpcRequest = params
      ? ({ id, method, params } as IpcRequest)
      : ({ id, method } as IpcRequest);

    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      this.socket!.write(JSON.stringify(frame) + '\n', (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  async ping(): Promise<'pong'> {
    return this.request<'pong'>('ping');
  }

  async status(): Promise<DaemonStatusReply> {
    return this.request<DaemonStatusReply>('status');
  }

  async recentEvents(limit = 50): Promise<ThreatEvent[]> {
    return this.request<ThreatEvent[]>('recent_events', { limit });
  }

  async topSources(limit = 10): Promise<Array<{ ip: string; count: number }>> {
    return this.request('top_sources', { limit });
  }

  async counters() {
    return this.request<{ total: number; threats: number; last24h: number; threats24h: number }>('counters');
  }

  async subscribe(channels: Array<'event' | 'module'>): Promise<void> {
    await this.request('subscribe', { channels });
  }

  async shutdown(): Promise<void> {
    await this.request('shutdown');
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let idx;
    while ((idx = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line) as IpcResponse | IpcPush;
        if ('push' in msg) {
          if (msg.push === 'event' && this.opts.onEvent) {
            const raw = msg.payload as ThreatEvent & { timestamp: string | Date };
            this.opts.onEvent({ ...raw, timestamp: new Date(raw.timestamp) });
          } else if (msg.push === 'module' && this.opts.onModule) {
            this.opts.onModule(msg.payload as { name: string; status: string; detail?: string });
          }
          continue;
        }
        const pending = this.pending.get(msg.id);
        if (!pending) continue;
        this.pending.delete(msg.id);
        if (msg.ok) pending.resolve(msg.result);
        else pending.reject(new Error(msg.error || 'ipc error'));
      } catch {
        // skip malformed frame
      }
    }
  }

  private onClose(): void {
    for (const { reject } of this.pending.values()) {
      reject(new Error('daemon connection closed'));
    }
    this.pending.clear();
    this.socket = null;
  }
}
