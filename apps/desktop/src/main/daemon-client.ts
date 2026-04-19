import { createConnection, Socket } from 'node:net'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'

export interface DaemonPaths {
  socket: string
  pidFile: string
  mode: 'system' | 'user'
}

export function resolveDaemonPaths(): DaemonPaths {
  // System paths (root / linux)
  if (process.platform === 'linux') {
    const systemSocket = '/var/run/threatcrush/threatcrushd.sock'
    if (existsSync(systemSocket)) {
      return {
        socket: systemSocket,
        pidFile: '/var/run/threatcrush/threatcrushd.pid',
        mode: 'system',
      }
    }
  }

  // User paths (fallback everywhere)
  const userRun = join(homedir(), '.threatcrush', 'run')
  return {
    socket: join(userRun, 'threatcrushd.sock'),
    pidFile: join(userRun, 'threatcrushd.pid'),
    mode: 'user',
  }
}

type Pending = {
  resolve: (value: unknown) => void
  reject: (err: Error) => void
}

export class DaemonClient {
  private socket: Socket | null = null
  private buffer = ''
  private nextId = 1
  private pending = new Map<number, Pending>()
  private listeners = new Set<(frame: Record<string, unknown>) => void>()
  private connected = false

  constructor(private socketPath: string) {}

  isConnected(): boolean {
    return this.connected
  }

  async connect(timeoutMs = 2000): Promise<void> {
    if (!existsSync(this.socketPath)) {
      throw new Error(`threatcrushd socket not found at ${this.socketPath}`)
    }

    return new Promise((resolve, reject) => {
      const sock = createConnection(this.socketPath)
      const timer = setTimeout(() => {
        sock.destroy()
        reject(new Error('ipc connect timeout'))
      }, timeoutMs)

      sock.once('connect', () => {
        clearTimeout(timer)
        this.socket = sock
        this.connected = true
        sock.setEncoding('utf-8')
        sock.on('data', (chunk) => this.onData(chunk.toString()))
        sock.on('close', () => this.onClose())
        sock.on('error', () => this.onClose())
        resolve()
      })

      sock.once('error', (err) => {
        clearTimeout(timer)
        reject(err)
      })
    })
  }

  close(): void {
    this.socket?.destroy()
    this.socket = null
    this.connected = false
  }

  onPush(cb: (frame: Record<string, unknown>) => void): () => void {
    this.listeners.add(cb)
    return () => this.listeners.delete(cb)
  }

  async request<T = unknown>(method: string, params?: Record<string, unknown>): Promise<T> {
    if (!this.socket) throw new Error('not connected')
    const id = this.nextId++
    const frame = params ? { id, method, params } : { id, method }
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject })
      this.socket!.write(JSON.stringify(frame) + '\n', (err) => {
        if (err) {
          this.pending.delete(id)
          reject(err)
        }
      })
    })
  }

  private onData(chunk: string): void {
    this.buffer += chunk
    let idx: number
    while ((idx = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 1)
      if (!line.trim()) continue
      try {
        const msg = JSON.parse(line) as Record<string, unknown>
        if ('push' in msg) {
          for (const cb of this.listeners) cb(msg)
          continue
        }
        const id = typeof msg.id === 'number' ? msg.id : -1
        const pending = this.pending.get(id)
        if (!pending) continue
        this.pending.delete(id)
        if (msg.ok === true) pending.resolve(msg.result)
        else pending.reject(new Error((msg.error as string) || 'ipc error'))
      } catch {
        // skip bad frame
      }
    }
  }

  private onClose(): void {
    this.connected = false
    for (const { reject } of this.pending.values()) {
      reject(new Error('daemon connection closed'))
    }
    this.pending.clear()
    this.socket = null
  }
}
