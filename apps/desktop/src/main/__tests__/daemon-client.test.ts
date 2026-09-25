import { afterEach, describe, expect, it, vi } from 'vitest'
import { createServer, type Server, type Socket } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DaemonClient } from '../daemon-client'

/**
 * The desktop app hung on a daemon that never answered: a daemon older than
 * #229 stays silent on a method it does not know, and the client waited on
 * that reply forever. Every request must now settle.
 */
describe('desktop daemon client never waits forever', () => {
  let fake: Server | null = null
  let client: DaemonClient | null = null
  let dir = ''

  afterEach(async () => {
    vi.useRealTimers()
    client?.close()
    client = null
    await new Promise<void>((r) => (fake ? fake.close(() => r()) : r()))
    fake = null
    rmSync(dir, { recursive: true, force: true })
  })

  /** A socket server that hands each connection's first frame to `onFrame`. */
  async function fakeDaemon(onFrame: (sock: Socket, frame: { id: number; method: string }) => void): Promise<DaemonClient> {
    dir = mkdtempSync(join(tmpdir(), 'tc-desktop-ipc-'))
    const path = join(dir, 'd.sock')
    fake = createServer((sock) =>
      sock.once('data', (chunk) => onFrame(sock, JSON.parse(chunk.toString().split('\n')[0])))
    )
    await new Promise<void>((r) => fake!.listen(path, r))
    client = new DaemonClient(path)
    await client.connect()
    return client
  }

  it('times out a request the daemon never answers, as an older daemon does', async () => {
    let received!: () => void
    const frameArrived = new Promise<void>((r) => { received = r })
    const c = await fakeDaemon(() => received())
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const settled = c.request('top_sources').then(() => null, (e: Error) => e)
    await frameArrived
    await vi.advanceTimersByTimeAsync(60_000)
    const err = await settled
    expect(err?.message).toMatch(/did not answer "top_sources"/)
  })

  it('tells the operator to update a daemon that does not know the method', async () => {
    const c = await fakeDaemon((sock, frame) =>
      sock.write(JSON.stringify({ id: frame.id, ok: false, error: `unknown method: ${frame.method}` }) + '\n')
    )
    const err = await c.request('top_sources').then(() => null, (e: Error) => e)
    expect(err?.message).toMatch(/older than this app/)
    expect(err?.message).toContain('top_sources')
    expect(err?.message).toMatch(/update/)
  })

  it('passes other daemon errors through unchanged', async () => {
    const c = await fakeDaemon((sock, frame) =>
      sock.write(JSON.stringify({ id: frame.id, ok: false, error: 'subscribe requires params' }) + '\n')
    )
    await expect(c.request('subscribe')).rejects.toThrow(/^subscribe requires params$/)
  })

  it('rejects a pending request when the daemon closes mid-request', async () => {
    const c = await fakeDaemon((sock) => sock.destroy())
    await expect(c.request('status')).rejects.toThrow(/closed/)
    expect(c.isConnected()).toBe(false)
  })

  it('an answered request does not later reject on the timeout', async () => {
    const c = await fakeDaemon((sock, frame) =>
      sock.write(JSON.stringify({ id: frame.id, ok: true, result: 'pong' }) + '\n')
    )
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    await expect(c.request('ping')).resolves.toBe('pong')
    expect(vi.getTimerCount()).toBe(0)
  })
})
