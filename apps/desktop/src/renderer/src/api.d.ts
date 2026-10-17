export type ConnectResult = {
  connected: boolean
  pid?: number
  version?: string
  socket?: string
  error?: string
}

declare global {
  interface Window {
    /** Exposed by src/preload/index.ts; absent when the renderer runs outside Electron. */
    api?: {
      connectDaemon(): Promise<ConnectResult>
      daemonStatus(): Promise<{ running: boolean; pid?: number; error?: string }>
      daemonRequest<T = unknown>(
        method: string,
        params?: Record<string, unknown>,
      ): Promise<{ ok: true; result: T } | { ok: false; error: string }>
      /** Pushed frames: { type: 'event' | 'module' | 'connected', data }. */
      onEvent(callback: (frame: unknown) => void): () => void
    }
  }
}
