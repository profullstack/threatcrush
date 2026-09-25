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
    }
  }
}
