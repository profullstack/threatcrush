import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

type DaemonStatus = {
  running: boolean
  pid?: number
  uptimeSeconds?: number
  modules?: unknown[]
  socket?: string
  error?: string
}

type ConnectResult = {
  connected: boolean
  pid?: number
  version?: string
  socket?: string
  error?: string
}

type RequestResult<T = unknown> = { ok: true; result: T } | { ok: false; error: string }

const api = {
  getVersion: (): string => '0.1.16',

  /**
   * Connect to a locally-running threatcrushd over its unix socket.
   * Pass an absolute socket path to override auto-detection.
   * Legacy (host, port) call signature is accepted but ignored.
   */
  connectDaemon: (arg1?: string | number, arg2?: number): Promise<ConnectResult> => {
    return ipcRenderer.invoke('connect-daemon', arg1, arg2)
  },

  disconnectDaemon: (): Promise<{ disconnected: boolean }> => {
    return ipcRenderer.invoke('disconnect-daemon')
  },

  daemonStatus: (): Promise<DaemonStatus> => {
    return ipcRenderer.invoke('daemon-status')
  },

  /** Low-level JSON-RPC passthrough to the daemon. */
  daemonRequest: <T = unknown>(
    method: string,
    params?: Record<string, unknown>,
  ): Promise<RequestResult<T>> => {
    return ipcRenderer.invoke('daemon-request', method, params)
  },

  /** Subscribe to pushed frames from the daemon (events, module status, etc.) */
  onEvent: (callback: (event: unknown) => void): (() => void) => {
    const handler = (_: unknown, data: unknown): void => callback(data)
    ipcRenderer.on('threat-event', handler)
    return () => ipcRenderer.removeListener('threat-event', handler)
  },
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore
  window.electron = electronAPI
  // @ts-ignore
  window.api = api
}
