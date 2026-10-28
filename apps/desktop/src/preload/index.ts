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

  /** threatcrush.com account + tracked findings (main process holds the session). */
  cloud: {
    status: () => ipcRenderer.invoke('cloud-status'),
    login: () => ipcRenderer.invoke('cloud-login'),
    waitForLogin: () => ipcRenderer.invoke('cloud-login-wait'),
    cancelLogin: () => ipcRenderer.invoke('cloud-login-cancel'),
    logout: () => ipcRenderer.invoke('cloud-logout'),
    orgs: () => ipcRenderer.invoke('cloud-orgs'),
    useOrg: (id: string, slug: string) => ipcRenderer.invoke('cloud-use-org', id, slug),
    findings: (q?: { status?: string; severity?: string; source?: string }) => ipcRenderer.invoke('cloud-findings', q),
    finding: (id: string) => ipcRenderer.invoke('cloud-finding', id),
    triage: (ids: string[], status: string | null, note?: string) => ipcRenderer.invoke('cloud-triage', ids, status, note),
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
