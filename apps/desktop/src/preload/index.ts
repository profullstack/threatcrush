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
  getVersion: (): string => ipcRenderer.sendSync('app-version') as string,

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
    findings: (q?: { status?: string; severity?: string; source?: string; offset?: number }) => ipcRenderer.invoke('cloud-findings', q),
    finding: (id: string) => ipcRenderer.invoke('cloud-finding', id),
    servers: () => ipcRenderer.invoke('cloud-servers'),
    attackMap: (windowMinutes?: number) => ipcRenderer.invoke('cloud-attack-map', windowMinutes),
    detections: (q?: { server_id?: string; since?: string; limit?: number }) => ipcRenderer.invoke('cloud-detections', q),
    triage: (ids: string[], status: string | null, note?: string) => ipcRenderer.invoke('cloud-triage', ids, status, note),
  },

  /** CrushAV: free antivirus. The engine runs in the main process. */
  av: {
    status: () => ipcRenderer.invoke('av-status'),
    pick: () => ipcRenderer.invoke('av-pick'),
    scan: (mode: 'quick' | 'full' | 'paths', paths?: string[], offline?: boolean) => ipcRenderer.invoke('av-scan', mode, paths, offline),
    cancel: () => ipcRenderer.invoke('av-cancel'),
    quarantine: (path: string) => ipcRenderer.invoke('av-quarantine', path),
    quarantineList: () => ipcRenderer.invoke('av-quarantine-list'),
    restore: (id: string) => ipcRenderer.invoke('av-restore', id),
    remove: (id: string) => ipcRenderer.invoke('av-delete', id),
    reveal: (path: string) => ipcRenderer.invoke('av-reveal', path),
    watch: (on: boolean, offline?: boolean) => ipcRenderer.invoke('av-watch', on, offline),
    onEvent: (callback: (event: unknown) => void): (() => void) => {
      const handler = (_: unknown, data: unknown): void => callback(data)
      ipcRenderer.on('av-event', handler)
      return () => ipcRenderer.removeListener('av-event', handler)
    },
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
