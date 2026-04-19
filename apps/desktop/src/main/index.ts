import { app, shell, BrowserWindow, ipcMain } from 'electron'
import { join } from 'path'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { DaemonClient, resolveDaemonPaths } from './daemon-client'

let daemon: DaemonClient | null = null
let daemonUnsub: (() => void) | null = null

function createWindow(): void {
  const mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    show: false,
    backgroundColor: '#0a0a0a',
    titleBarStyle: 'hiddenInset',
    autoHideMenuBar: true,
    ...(process.platform === 'linux' ? { icon: join(__dirname, '../../resources/icon.png') } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false
    }
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow.show()
  })

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

function broadcast(channel: string, payload: unknown): void {
  for (const win of BrowserWindow.getAllWindows()) {
    win.webContents.send(channel, payload)
  }
}

async function connectToDaemon(socketPathOverride?: string): Promise<
  | { connected: true; pid?: number; version?: string; socket: string }
  | { connected: false; error: string; socket: string }
> {
  // Tear down any existing connection.
  if (daemon) {
    try { daemon.close() } catch {}
    daemon = null
  }
  if (daemonUnsub) {
    daemonUnsub()
    daemonUnsub = null
  }

  const paths = resolveDaemonPaths()
  const socketPath = socketPathOverride || paths.socket
  const client = new DaemonClient(socketPath)

  try {
    await client.connect()
  } catch (err) {
    return {
      connected: false,
      error: err instanceof Error ? err.message : String(err),
      socket: socketPath,
    }
  }

  daemon = client

  // Subscribe to events + module status from the daemon.
  try {
    await client.request('subscribe', { channels: ['event', 'module'] })
  } catch {
    // subscription is best-effort; we still return connected
  }

  daemonUnsub = client.onPush((frame) => {
    const push = frame.push as string
    const payload = frame.payload
    if (push === 'event') {
      broadcast('threat-event', { type: 'event', data: payload })
    } else if (push === 'module') {
      broadcast('threat-event', { type: 'module', data: payload })
    }
  })

  // Fetch initial status for the handshake response.
  try {
    const status = await client.request<{ pid: number; version: string }>('status')
    broadcast('threat-event', { type: 'connected', data: status })
    return { connected: true, pid: status.pid, version: status.version, socket: socketPath }
  } catch {
    return { connected: true, socket: socketPath }
  }
}

// ─── IPC Handlers ───

ipcMain.handle('connect-daemon', async (_event, arg1?: string | number, _arg2?: number) => {
  // Legacy signature was (host, port). We ignore it and connect to the local
  // unix socket instead — ThreatCrush desktop always pairs with a local daemon
  // for v0.1.0. A future build can add remote TCP support.
  const override = typeof arg1 === 'string' && arg1.startsWith('/') ? arg1 : undefined
  return connectToDaemon(override)
})

ipcMain.handle('disconnect-daemon', async () => {
  if (daemonUnsub) { daemonUnsub(); daemonUnsub = null }
  if (daemon) {
    try { daemon.close() } catch {}
    daemon = null
  }
  broadcast('threat-event', { type: 'disconnected' })
  return { disconnected: true }
})

ipcMain.handle('daemon-status', async () => {
  if (!daemon || !daemon.isConnected()) {
    return { running: false, socket: resolveDaemonPaths().socket }
  }
  try {
    const status = await daemon.request<{ pid: number; uptimeSeconds: number; modules: unknown[] }>('status')
    return { running: true, pid: status.pid, uptimeSeconds: status.uptimeSeconds, modules: status.modules }
  } catch (err) {
    return { running: false, error: err instanceof Error ? err.message : String(err) }
  }
})

ipcMain.handle('daemon-request', async (_event, method: string, params?: Record<string, unknown>) => {
  if (!daemon || !daemon.isConnected()) {
    return { ok: false, error: 'not connected' }
  }
  try {
    const result = await daemon.request(method, params)
    return { ok: true, result }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
})

app.whenReady().then(() => {
  electronApp.setAppUserModelId('com.threatcrush.desktop')

  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window)
  })

  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (daemon) {
    try { daemon.close() } catch {}
    daemon = null
  }
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
