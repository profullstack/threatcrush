import { app, shell, BrowserWindow, ipcMain } from 'electron'
import { join } from 'path'
import { spawn, ChildProcess } from 'child_process'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'

let daemonProcess: ChildProcess | null = null

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

// ─── IPC Handlers ───

ipcMain.handle('connect-daemon', async (_event, host: string, port: number) => {
  if (daemonProcess) {
    return { connected: true, pid: daemonProcess.pid }
  }

  try {
    daemonProcess = spawn('threatcrush', ['monitor'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NODE_ENV: 'production' },
    })

    daemonProcess.stdout?.on('data', (data) => {
      const mainWindow = BrowserWindow.getAllWindows()[0]
      if (mainWindow) {
        mainWindow.webContents.send('threat-event', {
          type: 'daemon-output',
          data: data.toString().trim(),
        })
      }
    })

    daemonProcess.stderr?.on('data', (data) => {
      const mainWindow = BrowserWindow.getAllWindows()[0]
      if (mainWindow) {
        mainWindow.webContents.send('threat-event', {
          type: 'daemon-error',
          data: data.toString().trim(),
        })
      }
    })

    daemonProcess.on('exit', (code) => {
      daemonProcess = null
      const mainWindow = BrowserWindow.getAllWindows()[0]
      if (mainWindow) {
        mainWindow.webContents.send('threat-event', {
          type: 'daemon-exit',
          data: { code },
        })
      }
    })

    return { connected: true, pid: daemonProcess.pid }
  } catch (err) {
    return { connected: false, error: err instanceof Error ? err.message : 'Unknown error' }
  }
})

ipcMain.handle('disconnect-daemon', async () => {
  if (daemonProcess) {
    daemonProcess.kill('SIGTERM')
    daemonProcess = null
  }
  return { disconnected: true }
})

ipcMain.handle('daemon-status', async () => {
  if (!daemonProcess) {
    return { running: false }
  }
  return { running: true, pid: daemonProcess.pid }
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
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
