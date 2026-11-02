import { BrowserWindow, dialog, ipcMain, Notification, shell } from 'electron'
import { RULES, type AvDetection, type AvFileResult } from '@threatcrush/av'
import {
  clamInstallHint,
  deleteQuarantined,
  detectClamAV,
  fullScanTargets,
  listQuarantine,
  quarantineFile,
  quickScanTargets,
  restoreQuarantined,
  scanPaths,
  watchTargets,
  type ScanTarget,
} from '@threatcrush/av/node'

/**
 * CrushAV in the desktop app. The engine runs in the main process (it needs
 * the filesystem); the sandboxed renderer drives it over IPC and receives
 * progress and real-time protection events on the `av-event` channel.
 */

const LOOKUP = 'https://threatcrush.com/api/av/lookup'

type Res<T> = { ok: true; result: T } | { ok: false; error: string }
const wrap = async <T>(fn: () => Promise<T> | T): Promise<Res<T>> => {
  try {
    return { ok: true, result: await fn() }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

const send = (payload: unknown) => {
  for (const w of BrowserWindow.getAllWindows()) w.webContents.send('av-event', payload)
}

let current: AbortController | null = null
let stopWatch: (() => void) | null = null
/** Detections of the last scan by path, so quarantine records why. */
const lastDetections = new Map<string, AvDetection[]>()

export function registerAvHandlers(): void {
  ipcMain.handle('av-status', () =>
    wrap(async () => ({
      rules: RULES.length,
      clamav: await detectClamAV(),
      clamavHint: clamInstallHint(),
      quarantined: (await listQuarantine()).length,
      watching: !!stopWatch,
      quickTargets: quickScanTargets().map((t) => t.path),
    })),
  )

  ipcMain.handle('av-pick', () =>
    wrap(async () => {
      const r = await dialog.showOpenDialog({ title: 'Choose files or folders to scan', properties: ['openFile', 'openDirectory', 'multiSelections'] })
      return r.canceled ? [] : r.filePaths
    }),
  )

  ipcMain.handle('av-scan', (_e, mode: unknown, paths: unknown, offline: unknown) =>
    wrap(async () => {
      if (current) throw new Error('A scan is already running')
      let targets: ScanTarget[]
      if (mode === 'full') targets = fullScanTargets()
      else if (mode === 'paths' && Array.isArray(paths) && paths.length) targets = paths.map((p) => ({ path: String(p), depth: Infinity }))
      else targets = quickScanTargets()
      current = new AbortController()
      let last = 0
      try {
        const report = await scanPaths(targets, {
          signal: current.signal,
          reputation: offline !== true,
          lookupEndpoint: LOOKUP,
          onProgress: (p) => {
            if (p.type === 'phase') send({ type: 'phase', phase: p.phase, detail: p.detail })
            else if (p.type === 'file') {
              if (p.result.verdict === 'malicious' || p.result.verdict === 'suspicious') send({ type: 'hit', result: p.result })
              if (Date.now() - last > 150) {
                last = Date.now()
                send({ type: 'progress', scanned: p.scanned, path: p.path })
              }
            }
          },
        })
        const flagged = report.results.filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious')
        lastDetections.clear()
        for (const r of flagged) lastDetections.set(r.path, r.detections)
        return { summary: report.summary, flagged, clamav: report.clamav, clamavError: report.clamavError, cancelled: current.signal.aborted }
      } finally {
        current = null
      }
    }),
  )

  ipcMain.handle('av-cancel', () => wrap(() => current?.abort()))

  ipcMain.handle('av-quarantine', (_e, path: unknown) =>
    wrap(async () => {
      const p = String(path)
      const entry = await quarantineFile(p, lastDetections.get(p) ?? [])
      lastDetections.delete(p)
      return entry
    }),
  )
  ipcMain.handle('av-quarantine-list', () => wrap(() => listQuarantine()))
  ipcMain.handle('av-restore', (_e, id: unknown) => wrap(() => restoreQuarantined(String(id))))
  ipcMain.handle('av-delete', (_e, id: unknown) => wrap(() => deleteQuarantined(String(id))))
  ipcMain.handle('av-reveal', (_e, path: unknown) => wrap(() => shell.showItemInFolder(String(path))))

  ipcMain.handle('av-watch', (_e, on: unknown, offline: unknown) =>
    wrap(() => {
      stopWatch?.()
      stopWatch = null
      if (on !== true) return { watching: false }
      stopWatch = watchTargets(quickScanTargets(), {
        reputation: offline !== true,
        lookupEndpoint: LOOKUP,
        onResult: (r: AvFileResult) => {
          send({ type: 'watch', result: r })
          if (r.verdict === 'malicious' || r.verdict === 'suspicious') {
            lastDetections.set(r.path, r.detections)
            if (Notification.isSupported()) {
              const top = r.detections.find((d) => d.impact !== 'info')
              new Notification({
                title: r.verdict === 'malicious' ? 'CrushAV found malware' : 'CrushAV: suspicious file',
                body: `${r.path.split(/[\\/]/).pop()}: ${top?.name ?? r.verdict}. Do not open it; quarantine it in ThreatCrush → Virus Scan.`,
              }).show()
            }
          }
        },
      })
      return { watching: true }
    }),
  )
}

export function stopAv(): void {
  current?.abort()
  stopWatch?.()
  stopWatch = null
}
