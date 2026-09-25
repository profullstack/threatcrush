import { useState } from 'react'
import { cn } from '../lib/utils'
import type { ConnectResult } from '../api'

export default function Settings() {
  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [result, setResult] = useState<ConnectResult | null>(null)

  const handleConnect = async () => {
    const api = window.api
    if (!api) {
      setResult({ connected: false, error: 'not running inside ThreatCrush Desktop' })
      return
    }
    setConnecting(true)
    try {
      // The main process bounds every daemon request, so this settles with
      // either a connection or an error to show.
      const res = await api.connectDaemon()
      setConnected(res.connected)
      setResult(res)
    } catch (err) {
      setConnected(false)
      setResult({ connected: false, error: err instanceof Error ? err.message : String(err) })
    } finally {
      setConnecting(false)
    }
  }

  const statusText = connected
    ? `Connected to threatcrushd${result?.version ? ` v${result.version}` : ''}${result?.socket ? ` at ${result.socket}` : ''}`
    : result?.error
      ? `Not connected: ${result.error}`
      : 'Not connected — using demo data'

  return (
    <div className="flex flex-col h-full p-4 gap-6 max-w-2xl">
      <div>
        <h2 className="text-lg font-bold text-text">Settings</h2>
        <p className="text-[11px] text-dim mt-0.5">Configure ThreatCrush Desktop</p>
      </div>

      {/* Daemon Connection */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-bold text-text mb-1">Daemon Connection</h3>
        <p className="text-[10px] text-dim mb-4">
          Connect to the local threatcrushd over its unix socket.
          Dashboards still show simulated data.
        </p>

        <div className="flex gap-3 items-end">
          <button
            onClick={handleConnect}
            disabled={connecting}
            className={cn(
              'px-4 py-1.5 text-[10px] font-bold rounded border transition-colors',
              connected
                ? 'border-primary/30 text-primary bg-primary/10'
                : 'border-primary/30 text-primary hover:bg-primary/10',
              connecting && 'opacity-50 cursor-wait'
            )}
          >
            {connecting ? 'CONNECTING...' : connected ? 'CONNECTED' : 'CONNECT'}
          </button>
        </div>

        <div className="mt-3 flex items-center gap-2 text-[10px]">
          <span className={cn(
            'w-1.5 h-1.5 rounded-full',
            connected ? 'bg-primary' : 'bg-threat'
          )} />
          <span className={connected ? 'text-primary' : 'text-threat'}>
            {statusText}
          </span>
        </div>
      </div>

      {/* Display Settings */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-bold text-text mb-1">Display</h3>
        <p className="text-[10px] text-dim mb-4">Customize the monitoring display.</p>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs text-text">Max events in stream</div>
              <div className="text-[10px] text-dim">Number of events visible in the dashboard</div>
            </div>
            <input
              type="number"
              defaultValue={200}
              className="w-20 bg-bg border border-border rounded px-2 py-1 text-xs text-text font-mono text-right focus:border-primary/50 focus:outline-none"
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs text-text">Event generation speed</div>
              <div className="text-[10px] text-dim">Demo mode event interval (ms)</div>
            </div>
            <input
              type="number"
              defaultValue={600}
              className="w-20 bg-bg border border-border rounded px-2 py-1 text-xs text-text font-mono text-right focus:border-primary/50 focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* About */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-bold text-text mb-1">About</h3>
        <div className="space-y-1 text-[11px]">
          <div className="flex justify-between">
            <span className="text-dim">Version</span>
            <span className="text-text font-mono">0.1.3</span>
          </div>
          <div className="flex justify-between">
            <span className="text-dim">Electron</span>
            <span className="text-text font-mono">{(window as any).electron?.process?.versions?.electron || 'N/A'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-dim">Chrome</span>
            <span className="text-text font-mono">{(window as any).electron?.process?.versions?.chrome || 'N/A'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-dim">Node</span>
            <span className="text-text font-mono">{(window as any).electron?.process?.versions?.node || 'N/A'}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
