import { NavLink } from 'react-router-dom'
import { cn } from '../lib/utils'
import { useEventStore } from '../stores/events'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '◉' },
  { path: '/fleet', label: 'Fleet', icon: '☰' },
  { path: '/monitor', label: 'Monitor', icon: '▶' },
  { path: '/modules', label: 'Modules', icon: '⬡' },
  { path: '/antivirus', label: 'Virus Scan', icon: '⛉' },
  { path: '/findings', label: 'Findings', icon: '⚑' },
  { path: '/settings', label: 'Settings', icon: '⚙' }
]

export default function Sidebar() {
  const modules = useEventStore((s) => s.modules)
  const local = useEventStore((s) => s.local)
  const version = window.api?.getVersion?.() ?? ''
  const isUp = (st: string): boolean => st === 'running' || st === 'loaded'

  return (
    <div className="w-52 bg-card border-r border-border flex flex-col h-full shrink-0">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-primary text-xl glow-green">⛨</span>
          <div>
            <h1 className="text-primary text-sm font-bold tracking-wider glow-green">THREATCRUSH</h1>
            <span className="text-dim text-[10px]">{version ? `v${version} · ` : ''}DESKTOP</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="px-2 py-3 space-y-0.5">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2 px-3 py-2 rounded text-xs font-medium transition-colors',
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-dim hover:text-text hover:bg-white/5'
              )
            }
          >
            <span className="text-sm">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Module Status */}
      <div className="px-3 py-2 border-t border-border mt-2">
        <div className="text-[10px] text-dim uppercase tracking-widest mb-2">Modules</div>
        <div className="space-y-1">
          {modules.length === 0 && (
            <div className="text-[11px] text-dim">{local.state === 'connected' ? 'none loaded' : 'no local daemon'}</div>
          )}
          {modules.map((mod) => (
            <div key={mod.name} className="flex items-center gap-2 text-[11px]">
              <span
                className={cn(
                  'w-1.5 h-1.5 rounded-full',
                  isUp(mod.status) ? 'bg-primary' : mod.status === 'error' ? 'bg-threat' : 'bg-dim'
                )}
              />
              <span className={cn(
                isUp(mod.status) ? 'text-text' : 'text-dim'
              )}>
                {mod.name}
              </span>
              <span className="ml-auto text-dim">{mod.events}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Status */}
      <div className="mt-auto px-3 py-3 border-t border-border">
        <div className="flex items-center gap-2 text-[11px]">
          {local.state === 'connected' ? (
            <>
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              <span className="text-primary text-[10px]">MONITORING THIS MACHINE</span>
            </>
          ) : (
            <>
              <span className="w-2 h-2 rounded-full bg-dim" />
              <span className="text-dim text-[10px]">NOT MONITORING THIS MACHINE</span>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
