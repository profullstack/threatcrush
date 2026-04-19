import { NavLink } from 'react-router-dom'
import { cn } from '../lib/utils'
import { useEventStore } from '../stores/events'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '◉' },
  { path: '/monitor', label: 'Monitor', icon: '▶' },
  { path: '/modules', label: 'Modules', icon: '⬡' },
  { path: '/settings', label: 'Settings', icon: '⚙' }
]

export default function Sidebar() {
  const modules = useEventStore((s) => s.modules)

  return (
    <div className="w-52 bg-card border-r border-border flex flex-col h-full shrink-0">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-primary text-xl glow-green">⛨</span>
          <div>
            <h1 className="text-primary text-sm font-bold tracking-wider glow-green">THREATCRUSH</h1>
            <span className="text-dim text-[10px]">v0.1.3 · DESKTOP</span>
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
          {modules.map((mod) => (
            <div key={mod.name} className="flex items-center gap-2 text-[11px]">
              <span
                className={cn(
                  'w-1.5 h-1.5 rounded-full',
                  mod.status === 'running' ? 'bg-primary' : mod.status === 'error' ? 'bg-threat' : 'bg-dim'
                )}
              />
              <span className={cn(
                mod.status === 'running' ? 'text-text' : 'text-dim'
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
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <span className="text-primary text-[10px]">MONITORING ACTIVE</span>
        </div>
      </div>
    </div>
  )
}
