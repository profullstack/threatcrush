import { cn } from '../lib/utils'
import type { Module } from '../stores/events'

interface ModuleCardProps {
  module: Module
  onToggle: () => void
}

export default function ModuleCard({ module, onToggle }: ModuleCardProps) {
  return (
    <div className={cn(
      'bg-card border rounded-lg p-4 hover:border-primary/30 transition-colors',
      module.status === 'running' ? 'border-border' : 'border-border/50 opacity-70'
    )}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              'w-2 h-2 rounded-full',
              module.status === 'running' ? 'bg-primary' :
              module.status === 'error' ? 'bg-threat' :
              'bg-dim'
            )}
          />
          <h3 className="text-sm font-bold text-text">{module.name}</h3>
        </div>
        <button
          onClick={onToggle}
          className={cn(
            'px-2 py-0.5 text-[10px] font-bold rounded border transition-colors',
            module.status === 'running'
              ? 'border-threat/30 text-threat hover:bg-threat/10'
              : 'border-primary/30 text-primary hover:bg-primary/10'
          )}
        >
          {module.status === 'running' ? 'STOP' : 'START'}
        </button>
      </div>
      <p className="text-[11px] text-dim mb-3">{module.description}</p>
      <div className="flex items-center gap-4 text-[10px]">
        <div>
          <span className="text-dim">Status: </span>
          <span className={cn(
            'font-bold uppercase',
            module.status === 'running' ? 'text-primary' :
            module.status === 'error' ? 'text-threat' :
            'text-dim'
          )}>
            {module.status}
          </span>
        </div>
        <div>
          <span className="text-dim">Events: </span>
          <span className="text-text font-bold">{module.events}</span>
        </div>
      </div>
    </div>
  )
}
