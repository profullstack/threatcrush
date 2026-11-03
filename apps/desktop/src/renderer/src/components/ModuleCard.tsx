import { cn } from '../lib/utils'
import type { Module } from '../stores/events'

const isUp = (s: string): boolean => s === 'running' || s === 'loaded'

export default function ModuleCard({ module }: { module: Module }) {
  return (
    <div className={cn(
      'bg-card border rounded-lg p-4',
      isUp(module.status) ? 'border-border' : 'border-border/50 opacity-70'
    )}>
      <div className="flex items-center gap-2 mb-3">
        <span
          className={cn(
            'w-2 h-2 rounded-full',
            isUp(module.status) ? 'bg-primary' : module.status === 'error' ? 'bg-threat' : 'bg-dim'
          )}
        />
        <h3 className="text-sm font-bold text-text">{module.name}</h3>
      </div>
      {module.description && <p className="text-[11px] text-dim mb-3">{module.description}</p>}
      <div className="flex items-center gap-4 text-[10px]">
        <div>
          <span className="text-dim">Status: </span>
          <span className={cn(
            'font-bold uppercase',
            isUp(module.status) ? 'text-primary' : module.status === 'error' ? 'text-threat' : 'text-dim'
          )}>
            {module.status}
          </span>
        </div>
        <div>
          <span className="text-dim">Events: </span>
          <span className="text-text font-bold">{module.events.toLocaleString()}</span>
        </div>
      </div>
    </div>
  )
}
