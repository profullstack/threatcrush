import { cn } from '../lib/utils'
import { useEventStore } from '../stores/events'

export default function ThreatMap() {
  const threatSources = useEventStore((s) => s.threatSources)

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center px-3 py-2 border-b border-border bg-card/50">
        <span className="text-[10px] text-dim uppercase tracking-widest">Top Threat Sources</span>
        <span className="ml-auto text-[10px] text-threat">{threatSources.length}</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {threatSources.length === 0 ? (
          <div className="flex items-center justify-center h-full text-dim text-[11px]">
            No threats detected
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {threatSources.map((source, i) => {
              const maxHits = threatSources[0]?.hits || 1
              const barWidth = (source.hits / maxHits) * 100

              return (
                <div key={source.ip} className="px-3 py-1.5 hover:bg-white/[0.02]">
                  <div className="flex items-center gap-2 text-[11px]">
                    <span className={cn(
                      'w-4 text-right font-bold',
                      i < 3 ? 'text-threat' : 'text-warning'
                    )}>
                      {i + 1}
                    </span>
                    <span className="text-text font-mono flex-1">{source.ip}</span>
                    <span className="text-dim text-[10px]">{source.country}</span>
                    <span className={cn(
                      'font-bold w-8 text-right',
                      source.hits > 10 ? 'text-threat' : 'text-warning'
                    )}>
                      {source.hits}
                    </span>
                  </div>
                  <div className="mt-1 h-[2px] bg-border rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all duration-500',
                        i < 3 ? 'bg-threat/60' : 'bg-warning/40'
                      )}
                      style={{ width: `${barWidth}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
