import { useEventStore } from '../stores/events'
import { cn } from '../lib/utils'

export default function Monitor() {
  const events = useEventStore((s) => s.events)
  const totalEvents = useEventStore((s) => s.totalEvents)
  const totalThreats = useEventStore((s) => s.totalThreats)

  const infoCount = events.filter((e) => e.level === 'info').length
  const warnCount = events.filter((e) => e.level === 'warning').length
  const threatCount = events.filter((e) => e.level === 'threat').length

  return (
    <div className="flex flex-col h-full p-4 gap-4">
      {/* Stats row */}
      <div className="flex gap-4">
        {[
          { label: 'Total Events', value: totalEvents, color: 'text-primary' },
          { label: 'Info', value: infoCount, color: 'text-primary' },
          { label: 'Warnings', value: warnCount, color: 'text-warning' },
          { label: 'Threats', value: threatCount, color: 'text-threat' },
          { label: 'Blocked', value: totalThreats, color: 'text-threat' }
        ].map((stat) => (
          <div key={stat.label} className="bg-card border border-border rounded-lg px-4 py-3 flex-1">
            <div className="text-[10px] text-dim uppercase tracking-wider">{stat.label}</div>
            <div className={cn('text-2xl font-bold mt-1', stat.color)}>
              {stat.value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Full event log */}
      <div className="flex-1 bg-card border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-2 border-b border-border flex items-center">
          <span className="text-[10px] text-dim uppercase tracking-widest">Full Event Log</span>
          <span className="ml-2 text-[10px] text-primary cursor-blink">▌</span>
        </div>
        <div className="overflow-y-auto h-full pb-10">
          {events.map((event) => (
            <div
              key={event.id}
              className={cn(
                'flex gap-2 px-4 py-1 text-[11px] font-mono hover:bg-white/[0.02]',
                event.level === 'threat' && 'bg-threat/5'
              )}
            >
              <span className="text-dim shrink-0">{event.timestamp}</span>
              <span className={cn(
                'shrink-0 w-7 font-bold',
                event.level === 'info' ? 'text-primary' :
                event.level === 'warning' ? 'text-warning' :
                'text-threat'
              )}>
                {event.level === 'info' ? 'INF' : event.level === 'warning' ? 'WRN' : 'THR'}
              </span>
              <span className="text-dim shrink-0 w-20">[{event.module}]</span>
              <span className="text-text/80 truncate">{event.message}</span>
              {event.sourceIP && (
                <span className="ml-auto text-dim shrink-0">{event.sourceIP}</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
