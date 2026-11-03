import { useEffect, useRef } from 'react'
import { cn } from '../lib/utils'
import { useEventStore, type SecurityEvent } from '../stores/events'

const levelColors: Record<string, string> = {
  info: 'text-primary',
  warning: 'text-warning',
  threat: 'text-threat'
}

const levelBadge: Record<string, string> = {
  info: 'INF',
  warning: 'WRN',
  threat: 'THR'
}

function EventRow({ event }: { event: SecurityEvent }) {
  return (
    <div
      className={cn(
        'flex gap-3 px-3 py-1 text-[11px] font-mono hover:bg-white/[0.02] border-l-2',
        event.level === 'threat' ? 'border-threat/50' :
        event.level === 'warning' ? 'border-warning/30' :
        'border-transparent'
      )}
    >
      <span className="text-dim shrink-0">{event.timestamp}</span>
      <span
        className={cn(
          'shrink-0 w-7 text-center font-bold',
          levelColors[event.level]
        )}
      >
        {levelBadge[event.level]}
      </span>
      <span className="text-dim shrink-0 w-24 truncate" title={event.origin}>{event.origin}</span>
      <span className="text-dim shrink-0 w-28 truncate" title={event.module}>[{event.module}]</span>
      <span className={cn(
        'truncate',
        event.level === 'threat' ? 'text-threat' :
        event.level === 'warning' ? 'text-warning/80' :
        'text-text/70'
      )}>
        {event.message}
      </span>
    </div>
  )
}

export default function EventStream({ maxEvents = 200 }: { maxEvents?: number }) {
  const events = useEventStore((s) => s.events)
  const local = useEventStore((s) => s.local)
  const fleet = useEventStore((s) => s.fleet)
  const noSource = local.state === 'offline' && fleet.state !== 'ok'
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0
    }
  }, [events[0]?.id])

  const displayEvents = events.slice(0, maxEvents)

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center px-3 py-2 border-b border-border bg-card/50">
        <span className="text-[10px] text-dim uppercase tracking-widest">Event Stream</span>
        <span className="ml-auto text-[10px] text-dim">{events.length} events</span>
      </div>
      <div ref={containerRef} className="flex-1 overflow-y-auto overflow-x-hidden">
        {displayEvents.map((event) => (
          <EventRow key={event.id} event={event} />
        ))}
        {displayEvents.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-dim text-xs gap-2 px-6 text-center">
            {noSource ? (
              <>
                <span className="text-text">Nothing to show yet: no daemon on this machine and not signed in.</span>
                <span>
                  Start the daemon (<code className="text-primary">threatcrush start</code>) to watch this machine,
                  or sign in under Fleet to see your servers.
                </span>
              </>
            ) : (
              <span><span className="cursor-blink">▌</span> Waiting for events...</span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
