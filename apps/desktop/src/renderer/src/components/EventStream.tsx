import { useEffect, useRef } from 'react'
import { useEventStore } from '../stores/events'
import EventRow from './EventRow'

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
