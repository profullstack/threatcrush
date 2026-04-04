import { useEffect } from 'react'
import { formatUptime } from '../lib/utils'
import { useEventStore } from '../stores/events'

export default function StatsBar() {
  const totalEvents = useEventStore((s) => s.totalEvents)
  const totalThreats = useEventStore((s) => s.totalThreats)
  const connectionsPerSec = useEventStore((s) => s.connectionsPerSec)
  const uptimeSeconds = useEventStore((s) => s.uptimeSeconds)
  const incrementUptime = useEventStore((s) => s.incrementUptime)
  const generateFakeEvent = useEventStore((s) => s.generateFakeEvent)

  useEffect(() => {
    const uptimeInterval = setInterval(incrementUptime, 1000)
    const eventInterval = setInterval(generateFakeEvent, Math.random() * 800 + 400)

    // Generate initial batch
    for (let i = 0; i < 25; i++) {
      generateFakeEvent()
    }

    return () => {
      clearInterval(uptimeInterval)
      clearInterval(eventInterval)
    }
  }, [])

  return (
    <div className="h-7 bg-card border-t border-border flex items-center px-4 gap-6 text-[10px] font-mono shrink-0">
      <div className="flex items-center gap-1.5">
        <span className="text-dim">EVENTS</span>
        <span className="text-primary font-bold">{totalEvents.toLocaleString()}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className="text-dim">THREATS</span>
        <span className="text-threat font-bold">{totalThreats.toLocaleString()}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className="text-dim">CONN/S</span>
        <span className="text-warning font-bold">{connectionsPerSec}</span>
      </div>
      <div className="ml-auto flex items-center gap-1.5">
        <span className="text-dim">UPTIME</span>
        <span className="text-primary">{formatUptime(uptimeSeconds)}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
        <span className="text-primary">LIVE</span>
      </div>
    </div>
  )
}
