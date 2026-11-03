import { useEffect } from 'react'
import { cn, formatUptime } from '../lib/utils'
import { useEventStore } from '../stores/events'

export default function StatsBar() {
  const start = useEventStore((s) => s.start)
  const local = useEventStore((s) => s.local)
  const fleet = useEventStore((s) => s.fleet)
  const servers = useEventStore((s) => s.servers)
  const totalEvents = useEventStore((s) => s.totalEvents)
  const threats24h = useEventStore((s) => s.threats24h)
  const uptimeSeconds = useEventStore((s) => s.uptimeSeconds)

  useEffect(() => start(), [start])

  const online = servers.filter((s) => s.status === 'online').length
  const isLocal = local.state === 'connected'

  return (
    <div className="h-7 bg-card border-t border-border flex items-center px-4 gap-6 text-[10px] font-mono shrink-0">
      <div className="flex items-center gap-1.5" title={local.state === 'offline' ? local.error : undefined}>
        <span className={cn('w-1.5 h-1.5 rounded-full', isLocal ? 'bg-primary' : 'bg-dim')} />
        <span className="text-dim">LOCAL</span>
        <span className={cn('font-bold', isLocal ? 'text-primary' : 'text-dim')}>
          {isLocal ? 'threatcrushd' : local.state === 'connecting' ? 'connecting' : 'no daemon'}
        </span>
      </div>
      {isLocal && (
        <>
          <div className="flex items-center gap-1.5">
            <span className="text-dim">EVENTS</span>
            <span className="text-primary font-bold">{totalEvents.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-dim">THREATS 24H</span>
            <span className="text-threat font-bold">{threats24h.toLocaleString()}</span>
          </div>
        </>
      )}
      <div className="flex items-center gap-1.5" title={fleet.state === 'error' ? fleet.error : undefined}>
        <span className={cn('w-1.5 h-1.5 rounded-full', fleet.state === 'ok' ? 'bg-primary' : 'bg-dim')} />
        <span className="text-dim">FLEET</span>
        <span className={cn('font-bold', fleet.state === 'ok' ? 'text-text' : 'text-dim')}>
          {fleet.state === 'ok'
            ? `${online}/${servers.length} online`
            : fleet.state === 'signed-out'
              ? 'not signed in'
              : fleet.state === 'loading'
                ? 'loading'
                : 'error'}
        </span>
      </div>
      {isLocal && (
        <div className="ml-auto flex items-center gap-1.5">
          <span className="text-dim">DAEMON UPTIME</span>
          <span className="text-text font-bold">{formatUptime(uptimeSeconds)}</span>
        </div>
      )}
    </div>
  )
}
