import { useNavigate } from 'react-router-dom'
import { applyExpectedKeys, effectiveSeverity, rowSummary, sshContextOf } from '@threatcrush/event-detail'
import { cn } from '../lib/utils'
import { levelFor, useEventStore, type SecurityEvent } from '../stores/events'

const levelColors: Record<string, string> = {
  info: 'text-primary',
  warning: 'text-warning',
  threat: 'text-threat',
}

const levelBadge: Record<string, string> = {
  info: 'INF',
  warning: 'WRN',
  threat: 'THR',
}

const verdictColors: Record<string, string> = {
  expected: 'text-primary/70',
  'likely-ci': 'text-primary/80',
  internal: 'text-primary/80',
  review: 'text-warning',
  suspicious: 'text-threat',
}

/** The event detail route for a row. */
export function eventPath(e: SecurityEvent): string {
  return `/event/${encodeURIComponent(e.id)}`
}

/**
 * One event-log row: time, level, origin, rule and the event's story (who,
 * how, from where, and the agent's verdict for SSH logins). Click opens the
 * detail view with its full history.
 */
export default function EventRow({ event, showOrigin = true }: { event: SecurityEvent; showOrigin?: boolean }) {
  const navigate = useNavigate()
  const expected = useEventStore((s) => s.expectedKeys)
  const like = applyExpectedKeys(event.detail, expected)
  const level = levelFor(effectiveSeverity(like))
  const summary = like === event.detail ? event.summary : rowSummary(like).text
  const verdict = sshContextOf(like)?.verdict
  return (
    <button
      type="button"
      onClick={() => navigate(eventPath(event))}
      title={`${summary}${verdict ? `\n${verdict.summary}` : ''}\nClick for details and history`}
      className={cn(
        'flex w-full gap-3 px-3 py-1 text-left text-[11px] font-mono hover:bg-white/[0.04] border-l-2 cursor-pointer',
        level === 'threat' ? 'border-threat/50' : level === 'warning' ? 'border-warning/30' : 'border-transparent',
      )}
    >
      <span className="text-dim shrink-0">{event.timestamp}</span>
      <span className={cn('shrink-0 w-7 text-center font-bold', levelColors[level])}>{levelBadge[level]}</span>
      {showOrigin && <span className="text-dim shrink-0 w-24 truncate" title={event.origin}>{event.origin}</span>}
      <span className="text-dim shrink-0 w-28 truncate" title={event.module}>[{event.module}]</span>
      <span
        className={cn(
          'truncate min-w-0 flex-1',
          level === 'threat' ? 'text-threat' : level === 'warning' ? 'text-warning/80' : 'text-text/70',
        )}
      >
        {summary}
      </span>
      {verdict && (
        <span className={cn('shrink-0 max-w-[40%] truncate', verdictColors[verdict.level])}>{verdict.summary}</span>
      )}
    </button>
  )
}
