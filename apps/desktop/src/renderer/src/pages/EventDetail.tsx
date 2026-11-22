import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  applyExpectedKeys, buildTimeline, detailModel, fingerprintOf, sshContextOf, type EventLike, type Relation,
} from '@threatcrush/event-detail'
import { EventDetailView, type EventDetailAction } from '@threatcrush/event-detail/react'
import { useEventStore } from '../stores/events'
import type { CloudDetectionHistory } from '../api'

/**
 * One event with its full history: every event sharing its source IP, SSH
 * key, host or rule. The same view (and, for fleet events, the same API) as
 * the web dashboard's detection page, so desktop and PWA show the same thing.
 *
 *   fleet event  -> GET /api/orgs/:org/detections/:id/history (org-wide, 30 days)
 *   local event  -> the daemon's recent events held in this app
 */
export default function EventDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const events = useEventStore((s) => s.events)
  const expected = useEventStore((s) => s.expectedKeys)
  const toggleExpectedKey = useEventStore((s) => s.toggleExpectedKey)
  const event = events.find((e) => e.id === id)
  const [filter, setFilter] = useState<Relation | 'all'>('all')
  const [history, setHistory] = useState<CloudDetectionHistory | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const detectionId = event?.detectionId
  useEffect(() => {
    setHistory(null)
    setError(null)
    setFilter('all')
    const cloud = window.api?.cloud
    if (!detectionId || !cloud) return
    setLoading(true)
    cloud.detectionHistory(detectionId)
      .then((r) => (r.ok ? setHistory(r.result) : setError(`Fleet history unavailable: ${r.error}`)))
      .catch((e: unknown) => setError(String(e)))
      .finally(() => setLoading(false))
  }, [detectionId])

  const view = useMemo(() => {
    if (!event) return null
    // Fleet: the server's copy of the detection and its related rows. Local:
    // this app's events, newest first. Both through the shared builders.
    const primary: EventLike = applyExpectedKeys(history?.detection ?? event.detail, expected)
    const candidates: EventLike[] = history
      ? history.related
      : events.filter((e) => e.id !== event.id).map((e) => e.detail)
    return {
      primary,
      model: detailModel(primary, { originLabel: history?.origin ?? null, viewerTime: (ms) => new Date(ms).toLocaleString() }),
      timeline: buildTimeline(primary, candidates.map((c) => applyExpectedKeys(c, expected))),
    }
  }, [event, events, history, expected])

  if (!event || !view) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-dim text-xs">
        <span>This event is no longer in the app's recent history.</span>
        <button type="button" onClick={() => navigate('/monitor')} className="text-primary hover:underline">Back to the event log</button>
      </div>
    )
  }

  const flash = (t: string): void => {
    setNotice(t)
    setTimeout(() => setNotice(null), 4000)
  }
  const fp = fingerprintOf(view.primary)
  const isExpected = !!fp && expected.has(fp)
  const actions: EventDetailAction[] = [
    {
      id: 'copy',
      label: 'Copy event JSON',
      onClick: () => {
        void navigator.clipboard.writeText(JSON.stringify(history?.detection ?? event.detail, null, 2)).then(() => flash('Copied'))
      },
    },
  ]
  if (fp && sshContextOf(view.primary)) {
    actions.push({
      id: 'expected',
      label: isExpected ? 'Unmark expected CI key' : 'Mark this key as expected CI',
      primary: !isExpected,
      title: 'Future logins with this key show as a quiet info row in this app. To quiet the agent itself, add the fingerprint to [ssh_context] expected_keys in threatcrushd.conf.',
      onClick: () => {
        const added = toggleExpectedKey(fp)
        flash(added ? `Marked. For the agent: [ssh_context] expected_keys = ["${fp}"]` : 'Removed from expected keys')
      },
    })
  }
  if (detectionId) {
    actions.push({
      id: 'web',
      label: history?.incident ? `Open on threatcrush.com (incident ${history.incident.status})` : 'Open on threatcrush.com',
      onClick: () => { void window.api?.cloud.openDetection(detectionId) },
    })
  }

  return (
    <div className="h-full overflow-y-auto p-4">
      <div className="mb-3 flex items-center gap-3 text-[11px] text-dim">
        <button type="button" onClick={() => navigate(-1)} className="hover:text-text">← Back</button>
        <span>{event.origin}</span>
        <span>{history ? `history: last ${history.window_days} days across your fleet` : detectionId ? '' : "history: this machine's recent events"}</span>
      </div>
      <EventDetailView
        model={view.model}
        timeline={view.timeline}
        filter={filter}
        onFilter={setFilter}
        onSelect={(item) => {
          const target = events.find((e) => e.detail.id === item.event.id || e.detectionId === item.event.id)
          if (target) navigate(`/event/${encodeURIComponent(target.id)}`)
          else if (history) void window.api?.cloud.openDetection(item.event.id)
        }}
        actions={actions}
        notice={notice}
        loadingHistory={loading}
        historyError={error}
      />
    </div>
  )
}
