/**
 * The event detail view shared by the web dashboard (PWA) and the desktop
 * app, so both show the same facts in the same order. Stateless: the host
 * app owns data loading, the timeline filter and what the actions do.
 *
 * Styling is plain Tailwind utilities from the default palette; both apps
 * scan this file (web: `@source` in globals.css, desktop: tailwind.config.js).
 */
import type { DetailModel, DetailRow } from './model';
import { verdictTone } from './model';
import type { Relation, TimelineItem } from './timeline';
import { RELATIONS, RELATION_LABEL, filterTimeline, relationCounts } from './timeline';

export interface EventDetailAction {
  id: string;
  label: string;
  onClick: () => void;
  title?: string;
  disabled?: boolean;
  /** Visually emphasised. */
  primary?: boolean;
}

export interface EventDetailViewProps {
  model: DetailModel;
  timeline: TimelineItem[];
  filter: Relation | 'all';
  onFilter: (filter: Relation | 'all') => void;
  onSelect?: (item: TimelineItem) => void;
  actions?: EventDetailAction[];
  notice?: string | null;
  loadingHistory?: boolean;
  historyError?: string | null;
  formatTime?: (ms: number) => string;
}

const SEVERITY: Record<string, string> = {
  critical: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  high: 'bg-red-500/20 text-red-300 border-red-500/40',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  low: 'bg-sky-500/20 text-sky-300 border-sky-500/40',
  info: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
};

const TONE: Record<NonNullable<DetailRow['tone']>, string> = {
  bad: 'text-red-300',
  warn: 'text-amber-300',
  good: 'text-emerald-300',
  dim: 'text-zinc-500',
};

const VERDICT_BOX: Record<string, string> = {
  good: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
  warn: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  bad: 'border-red-500/50 bg-red-500/10 text-red-200',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${SEVERITY[severity] ?? SEVERITY.info}`}>
      {severity}
    </span>
  );
}

const defaultTime = (ms: number) => (Number.isNaN(ms) ? '' : new Date(ms).toLocaleString());

export function EventDetailView(props: EventDetailViewProps) {
  const { model, timeline, filter, onFilter, onSelect, actions = [], notice, loadingHistory, historyError } = props;
  const fmt = props.formatTime ?? defaultTime;
  const tone = verdictTone(model.verdict?.level);
  const counts = relationCounts(timeline);
  const shown = filterTimeline(timeline, filter);

  return (
    <div className="flex flex-col gap-4 text-sm text-zinc-200" data-testid="event-detail">
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={model.severity} />
          {model.raisedSeverity && (
            <span className="text-[11px] text-zinc-500" title="The rule's own severity before the agent's verdict">
              raised as {model.raisedSeverity}
            </span>
          )}
          {model.keys.rule && <code className="text-[11px] text-zinc-500">{model.keys.rule}</code>}
        </div>
        <h2 className="text-base font-semibold text-white">{model.title}</h2>
        <p className="break-words font-mono text-xs text-zinc-400">{model.headline}</p>
      </div>

      {model.verdict && (
        <div className={`rounded border px-3 py-2 ${VERDICT_BOX[tone ?? 'warn'] ?? VERDICT_BOX.warn}`} data-testid="verdict">
          <div className="font-medium">{model.verdict.summary}</div>
          {model.verdict.reasons.length > 1 && (
            <ul className="mt-1 list-disc pl-5 text-xs opacity-80">
              {model.verdict.reasons.map((r) => <li key={r}>{r}</li>)}
            </ul>
          )}
        </div>
      )}

      {actions.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {actions.map((a) => (
            <button
              key={a.id}
              type="button"
              onClick={a.onClick}
              disabled={a.disabled}
              title={a.title}
              className={`rounded border px-2.5 py-1 text-xs disabled:opacity-40 ${a.primary
                ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20'
                : 'border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800'}`}
            >
              {a.label}
            </button>
          ))}
          {notice && <span className="text-xs text-emerald-300">{notice}</span>}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        {model.sections.map((s) => (
          <section key={s.id} className="rounded border border-zinc-800 bg-zinc-900/60 p-3" data-section={s.id}>
            <h3 className="mb-2 text-[10px] uppercase tracking-widest text-zinc-500">{s.title}</h3>
            {s.note && <p className="mb-2 text-xs text-zinc-300">{s.note}</p>}
            {s.rows.length > 0 && (
              <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-3 gap-y-1 text-xs">
                {s.rows.map((r) => (
                  <div key={r.label} className="contents">
                    <dt className="text-zinc-500">{r.label}</dt>
                    <dd className={`min-w-0 whitespace-pre-wrap break-words ${r.mono ? 'font-mono' : ''} ${r.tone ? TONE[r.tone] : 'text-zinc-200'}`}>{r.value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
        ))}
      </div>

      <section className="rounded border border-zinc-800 bg-zinc-900/60 p-3" data-section="history">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h3 className="mr-2 text-[10px] uppercase tracking-widest text-zinc-500">History</h3>
          {(['all', ...RELATIONS] as const).map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => onFilter(r)}
              disabled={r !== 'all' && counts[r] === 0}
              className={`rounded border px-2 py-0.5 text-[11px] disabled:opacity-30 ${filter === r
                ? 'border-zinc-500 bg-zinc-800 text-white'
                : 'border-zinc-800 text-zinc-400 hover:text-zinc-200'}`}
            >
              {r === 'all' ? 'All related' : RELATION_LABEL[r]} ({counts[r]})
            </button>
          ))}
        </div>
        {loadingHistory && <p className="text-xs text-zinc-500">Loading history…</p>}
        {historyError && <p className="text-xs text-amber-300">{historyError}</p>}
        <ol className="flex flex-col">
          {shown.map((item) => (
            <li key={item.event.id}>
              <button
                type="button"
                onClick={() => onSelect?.(item)}
                disabled={item.current || !onSelect}
                className={`flex w-full items-start gap-2 border-l-2 px-2 py-1 text-left text-xs ${item.current
                  ? 'border-emerald-500 bg-emerald-500/5'
                  : 'border-zinc-800 hover:bg-white/[0.03]'}`}
              >
                <span className="w-36 shrink-0 font-mono text-zinc-500">{fmt(item.at)}</span>
                <SeverityBadge severity={item.severity} />
                <span className="min-w-0 flex-1 break-words text-zinc-300">{item.summary}</span>
                <span className="shrink-0 text-[10px] text-zinc-500">
                  {item.current ? 'this event' : item.relations.join(' · ')}
                </span>
              </button>
            </li>
          ))}
          {!loadingHistory && shown.length <= 1 && (
            <li className="px-2 py-1 text-xs text-zinc-500">No other events share this address, key, host or rule in the loaded history.</li>
          )}
        </ol>
      </section>
    </div>
  );
}
