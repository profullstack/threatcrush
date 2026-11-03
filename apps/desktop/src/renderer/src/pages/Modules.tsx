import { useEventStore } from '../stores/events'
import ModuleCard from '../components/ModuleCard'

// The modules loaded in this machine's threatcrushd, as it reports them.
// Starting and stopping modules is done in the daemon's config, not here.
export default function Modules() {
  const modules = useEventStore((s) => s.modules)
  const local = useEventStore((s) => s.local)
  const reconnect = useEventStore((s) => s.reconnectLocal)

  const active = modules.filter((m) => m.status === 'running' || m.status === 'loaded').length

  return (
    <div className="flex flex-col h-full p-4 gap-4">
      <div>
        <h2 className="text-lg font-bold text-text">Security Modules</h2>
        <p className="text-[11px] text-dim mt-0.5">
          {local.state === 'connected'
            ? `${active}/${modules.length} modules active in threatcrushd on this machine`
            : 'Modules running in threatcrushd on this machine'}
        </p>
      </div>

      {local.state !== 'connected' ? (
        <div className="bg-card border border-border rounded-lg p-4 text-[11px] text-dim max-w-xl">
          <p className="text-text mb-2">No threatcrushd running on this machine.</p>
          <p>
            Install and start it with <code className="text-primary">threatcrush start</code>, then
            reconnect. {local.state === 'offline' && local.error ? `(${local.error})` : ''}
          </p>
          <button
            onClick={() => void reconnect()}
            className="mt-3 px-3 py-1 text-[10px] font-bold text-primary border border-primary/30 rounded hover:bg-primary/10"
          >
            RECONNECT
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-2 xl:grid-cols-3 gap-3 overflow-y-auto">
          {modules.map((mod) => (
            <ModuleCard key={mod.name} module={mod} />
          ))}
        </div>
      )}
    </div>
  )
}
