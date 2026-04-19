import { useEventStore } from '../stores/events'
import ModuleCard from '../components/ModuleCard'

export default function Modules() {
  const modules = useEventStore((s) => s.modules)

  const toggleModule = (name: string) => {
    useEventStore.setState((state) => ({
      modules: state.modules.map((m) =>
        m.name === name
          ? { ...m, status: m.status === 'running' ? 'stopped' : 'running' }
          : m
      )
    }))
  }

  const runningCount = modules.filter((m) => m.status === 'running').length

  return (
    <div className="flex flex-col h-full p-4 gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-text">Security Modules</h2>
          <p className="text-[11px] text-dim mt-0.5">
            {runningCount}/{modules.length} modules active
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() =>
              useEventStore.setState((s) => ({
                modules: s.modules.map((m) => ({ ...m, status: 'running' }))
              }))
            }
            className="px-3 py-1 text-[10px] font-bold text-primary border border-primary/30 rounded hover:bg-primary/10 transition-colors"
          >
            START ALL
          </button>
          <button
            onClick={() =>
              useEventStore.setState((s) => ({
                modules: s.modules.map((m) => ({ ...m, status: 'stopped' }))
              }))
            }
            className="px-3 py-1 text-[10px] font-bold text-threat border border-threat/30 rounded hover:bg-threat/10 transition-colors"
          >
            STOP ALL
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-3 gap-3 overflow-y-auto">
        {modules.map((mod) => (
          <ModuleCard
            key={mod.name}
            module={mod}
            onToggle={() => toggleModule(mod.name)}
          />
        ))}
      </div>
    </div>
  )
}
