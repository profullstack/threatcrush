import EventStream from '../components/EventStream'
import ThreatMap from '../components/ThreatMap'

export default function Dashboard() {
  return (
    <div className="flex h-full">
      {/* Center: Event Stream */}
      <div className="flex-1 min-w-0 border-r border-border">
        <EventStream />
      </div>

      {/* Right: Threat Sources */}
      <div className="w-72 shrink-0">
        <ThreatMap />
      </div>
    </div>
  )
}
