import AttackMap from '../components/AttackMap'
import EventStream from '../components/EventStream'
import ThreatMap from '../components/ThreatMap'

export default function Dashboard() {
  return (
    <div className="flex h-full">
      {/* Center: live attack map over the event stream */}
      <div className="flex-1 min-w-0 flex flex-col border-r border-border">
        <AttackMap />
        <div className="flex-1 min-h-0">
          <EventStream />
        </div>
      </div>

      {/* Right: Threat Sources */}
      <div className="w-72 shrink-0">
        <ThreatMap />
      </div>
    </div>
  )
}
