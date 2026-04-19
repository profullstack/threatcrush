import { Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import StatsBar from './components/StatsBar'
import Dashboard from './pages/Dashboard'
import Monitor from './pages/Monitor'
import Modules from './pages/Modules'
import Settings from './pages/Settings'

export default function App() {
  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <div className="flex-1 overflow-hidden">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/monitor" element={<Monitor />} />
            <Route path="/modules" element={<Modules />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
        <StatsBar />
      </div>
    </div>
  )
}
