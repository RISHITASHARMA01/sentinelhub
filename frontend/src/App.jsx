import { Routes, Route } from "react-router-dom"
import Sidebar from "./components/Sidebar"
import Overview from "./pages/Overview"
import Alerts from "./pages/Alerts"
import Logs from "./pages/Logs"

function App() {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/logs" element={<Logs />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
