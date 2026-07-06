import { useEffect, useState } from "react"
import { getLogs } from "../api/client"

const PAGE_SIZE = 50

export default function Logs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [q, setQ] = useState("")
  const [srcIp, setSrcIp] = useState("")
  const [eventType, setEventType] = useState("")
  const [page, setPage] = useState(0)

  useEffect(() => {
    setLoading(true)
    getLogs({
      q: q || undefined,
      src_ip: srcIp || undefined,
      event_type: eventType || undefined,
      limit: PAGE_SIZE,
      offset: page * PAGE_SIZE,
    })
      .then(setLogs)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [q, srcIp, eventType, page])

  // Any filter change resets to page 0 -- otherwise you can land on an
  // empty page 3 of a now-much-smaller filtered result set.
  const updateFilter = (setter) => (value) => {
    setter(value)
    setPage(0)
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold">Logs</h1>

      <div className="flex flex-wrap gap-3">
        <input
          value={q}
          onChange={(e) => updateFilter(setQ)(e.target.value)}
          placeholder="Search raw log text..."
          className="w-64 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm placeholder:text-[var(--color-text-muted)]"
        />
        <input
          value={srcIp}
          onChange={(e) => updateFilter(setSrcIp)(e.target.value)}
          placeholder="Filter by source IP..."
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm mono placeholder:text-[var(--color-text-muted)]"
        />
        <select
          value={eventType}
          onChange={(e) => updateFilter(setEventType)(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm"
        >
          <option value="">All event types</option>
          <option value="auth_failure">auth_failure</option>
          <option value="auth_success">auth_success</option>
          <option value="http_request">http_request</option>
        </select>
      </div>

      {error && <div className="text-[var(--color-sev-critical)]">Failed to load logs: {error}</div>}

      <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
        <table className="w-full text-left text-sm">
          <thead className="bg-[var(--color-panel-raised)] text-[var(--color-text-muted)]">
            <tr>
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Src IP</th>
              <th className="px-4 py-2 font-medium">User</th>
              <th className="px-4 py-2 font-medium">Raw Message</th>
            </tr>
          </thead>
          <tbody>
            {!loading && logs.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-6 text-center text-[var(--color-text-muted)]">
                  No log events match these filters.
                </td>
              </tr>
            )}
            {logs.map((log) => (
              <tr key={log.id} className="border-t border-[var(--color-border)] bg-[var(--color-panel)]">
                <td className="whitespace-nowrap px-4 py-2 mono text-[var(--color-text-muted)]">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-2">{log.source}</td>
                <td className="px-4 py-2">{log.event_type || "—"}</td>
                <td className="px-4 py-2 mono">{log.src_ip || "—"}</td>
                <td className="px-4 py-2">{log.username || "—"}</td>
                <td className="max-w-md truncate px-4 py-2 mono text-[var(--color-text-muted)]" title={log.raw_message}>
                  {log.raw_message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center gap-3 text-sm">
        <button
          disabled={page === 0}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          className="rounded-md border border-[var(--color-border)] px-3 py-1 disabled:opacity-40"
        >
          Previous
        </button>
        <span className="text-[var(--color-text-muted)]">Page {page + 1}</span>
        <button
          disabled={logs.length < PAGE_SIZE}
          onClick={() => setPage((p) => p + 1)}
          className="rounded-md border border-[var(--color-border)] px-3 py-1 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}
