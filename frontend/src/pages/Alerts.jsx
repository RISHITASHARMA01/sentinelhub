import { useEffect, useMemo, useState } from "react"
import SeverityBadge from "../components/SeverityBadge"
import StatusBadge from "../components/StatusBadge"
import { getAlerts, updateAlertStatus, enrichAlert } from "../api/client"

const STATUSES = ["open", "investigating", "resolved", "false_positive"]
const SEVERITIES = ["critical", "high", "medium", "low"]

const COLUMNS = [
  { key: "created_at", label: "Time" },
  { key: "severity", label: "Severity" },
  { key: "rule_name", label: "Rule" },
  { key: "mitre_technique_id", label: "MITRE" },
  { key: "src_ip", label: "Source IP" },
  { key: "status", label: "Status" },
]

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expandedId, setExpandedId] = useState(null)

  const [severity, setSeverity] = useState("")
  const [status, setStatus] = useState("")
  const [srcIp, setSrcIp] = useState("")
  const [sort, setSort] = useState({ key: "created_at", dir: "desc" })

  const fetchAlerts = () => {
    setLoading(true)
    getAlerts({
      severity: severity || undefined,
      status: status || undefined,
      src_ip: srcIp || undefined,
      limit: 200,
    })
      .then(setAlerts)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }

  // Filters hit the API (server-side), so this stays fast even once there
  // are thousands of alerts. Sorting is done client-side over whatever page
  // of results we already have -- no need to round-trip for that.
  useEffect(fetchAlerts, [severity, status, srcIp])

  const sortedAlerts = useMemo(() => {
    const sorted = [...alerts].sort((a, b) => {
      const av = a[sort.key] ?? ""
      const bv = b[sort.key] ?? ""
      if (av < bv) return sort.dir === "asc" ? -1 : 1
      if (av > bv) return sort.dir === "asc" ? 1 : -1
      return 0
    })
    return sorted
  }, [alerts, sort])

  const toggleSort = (key) => {
    setSort((prev) =>
      prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }
    )
  }

  const handleStatusChange = async (alert, newStatus) => {
    const updated = await updateAlertStatus(alert.id, newStatus)
    setAlerts((prev) => prev.map((a) => (a.id === alert.id ? updated : a)))
  }

  const handleEnrich = async (alert) => {
    const result = await enrichAlert(alert.id)
    setAlerts((prev) => prev.map((a) => (a.id === alert.id ? result.alert : a)))
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-xl font-semibold">Alerts</h1>

      <div className="flex flex-wrap gap-3">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm"
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace("_", " ")}</option>
          ))}
        </select>
        <input
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          placeholder="Filter by source IP..."
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm mono placeholder:text-[var(--color-text-muted)]"
        />
      </div>

      {error && <div className="text-[var(--color-sev-critical)]">Failed to load alerts: {error}</div>}

      <div className="overflow-x-auto rounded-lg border border-[var(--color-border)]">
        <table className="w-full text-left text-sm">
          <thead className="bg-[var(--color-panel-raised)] text-[var(--color-text-muted)]">
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  onClick={() => toggleSort(col.key)}
                  className="cursor-pointer select-none px-4 py-2 font-medium hover:text-[var(--color-text)]"
                >
                  {col.label}
                  {sort.key === col.key && (sort.dir === "asc" ? " ▲" : " ▼")}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {!loading && sortedAlerts.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length} className="px-4 py-6 text-center text-[var(--color-text-muted)]">
                  No alerts match these filters.
                </td>
              </tr>
            )}
            {sortedAlerts.map((alert) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                expanded={expandedId === alert.id}
                onToggle={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
                onStatusChange={handleStatusChange}
                onEnrich={handleEnrich}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AlertRow({ alert, expanded, onToggle, onStatusChange, onEnrich }) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer border-t border-[var(--color-border)] bg-[var(--color-panel)] hover:bg-[var(--color-panel-raised)]"
      >
        <td className="px-4 py-2.5 mono text-[var(--color-text-muted)]">
          {new Date(alert.created_at).toLocaleString()}
        </td>
        <td className="px-4 py-2.5"><SeverityBadge severity={alert.severity} /></td>
        <td className="px-4 py-2.5">{alert.rule_name.replace(/_/g, " ")}</td>
        <td className="px-4 py-2.5 mono text-[var(--color-accent)]">{alert.mitre_technique_id}</td>
        <td className="px-4 py-2.5 mono">{alert.src_ip || "—"}</td>
        <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
          <select
            value={alert.status}
            onChange={(e) => onStatusChange(alert, e.target.value)}
            className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-2 py-1 text-xs"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s.replace("_", " ")}</option>
            ))}
          </select>
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-[var(--color-border)] bg-[var(--color-bg)]">
          <td colSpan={COLUMNS.length} className="px-4 py-4">
            <AlertDetail alert={alert} onEnrich={onEnrich} />
          </td>
        </tr>
      )}
    </>
  )
}

function AlertDetail({ alert, onEnrich }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase text-[var(--color-text-muted)]">Description</h3>
        <p className="text-sm">{alert.description}</p>
        <h3 className="mt-3 mb-1 text-xs font-semibold uppercase text-[var(--color-text-muted)]">MITRE ATT&amp;CK</h3>
        <p className="text-sm mono">
          {alert.mitre_technique_id} — {alert.mitre_technique_name}
        </p>
      </div>

      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase text-[var(--color-text-muted)]">Triggering Log Event</h3>
        {alert.triggering_event ? (
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-3 text-xs">
            <div className="mono break-all text-[var(--color-text)]">{alert.triggering_event.raw_message}</div>
            <dl className="mt-2 grid grid-cols-2 gap-1 text-[var(--color-text-muted)]">
              <dt>Source</dt><dd>{alert.triggering_event.source}</dd>
              <dt>Event type</dt><dd>{alert.triggering_event.event_type}</dd>
              <dt>Username</dt><dd>{alert.triggering_event.username || "—"}</dd>
              <dt>Timestamp</dt><dd>{new Date(alert.triggering_event.timestamp).toLocaleString()}</dd>
            </dl>
          </div>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">No linked log event.</p>
        )}
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase text-[var(--color-text-muted)]">Threat Intel</h3>
          <button
            onClick={() => onEnrich(alert)}
            className="rounded-md border border-[var(--color-border)] px-2 py-0.5 text-xs text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10"
          >
            Re-enrich
          </button>
        </div>
        {alert.enrichment ? (
          <dl className="grid grid-cols-2 gap-1 text-xs">
            <dt className="text-[var(--color-text-muted)]">Abuse score</dt>
            <dd className={alert.enrichment.abuse_score > 50 ? "text-[var(--color-sev-critical)]" : ""}>
              {alert.enrichment.abuse_score}/100
            </dd>
            <dt className="text-[var(--color-text-muted)]">Country</dt><dd>{alert.enrichment.country || "—"}</dd>
            <dt className="text-[var(--color-text-muted)]">ISP</dt><dd>{alert.enrichment.isp || "—"}</dd>
            <dt className="text-[var(--color-text-muted)]">Total reports</dt><dd>{alert.enrichment.total_reports ?? "—"}</dd>
          </dl>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            No enrichment data yet — set <span className="mono">ABUSEIPDB_API_KEY</span> or click Re-enrich.
          </p>
        )}
      </div>
    </div>
  )
}
