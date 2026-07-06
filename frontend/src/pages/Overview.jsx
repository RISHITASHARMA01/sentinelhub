import { useEffect, useState } from "react"
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts"
import StatCard from "../components/StatCard"
import { getLogsSummary, getLogsTimeseries, getAlertsSummary, getAlertsTimeseries } from "../api/client"

const SEVERITY_COLORS = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#facc15",
  low: "#60a5fa",
}

// Both timeseries endpoints return [{bucket, count}], one row per hour that
// actually had data. We zip them into a single [{bucket, events, alerts}]
// array so one chart can show both lines against a shared x-axis, filling
// in 0 for whichever side is missing a given hour.
function mergeTimeseries(events, alerts) {
  const byBucket = new Map()
  for (const row of events) byBucket.set(row.bucket, { bucket: row.bucket, events: row.count, alerts: 0 })
  for (const row of alerts) {
    const existing = byBucket.get(row.bucket)
    if (existing) existing.alerts = row.count
    else byBucket.set(row.bucket, { bucket: row.bucket, events: 0, alerts: row.count })
  }
  return Array.from(byBucket.values()).sort((a, b) => a.bucket.localeCompare(b.bucket))
}

function formatBucketLabel(bucket) {
  const d = new Date(bucket)
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" })
}

export default function Overview() {
  const [logsSummary, setLogsSummary] = useState(null)
  const [alertsSummary, setAlertsSummary] = useState(null)
  const [series, setSeries] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    Promise.all([getLogsSummary(), getAlertsSummary(), getLogsTimeseries(), getAlertsTimeseries()])
      .then(([ls, as, lt, at]) => {
        setLogsSummary(ls)
        setAlertsSummary(as)
        setSeries(mergeTimeseries(lt, at))
      })
      .catch((err) => setError(err.message))
  }, [])

  if (error) {
    return <div className="text-[var(--color-sev-critical)]">Failed to load dashboard data: {error}</div>
  }

  const severityData = Object.entries(alertsSummary?.by_severity || {}).map(([name, value]) => ({ name, value }))

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-xl font-semibold">Overview</h1>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Events" value={logsSummary?.total_events ?? "—"} />
        <StatCard
          label="Open Alerts"
          value={alertsSummary?.open_alerts ?? "—"}
          accent={alertsSummary?.open_alerts ? "var(--color-sev-critical)" : undefined}
        />
        <StatCard label="Unique Attacker IPs" value={alertsSummary?.unique_attacker_ips ?? "—"} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
          <h2 className="mb-4 text-sm font-semibold text-[var(--color-text-muted)]">Events &amp; Alerts Over Time</h2>
          {series.length === 0 ? (
            <EmptyState message="No events yet — ingest some logs to see activity here." />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={series}>
                <defs>
                  <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="alertsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f87171" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#232b36" />
                <XAxis dataKey="bucket" tickFormatter={formatBucketLabel} stroke="#8b96a5" fontSize={12} />
                <YAxis stroke="#8b96a5" fontSize={12} allowDecimals={false} />
                <Tooltip
                  labelFormatter={formatBucketLabel}
                  contentStyle={{ background: "#161c25", border: "1px solid #232b36", borderRadius: 8 }}
                />
                <Area type="monotone" dataKey="events" name="Log Events" stroke="#22d3ee" fill="url(#eventsGradient)" />
                <Area type="monotone" dataKey="alerts" name="Alerts" stroke="#f87171" fill="url(#alertsGradient)" />
                <Legend />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
          <h2 className="mb-4 text-sm font-semibold text-[var(--color-text-muted)]">Alerts by Severity</h2>
          {severityData.length === 0 ? (
            <EmptyState message="No alerts yet — run detection to populate this." />
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || "#8b96a5"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#161c25", border: "1px solid #232b36", borderRadius: 8 }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}

function EmptyState({ message }) {
  return (
    <div className="flex h-[280px] items-center justify-center text-sm text-[var(--color-text-muted)]">
      {message}
    </div>
  )
}
