export default function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
      <div className="text-xs uppercase tracking-wide text-[var(--color-text-muted)]">{label}</div>
      <div
        className="mt-2 text-3xl font-semibold mono"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
    </div>
  )
}
