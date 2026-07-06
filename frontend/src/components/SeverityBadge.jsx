const COLORS = {
  critical: "bg-[var(--color-sev-critical)]/15 text-[var(--color-sev-critical)] ring-[var(--color-sev-critical)]/30",
  high: "bg-[var(--color-sev-high)]/15 text-[var(--color-sev-high)] ring-[var(--color-sev-high)]/30",
  medium: "bg-[var(--color-sev-medium)]/15 text-[var(--color-sev-medium)] ring-[var(--color-sev-medium)]/30",
  low: "bg-[var(--color-sev-low)]/15 text-[var(--color-sev-low)] ring-[var(--color-sev-low)]/30",
}

export default function SeverityBadge({ severity }) {
  const cls = COLORS[severity] || COLORS.low
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ring-1 ${cls}`}>
      {severity}
    </span>
  )
}
