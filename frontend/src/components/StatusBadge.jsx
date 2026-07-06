const COLORS = {
  open: "bg-[var(--color-status-open)]/15 text-[var(--color-status-open)] ring-[var(--color-status-open)]/30",
  investigating: "bg-[var(--color-status-investigating)]/15 text-[var(--color-status-investigating)] ring-[var(--color-status-investigating)]/30",
  resolved: "bg-[var(--color-status-resolved)]/15 text-[var(--color-status-resolved)] ring-[var(--color-status-resolved)]/30",
  false_positive: "bg-[var(--color-status-false_positive)]/15 text-[var(--color-status-false_positive)] ring-[var(--color-status-false_positive)]/30",
}

export default function StatusBadge({ status }) {
  const cls = COLORS[status] || COLORS.open
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${cls}`}>
      {status.replace("_", " ")}
    </span>
  )
}
