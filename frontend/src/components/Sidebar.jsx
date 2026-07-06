import { NavLink } from "react-router-dom"

const links = [
  { to: "/", label: "Overview", end: true },
  { to: "/alerts", label: "Alerts" },
  { to: "/logs", label: "Logs" },
]

export default function Sidebar() {
  return (
    <aside className="w-56 shrink-0 border-r border-[var(--color-border)] bg-[var(--color-panel)] p-4 flex flex-col">
      <div className="mb-8 px-2">
        <div className="text-lg font-bold text-[var(--color-accent)] mono">SentinelHub</div>
        <div className="text-xs text-[var(--color-text-muted)]">Security Operations Center</div>
      </div>
      <nav className="flex flex-col gap-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            className={({ isActive }) =>
              `rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                  : "text-[var(--color-text-muted)] hover:bg-white/5 hover:text-[var(--color-text)]"
              }`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
