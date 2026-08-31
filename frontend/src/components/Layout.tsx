import { NavLink, Outlet } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: '▦' },
  { to: '/scan', label: 'Scan URL', icon: '⌕' },
  { to: '/scans', label: 'History', icon: '☰' },
  { to: '/analytics', label: 'Analytics', icon: '▲' },
]

/** Navbar is the fixed top bar. */
function Navbar() {
  return (
    <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-900/80 backdrop-blur">
      <div className="flex h-14 items-center gap-3 px-4 sm:px-6">
        <span className="text-lg font-bold tracking-tight text-slate-100">
          Go<span className="text-emerald-400">Shield</span>
        </span>
        <span className="hidden text-xs text-slate-500 sm:inline">
          offline URL security scanner
        </span>
        <a
          href={`${(import.meta.env.VITE_API_URL ?? 'http://localhost:8080/api/v1').replace(/\/api\/v1\/?$/, '')}/swagger/index.html`}
          target="_blank"
          rel="noreferrer"
          className="ml-auto rounded-md border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-slate-600 hover:text-slate-100"
        >
          API docs
        </a>
      </div>
    </header>
  )
}

/** Sidebar holds the primary navigation. */
function Sidebar() {
  return (
    <aside className="border-b border-slate-800 md:w-56 md:shrink-0 md:border-b-0 md:border-r">
      <nav className="flex gap-1 overflow-x-auto p-3 md:flex-col md:overflow-visible">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-2 whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition ${
                isActive
                  ? 'bg-emerald-500/10 text-emerald-300'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`
            }
          >
            <span aria-hidden className="text-xs">
              {item.icon}
            </span>
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}

/** Layout wraps every page with the navbar and sidebar. */
export function Layout() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <Navbar />
      <div className="flex flex-col md:flex-row">
        <Sidebar />
        <main className="min-w-0 flex-1 p-4 sm:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
