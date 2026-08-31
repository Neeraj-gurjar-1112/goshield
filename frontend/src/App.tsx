import { Suspense, lazy } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Loading } from './components/States'
import { Dashboard } from './pages/Dashboard'
import { HistoryPage } from './pages/HistoryPage'
import { ScanDetailsPage } from './pages/ScanDetailsPage'
import { ScanPage } from './pages/ScanPage'

// Recharts is the heaviest dependency in the app and only analytics needs it,
// so that page loads on demand.
const AnalyticsPage = lazy(() =>
  import('./pages/AnalyticsPage').then((m) => ({ default: m.AnalyticsPage })),
)

function NotFound() {
  return (
    <div className="mx-auto max-w-md text-center">
      <p className="text-4xl font-bold text-slate-700">404</p>
      <p className="mt-2 text-sm text-slate-400">That page does not exist.</p>
      <Link
        to="/"
        className="mt-4 inline-block text-sm font-medium text-emerald-400 transition hover:text-emerald-300"
      >
        Back to the dashboard
      </Link>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/scans" element={<HistoryPage />} />
        <Route path="/scans/:id" element={<ScanDetailsPage />} />
        <Route
          path="/analytics"
          element={
            <Suspense fallback={<Loading label="Loading charts…" />}>
              <AnalyticsPage />
            </Suspense>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
