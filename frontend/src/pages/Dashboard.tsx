import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ScanForm } from '../components/ScanForm'
import { ScanResult } from '../components/ScanResult'
import { ScanTable } from '../components/ScanTable'
import { StatCard, StatCards } from '../components/StatCards'
import { Card, EmptyState, ErrorState, Loading } from '../components/States'
import { useMetrics } from '../hooks/useMetrics'
import { useScans } from '../hooks/useScans'
import type { Scan } from '../types/scan'

/** Dashboard is the landing page: stats, a scan box and the latest scans. */
export function Dashboard() {
  const [latest, setLatest] = useState<Scan | null>(null)
  const { metrics, loading: metricsLoading, error: metricsError, reload: reloadMetrics } =
    useMetrics()
  const { data, loading, error, reload } = useScans({ page: 1, limit: 8 })

  function onScanned(scan: Scan) {
    setLatest(scan)
    reload()
    reloadMetrics()
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">
          Live view of everything GoShield has scanned.
        </p>
      </header>

      {metricsError ? (
        <ErrorState message={metricsError} onRetry={reloadMetrics} />
      ) : metricsLoading && !metrics ? (
        <Loading label="Loading metrics…" />
      ) : (
        <>
          <StatCards metrics={metrics} historyTotal={data?.pagination.total ?? 0} />
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatCard label="Scans this uptime" value={metrics?.scans_total ?? '—'} />
            <StatCard
              label="Avg scan time"
              value={metrics ? `${metrics.scan_duration_ms_avg} ms` : '—'}
            />
          </div>
        </>
      )}

      <Card title="Quick scan">
        <ScanForm onScanned={onScanned} />
      </Card>

      {latest && <ScanResult scan={latest} />}

      <Card
        title="Recent scans"
        action={
          <Link
            to="/scans"
            className="text-xs font-medium text-emerald-400 transition hover:text-emerald-300"
          >
            View all →
          </Link>
        }
      >
        {error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : loading && !data ? (
          <Loading label="Loading scans…" />
        ) : !data || data.data.length === 0 ? (
          <EmptyState message="No scans yet. Scan a URL above to get started." />
        ) : (
          <ScanTable scans={data.data} />
        )}
      </Card>
    </div>
  )
}
