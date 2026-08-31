import { useState } from 'react'
import { Pagination, ScanTable } from '../components/ScanTable'
import { Card, EmptyState, ErrorState, Loading } from '../components/States'
import { useScans } from '../hooks/useScans'
import { RISK_LEVELS, SCAN_STATUSES } from '../types/scan'
import type { RiskLevel, ScanStatus } from '../types/scan'

const PAGE_SIZES = [10, 20, 50, 100]

/** HistoryPage lists scan history with filters and paging. */
export function HistoryPage() {
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(20)
  const [riskLevel, setRiskLevel] = useState<RiskLevel | ''>('')
  const [status, setStatus] = useState<ScanStatus | ''>('')
  const [domainInput, setDomainInput] = useState('')
  const [domain, setDomain] = useState('')

  const { data, loading, error, reload } = useScans({
    page,
    limit,
    risk_level: riskLevel,
    status,
    domain,
  })

  /** Any filter change resets to the first page. */
  function update<T>(setter: (value: T) => void) {
    return (value: T) => {
      setter(value)
      setPage(1)
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Scan history</h1>
        <p className="mt-1 text-sm text-slate-500">Every scan, newest first.</p>
      </header>

      <Card title="Filters">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="text-xs text-slate-400">
            Risk level
            <select
              value={riskLevel}
              onChange={(e) => update(setRiskLevel)(e.target.value as RiskLevel | '')}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500/60"
            >
              <option value="">Any</option>
              {RISK_LEVELS.map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </select>
          </label>

          <label className="text-xs text-slate-400">
            Status
            <select
              value={status}
              onChange={(e) => update(setStatus)(e.target.value as ScanStatus | '')}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500/60"
            >
              <option value="">Any</option>
              {SCAN_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>

          <label className="text-xs text-slate-400">
            Domain
            <form
              onSubmit={(e) => {
                e.preventDefault()
                update(setDomain)(domainInput.trim())
              }}
            >
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onBlur={() => update(setDomain)(domainInput.trim())}
                placeholder="example.com"
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950/60 px-3 py-2 font-mono text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-emerald-500/60"
              />
            </form>
          </label>

          <label className="text-xs text-slate-400">
            Page size
            <select
              value={limit}
              onChange={(e) => update(setLimit)(Number(e.target.value))}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 outline-none focus:border-emerald-500/60"
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size} per page
                </option>
              ))}
            </select>
          </label>
        </div>

        {(riskLevel || status || domain) && (
          <button
            type="button"
            onClick={() => {
              setRiskLevel('')
              setStatus('')
              setDomain('')
              setDomainInput('')
              setPage(1)
            }}
            className="mt-3 text-xs font-medium text-emerald-400 transition hover:text-emerald-300"
          >
            Clear filters
          </button>
        )}
      </Card>

      <Card>
        {error ? (
          <ErrorState message={error} onRetry={reload} />
        ) : loading && !data ? (
          <Loading label="Loading scans…" />
        ) : !data || data.data.length === 0 ? (
          <EmptyState message="No scans match these filters." />
        ) : (
          <>
            <ScanTable scans={data.data} />
            <Pagination pagination={data.pagination} onPageChange={setPage} />
          </>
        )}
      </Card>
    </div>
  )
}
