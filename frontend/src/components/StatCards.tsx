import type { Metrics } from '../types/scan'

interface StatCardProps {
  label: string
  value: string | number
  hint?: string
  accent?: 'default' | 'safe' | 'danger' | 'info'
}

const ACCENTS: Record<NonNullable<StatCardProps['accent']>, string> = {
  default: 'text-slate-100',
  safe: 'text-emerald-300',
  danger: 'text-rose-300',
  info: 'text-sky-300',
}

/** StatCard is one headline number. */
export function StatCard({ label, value, hint, accent = 'default' }: StatCardProps) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-2 text-2xl font-semibold tabular-nums ${ACCENTS[accent]}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

interface StatCardsProps {
  metrics: Metrics | null
  historyTotal: number
}

/**
 * StatCards summarises the service. Counters come from /metrics and reset when
 * the process restarts, so the stored total comes from /scans instead.
 */
export function StatCards({ metrics, historyTotal }: StatCardsProps) {
  const cacheRate =
    metrics && metrics.scans_total > 0
      ? `${Math.round((metrics.cache_hits_total / metrics.scans_total) * 100)}%`
      : '—'

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatCard label="Scans stored" value={historyTotal} hint="rows in PostgreSQL" />
      <StatCard
        label="Safe"
        value={metrics?.scans_safe_total ?? '—'}
        hint="score 50 or below"
        accent="safe"
      />
      <StatCard
        label="Blocked"
        value={metrics?.scans_blocked_total ?? '—'}
        hint="score 76 or above"
        accent="danger"
      />
      <StatCard
        label="Cache hit rate"
        value={cacheRate}
        hint={metrics ? `${metrics.cache_hits_total} hits this uptime` : 'metrics unavailable'}
        accent="info"
      />
    </div>
  )
}
