import { Link } from 'react-router-dom'
import { RiskBadge, ScoreBar, StatusBadge } from './RiskBadge'
import { formatTime } from '../lib/format'
import type { Scan } from '../types/scan'

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 break-all font-mono text-sm text-slate-200">{value}</dd>
    </div>
  )
}

interface ScanResultProps {
  scan: Scan
  showLink?: boolean
}

/** ScanResult renders one scan verdict in full. */
export function ScanResult({ scan, showLink = true }: ScanResultProps) {
  return (
    <article className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="break-all font-mono text-sm text-slate-100">{scan.url}</p>
          <p className="mt-1 text-xs text-slate-500">
            {formatTime(scan.created_at)} · {scan.scan_time_ms} ms
            {scan.cached && (
              <span className="ml-2 rounded bg-sky-500/15 px-1.5 py-0.5 text-sky-300">cached</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <RiskBadge level={scan.risk_level} score={scan.risk_score} />
          <StatusBadge status={scan.status} />
        </div>
      </div>

      <div className="mt-4">
        <div className="mb-1 flex justify-between text-xs text-slate-500">
          <span>Risk score</span>
          <span className="font-mono text-slate-300">{scan.risk_score}/100</span>
        </div>
        <ScoreBar score={scan.risk_score} />
      </div>

      <dl className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Field label="Domain" value={scan.domain} />
        <Field label="Protocol" value={scan.protocol} />
        <Field label="Verdict" value={scan.safe ? 'safe' : 'not safe'} />
        <div className="sm:col-span-3">
          <Field label="Normalized URL" value={scan.normalized_url} />
        </div>
      </dl>

      <div className="mt-5">
        <h3 className="text-xs uppercase tracking-wide text-slate-500">
          Reasons ({scan.reasons.length})
        </h3>
        {scan.reasons.length === 0 ? (
          <p className="mt-2 text-sm text-emerald-300">No suspicious signals found.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {scan.reasons.map((reason) => (
              <li key={reason} className="flex gap-2 text-sm text-slate-300">
                <span aria-hidden className="text-amber-400">
                  ▸
                </span>
                {reason}
              </li>
            ))}
          </ul>
        )}
      </div>

      {showLink && (
        <Link
          to={`/scans/${scan.id}`}
          className="mt-5 inline-block text-xs font-medium text-emerald-400 transition hover:text-emerald-300"
        >
          Open scan details →
        </Link>
      )}
    </article>
  )
}
