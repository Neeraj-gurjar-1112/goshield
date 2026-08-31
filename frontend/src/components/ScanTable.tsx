import { Link } from 'react-router-dom'
import { RiskBadge, StatusBadge } from './RiskBadge'
import { formatTime } from '../lib/format'
import type { PaginationMeta, Scan } from '../types/scan'

interface ScanTableProps {
  scans: Scan[]
}

/** ScanTable lists scans, newest first. */
export function ScanTable({ scans }: ScanTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead>
          <tr className="border-b border-slate-800 text-xs uppercase tracking-wide text-slate-500">
            <th className="px-3 py-2 font-medium">URL</th>
            <th className="px-3 py-2 font-medium">Risk</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-3 py-2 font-medium">Scanned</th>
            <th className="px-3 py-2 font-medium text-right">Time</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="border-b border-slate-800/60 transition hover:bg-slate-800/30"
            >
              <td className="max-w-[320px] px-3 py-2.5">
                <span className="block truncate font-mono text-slate-200" title={scan.url}>
                  {scan.url}
                </span>
                <span className="text-xs text-slate-500">{scan.domain}</span>
              </td>
              <td className="px-3 py-2.5">
                <RiskBadge level={scan.risk_level} score={scan.risk_score} />
              </td>
              <td className="px-3 py-2.5">
                <StatusBadge status={scan.status} />
              </td>
              <td className="whitespace-nowrap px-3 py-2.5 text-xs text-slate-400">
                {formatTime(scan.created_at)}
                {scan.cached && <span className="ml-2 text-sky-400">cached</span>}
              </td>
              <td className="whitespace-nowrap px-3 py-2.5 text-right font-mono text-xs text-slate-400">
                {scan.scan_time_ms} ms
              </td>
              <td className="px-3 py-2.5 text-right">
                <Link
                  to={`/scans/${scan.id}`}
                  className="text-xs font-medium text-emerald-400 transition hover:text-emerald-300"
                >
                  View
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

interface PaginationProps {
  pagination: PaginationMeta
  onPageChange: (page: number) => void
}

/** Pagination steps through pages of scan history. */
export function Pagination({ pagination, onPageChange }: PaginationProps) {
  const { page, limit, total, total_pages: totalPages } = pagination

  const first = total === 0 ? 0 : (page - 1) * limit + 1
  const last = Math.min(page * limit, total)

  return (
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400">
      <span>
        {total === 0 ? 'No scans' : `Showing ${first}–${last} of ${total}`}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          className="rounded-md border border-slate-700 px-3 py-1.5 font-medium transition hover:border-slate-600 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Previous
        </button>
        <span className="font-mono">
          {page} / {Math.max(totalPages, 1)}
        </span>
        <button
          type="button"
          disabled={totalPages === 0 || page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          className="rounded-md border border-slate-700 px-3 py-1.5 font-medium transition hover:border-slate-600 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}
