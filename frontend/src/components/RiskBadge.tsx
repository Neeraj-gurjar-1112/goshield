import type { RiskLevel, ScanStatus } from '../types/scan'

const RISK_STYLES: Record<RiskLevel, string> = {
  SAFE: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
  LOW: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  HIGH: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
}

const STATUS_STYLES: Record<ScanStatus, string> = {
  SAFE: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
  SUSPICIOUS: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  BLOCKED: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
}

interface RiskBadgeProps {
  level: RiskLevel
  score?: number
}

/** RiskBadge shows a risk level, optionally with its score. */
export function RiskBadge({ level, score }: RiskBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${RISK_STYLES[level]}`}
    >
      {level}
      {score !== undefined && <span className="opacity-70">{score}</span>}
    </span>
  )
}

/** StatusBadge shows the scan verdict. */
export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ring-1 ring-inset ${STATUS_STYLES[status]}`}
    >
      {status}
    </span>
  )
}

/** ScoreBar draws the risk score as a 0-100 meter. */
export function ScoreBar({ score }: { score: number }) {
  const clamped = Math.max(0, Math.min(100, score))
  const color =
    clamped <= 20
      ? 'bg-emerald-400'
      : clamped <= 50
        ? 'bg-sky-400'
        : clamped <= 75
          ? 'bg-amber-400'
          : 'bg-rose-400'

  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-700/60">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${clamped}%` }} />
    </div>
  )
}
