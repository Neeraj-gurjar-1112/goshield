import { useMemo } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Card, EmptyState, ErrorState, Loading } from '../components/States'
import { useScans } from '../hooks/useScans'
import { RISK_LEVELS } from '../types/scan'
import type { RiskLevel, Scan } from '../types/scan'

/** The API caps a page at 100 rows, so analytics covers the latest 100 scans. */
const SAMPLE_SIZE = 100

const RISK_COLORS: Record<RiskLevel, string> = {
  SAFE: '#34d399',
  LOW: '#38bdf8',
  MEDIUM: '#fbbf24',
  HIGH: '#fb7185',
}

const AXIS = { stroke: '#475569', fontSize: 11 }

const TOOLTIP_STYLE = {
  backgroundColor: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: 8,
  fontSize: 12,
  color: '#e2e8f0',
}

/** bucketByHour counts scans per hour, oldest first. */
function bucketByHour(scans: Scan[]) {
  const counts = new Map<string, { time: string; scans: number; unsafe: number }>()

  for (const scan of [...scans].reverse()) {
    const date = new Date(scan.created_at)
    const key = Number.isNaN(date.getTime())
      ? scan.created_at
      : `${date.getHours().toString().padStart(2, '0')}:00`

    const bucket = counts.get(key) ?? { time: key, scans: 0, unsafe: 0 }
    bucket.scans += 1
    if (!scan.safe) bucket.unsafe += 1
    counts.set(key, bucket)
  }
  return [...counts.values()]
}

/** AnalyticsPage charts the most recent scans. */
export function AnalyticsPage() {
  const { data, loading, error, reload } = useScans({ page: 1, limit: SAMPLE_SIZE })

  // Memoised so the chart aggregations below have a stable dependency.
  const scans = useMemo(() => data?.data ?? [], [data])

  const overTime = useMemo(() => bucketByHour(scans), [scans])

  const verdictSplit = useMemo(() => {
    const safe = scans.filter((s) => s.safe).length
    const suspicious = scans.filter((s) => s.status === 'SUSPICIOUS').length
    const blocked = scans.filter((s) => s.status === 'BLOCKED').length
    return [
      { name: 'Safe', value: safe, color: RISK_COLORS.SAFE },
      { name: 'Suspicious', value: suspicious, color: RISK_COLORS.MEDIUM },
      { name: 'Blocked', value: blocked, color: RISK_COLORS.HIGH },
    ].filter((slice) => slice.value > 0)
  }, [scans])

  const riskDistribution = useMemo(
    () =>
      RISK_LEVELS.map((level) => ({
        level,
        count: scans.filter((s) => s.risk_level === level).length,
      })),
    [scans],
  )

  if (error) {
    return <ErrorState message={error} onRetry={reload} />
  }
  if (loading && !data) {
    return <Loading label="Loading analytics…" />
  }
  if (scans.length === 0) {
    return <EmptyState message="No scans to chart yet." />
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Analytics</h1>
        <p className="mt-1 text-sm text-slate-500">
          Based on the {scans.length} most recent scans.
        </p>
      </header>

      <Card title="Scans over time (by hour)">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={overTime} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
              <XAxis dataKey="time" {...AXIS} />
              <YAxis allowDecimals={false} {...AXIS} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line
                type="monotone"
                dataKey="scans"
                name="All scans"
                stroke="#38bdf8"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="unsafe"
                name="Not safe"
                stroke="#fb7185"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Verdict split">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={verdictSplit}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={2}
                >
                  {verdictSplit.map((slice) => (
                    <Cell key={slice.name} fill={slice.color} stroke="#0f172a" />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Risk level distribution">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskDistribution} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="level" {...AXIS} />
                <YAxis allowDecimals={false} {...AXIS} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#1e293b55' }} />
                <Bar dataKey="count" name="Scans" radius={[4, 4, 0, 0]}>
                  {riskDistribution.map((entry) => (
                    <Cell key={entry.level} fill={RISK_COLORS[entry.level]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
    </div>
  )
}
