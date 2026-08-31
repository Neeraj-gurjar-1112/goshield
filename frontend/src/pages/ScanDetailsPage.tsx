import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ScanResult } from '../components/ScanResult'
import { ErrorState, Loading } from '../components/States'
import { getScan } from '../services/api'
import type { Scan } from '../types/scan'

/** ScanDetailsPage shows one stored scan by id. */
export function ScanDetailsPage() {
  const { id = '' } = useParams()
  const [scan, setScan] = useState<Scan | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  useEffect(() => {
    let active = true

    setLoading(true)
    setError(null)

    getScan(id)
      .then((res) => {
        if (active) setScan(res)
      })
      .catch((err: Error) => {
        if (active) {
          setError(err.message)
          setScan(null)
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [id, reloadToken])

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Scan details</h1>
        <Link
          to="/scans"
          className="text-xs font-medium text-emerald-400 transition hover:text-emerald-300"
        >
          ← Back to history
        </Link>
      </div>

      <p className="break-all font-mono text-xs text-slate-500">{id}</p>

      {error ? (
        <ErrorState message={error} onRetry={reload} />
      ) : loading ? (
        <Loading label="Loading scan…" />
      ) : (
        scan && <ScanResult scan={scan} showLink={false} />
      )}
    </div>
  )
}
