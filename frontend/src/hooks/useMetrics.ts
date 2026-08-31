import { useCallback, useEffect, useState } from 'react'
import { getMetrics } from '../services/api'
import type { Metrics } from '../types/scan'

interface UseMetricsResult {
  metrics: Metrics | null
  loading: boolean
  error: string | null
  reload: () => void
}

/** useMetrics fetches the counters served by GET /metrics. */
export function useMetrics(): UseMetricsResult {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  useEffect(() => {
    let active = true

    setLoading(true)
    setError(null)

    getMetrics()
      .then((res) => {
        if (active) setMetrics(res)
      })
      .catch((err: Error) => {
        if (active) {
          setError(err.message)
          setMetrics(null)
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [reloadToken])

  return { metrics, loading, error, reload }
}
