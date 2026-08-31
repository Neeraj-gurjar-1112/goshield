import { useCallback, useEffect, useState } from 'react'
import { listScans } from '../services/api'
import type { ListScansResponse, ScanFilters } from '../types/scan'

interface UseScansResult {
  data: ListScansResponse | null
  loading: boolean
  error: string | null
  reload: () => void
}

/**
 * useScans fetches a page of scan history and refetches whenever the filters
 * change. Filters are compared by value, so callers may pass a fresh object on
 * every render.
 */
export function useScans(filters: ScanFilters = {}): UseScansResult {
  const [data, setData] = useState<ListScansResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  const filterKey = JSON.stringify(filters)

  const reload = useCallback(() => setReloadToken((n) => n + 1), [])

  useEffect(() => {
    let active = true
    const parsed: ScanFilters = JSON.parse(filterKey)

    setLoading(true)
    setError(null)

    listScans(parsed)
      .then((res) => {
        if (active) setData(res)
      })
      .catch((err: Error) => {
        if (active) {
          setError(err.message)
          setData(null)
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => {
      active = false
    }
  }, [filterKey, reloadToken])

  return { data, loading, error, reload }
}
