import axios, { AxiosError } from 'axios'
import type {
  BulkScanResponse,
  ListScansResponse,
  Metrics,
  Scan,
  ScanFilters,
} from '../types/scan'

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8080/api/v1'

/** The server root, for endpoints that live outside /api/v1. */
const ROOT_URL = BASE_URL.replace(/\/api\/v1\/?$/, '')

export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

/** An error carrying the API's error envelope, or a transport failure. */
export class ApiError extends Error {
  code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.code = code
  }
}

/** Turns any axios failure into an ApiError with a message worth showing. */
function toApiError(err: unknown): ApiError {
  const axiosErr = err as AxiosError<{ error?: { code?: string; message?: string } }>

  const envelope = axiosErr.response?.data?.error
  if (envelope?.code) {
    return new ApiError(envelope.code, envelope.message ?? 'Request failed')
  }
  if (axiosErr.code === 'ECONNABORTED') {
    return new ApiError('TIMEOUT', 'The request timed out. Is the API still running?')
  }
  if (!axiosErr.response) {
    return new ApiError('NETWORK_ERROR', 'Cannot reach the API. Check that the backend is running.')
  }
  return new ApiError('UNKNOWN', axiosErr.message || 'Request failed')
}

async function request<T>(fn: () => Promise<{ data: T }>): Promise<T> {
  try {
    const res = await fn()
    return res.data
  } catch (err) {
    throw toApiError(err)
  }
}

/** POST /scan */
export function scanUrl(url: string): Promise<Scan> {
  return request<Scan>(() => api.post('/scan', { url }))
}

/** POST /scans/bulk */
export function bulkScan(urls: string[]): Promise<BulkScanResponse> {
  return request<BulkScanResponse>(() => api.post('/scans/bulk', { urls }))
}

/** GET /scans/{id} */
export function getScan(id: string): Promise<Scan> {
  return request<Scan>(() => api.get(`/scans/${id}`))
}

/** GET /scans */
export function listScans(filters: ScanFilters = {}): Promise<ListScansResponse> {
  const params: Record<string, string | number> = {}
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== '') {
      params[key] = value
    }
  }
  return request<ListScansResponse>(() => api.get('/scans', { params }))
}

/** GET /metrics, parsed from the Prometheus text format. */
export async function getMetrics(): Promise<Metrics> {
  try {
    const res = await axios.get<string>(`${ROOT_URL}/metrics`, {
      timeout: 10000,
      responseType: 'text',
      transformResponse: [(data) => data],
    })
    return parseMetrics(res.data)
  } catch (err) {
    throw toApiError(err)
  }
}

/** parseMetrics reads `name value` lines into a typed object. */
export function parseMetrics(text: string): Metrics {
  const values: Record<string, number> = {}

  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue

    const [name, raw] = trimmed.split(/\s+/)
    const value = Number(raw)
    if (name && Number.isFinite(value)) {
      values[name] = value
    }
  }

  return {
    scans_total: values.goshield_scans_total ?? 0,
    scans_safe_total: values.goshield_scans_safe_total ?? 0,
    scans_blocked_total: values.goshield_scans_blocked_total ?? 0,
    cache_hits_total: values.goshield_cache_hits_total ?? 0,
    scan_duration_ms_avg: values.goshield_scan_duration_ms_avg ?? 0,
  }
}
