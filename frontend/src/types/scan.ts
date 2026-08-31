/** Types mirroring the GoShield API contract. */

export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH'

export type ScanStatus = 'SAFE' | 'SUSPICIOUS' | 'BLOCKED'

export interface Scan {
  id: string
  url: string
  normalized_url: string
  domain: string
  protocol: string
  safe: boolean
  risk_score: number
  risk_level: RiskLevel
  status: ScanStatus
  reasons: string[]
  cached: boolean
  scan_time_ms: number
  created_at: string
}

export interface PaginationMeta {
  page: number
  limit: number
  total: number
  total_pages: number
}

export interface ListScansResponse {
  data: Scan[]
  pagination: PaginationMeta
}

/** Filters accepted by GET /scans. */
export interface ScanFilters {
  page?: number
  limit?: number
  risk_level?: RiskLevel | ''
  status?: ScanStatus | ''
  domain?: string
  from?: string
  to?: string
}

export interface ApiErrorBody {
  code: string
  message: string
}

/** A bulk entry that could not be scanned. */
export interface BulkErrorItem {
  url: string
  error: ApiErrorBody
}

export type BulkResultItem = Scan | BulkErrorItem

export interface BulkScanResponse {
  results: BulkResultItem[]
  total: number
  duration_ms: number
}

export interface Metrics {
  scans_total: number
  scans_safe_total: number
  scans_blocked_total: number
  cache_hits_total: number
  scan_duration_ms_avg: number
}

/** Narrows a bulk entry to the failure shape. */
export function isBulkError(item: BulkResultItem): item is BulkErrorItem {
  return (item as BulkErrorItem).error !== undefined
}

export const RISK_LEVELS: RiskLevel[] = ['SAFE', 'LOW', 'MEDIUM', 'HIGH']

export const SCAN_STATUSES: ScanStatus[] = ['SAFE', 'SUSPICIOUS', 'BLOCKED']
