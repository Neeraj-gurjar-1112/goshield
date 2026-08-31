import { useState } from 'react'
import { scanUrl } from '../services/api'
import type { Scan } from '../types/scan'

const SAMPLES = [
  'https://google.com',
  'http://free-money-login.xyz/verify',
  'https://phishing-test.example/login',
  'http://192.168.1.1:8080/admin',
]

interface ScanFormProps {
  onScanned: (scan: Scan) => void
  compact?: boolean
}

/** ScanForm submits a single URL to POST /scan. */
export function ScanForm({ onScanned, compact = false }: ScanFormProps) {
  const [url, setUrl] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(value: string) {
    const trimmed = value.trim()
    if (trimmed === '') {
      setError('Enter a URL to scan.')
      return
    }

    setSubmitting(true)
    setError(null)
    try {
      onScanned(await scanUrl(trimmed))
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void submit(url)
        }}
        className="flex flex-col gap-2 sm:flex-row"
      >
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/login"
          aria-label="URL to scan"
          spellCheck={false}
          className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2.5 font-mono text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-emerald-500/60"
        />
        <button
          type="submit"
          disabled={submitting}
          className="rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting ? 'Scanning…' : 'Scan'}
        </button>
      </form>

      {!compact && (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <span>Try:</span>
          {SAMPLES.map((sample) => (
            <button
              key={sample}
              type="button"
              onClick={() => {
                setUrl(sample)
                void submit(sample)
              }}
              className="rounded-md border border-slate-800 px-2 py-1 font-mono text-slate-400 transition hover:border-slate-700 hover:text-slate-200"
            >
              {sample}
            </button>
          ))}
        </div>
      )}

      {error && (
        <p className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          {error}
        </p>
      )}
    </div>
  )
}
