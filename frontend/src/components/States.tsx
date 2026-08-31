/** Shared loading, error and empty states so every fetch looks the same. */

interface LoadingProps {
  label?: string
}

export function Loading({ label = 'Loading…' }: LoadingProps) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/50 p-4 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-emerald-400" />
      {label}
    </div>
  )
}

interface ErrorStateProps {
  message: string
  onRetry?: () => void
}

export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-semibold">Something went wrong.</span>
        <span className="text-rose-200/80">{message}</span>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="ml-auto rounded-md border border-rose-400/40 px-3 py-1 text-xs font-medium text-rose-100 transition hover:bg-rose-500/20"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
      {message}
    </div>
  )
}

/** Card is the panel used across the dashboard. */
export function Card({
  title,
  action,
  children,
}: {
  title?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 sm:p-5">
      {(title || action) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title && <h2 className="text-sm font-semibold text-slate-300">{title}</h2>}
          {action}
        </div>
      )}
      {children}
    </section>
  )
}
