import { useState } from 'react'
import { ScanForm } from '../components/ScanForm'
import { ScanResult } from '../components/ScanResult'
import { Card } from '../components/States'
import type { Scan } from '../types/scan'

/** ScanPage scans one URL and shows the verdict. */
export function ScanPage() {
  const [scans, setScans] = useState<Scan[]>([])

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Scan a URL</h1>
        <p className="mt-1 text-sm text-slate-500">
          The scanner reads the URL string only — it never sends traffic to the address being
          checked.
        </p>
      </header>

      <Card>
        <ScanForm onScanned={(scan) => setScans((prev) => [scan, ...prev])} />
      </Card>

      {scans.map((scan) => (
        <ScanResult key={scan.id} scan={scan} />
      ))}
    </div>
  )
}
