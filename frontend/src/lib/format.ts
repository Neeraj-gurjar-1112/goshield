/** formatTime renders an RFC3339 timestamp in the viewer's locale. */
export function formatTime(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}
