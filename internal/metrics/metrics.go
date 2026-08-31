// Package metrics holds the process-wide counters exposed by GET /metrics.
// Counters are plain atomics: no Prometheus dependency, no locks on the hot
// path.
package metrics

import "sync/atomic"

// Counter is a monotonically increasing uint64 counter.
type Counter struct {
	value atomic.Uint64
}

// Inc adds one to the counter.
func (c *Counter) Inc() { c.value.Add(1) }

// Value returns the current count.
func (c *Counter) Value() uint64 { return c.value.Load() }

// Histogram tracks just enough to report a mean: a running sum and a count.
type Histogram struct {
	sum   atomic.Uint64
	count atomic.Uint64
}

// Observe records one sample. Negative samples are treated as zero.
func (h *Histogram) Observe(v int64) {
	if v < 0 {
		v = 0
	}
	h.sum.Add(uint64(v))
	h.count.Add(1)
}

// Average returns the mean of the observed samples, or zero when there are
// none.
func (h *Histogram) Average() uint64 {
	count := h.count.Load()
	if count == 0 {
		return 0
	}
	return h.sum.Load() / count
}

// Counters exposed by the API.
var (
	ScansTotal   Counter
	ScansSafe    Counter
	ScansBlocked Counter
	CacheHits    Counter
	ScanDuration Histogram
)

// Snapshot is a point-in-time read of every metric.
type Snapshot struct {
	ScansTotal     uint64
	ScansSafe      uint64
	ScansBlocked   uint64
	CacheHits      uint64
	ScanDurationMs uint64
}

// Read returns the current values of all metrics.
func Read() Snapshot {
	return Snapshot{
		ScansTotal:     ScansTotal.Value(),
		ScansSafe:      ScansSafe.Value(),
		ScansBlocked:   ScansBlocked.Value(),
		CacheHits:      CacheHits.Value(),
		ScanDurationMs: ScanDuration.Average(),
	}
}
