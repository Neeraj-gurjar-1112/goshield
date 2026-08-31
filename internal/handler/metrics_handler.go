package handler

import (
	"fmt"
	"net/http"

	"github.com/neerajgurjar/goshield/internal/metrics"
)

// MetricsHandler serves the plain-text metrics endpoint.
type MetricsHandler struct{}

// NewMetricsHandler builds a MetricsHandler.
func NewMetricsHandler() *MetricsHandler { return &MetricsHandler{} }

// Metrics writes the in-memory counters in Prometheus text format.
//
// goshield_scans_safe_total counts scans whose verdict was safe (score <= 50),
// and goshield_scans_blocked_total counts scans whose status is BLOCKED
// (score >= 76); SUSPICIOUS scans fall in neither, so the two do not have to
// add up to goshield_scans_total.
//
//	@Summary		Service metrics
//	@Description	In-memory counters in Prometheus text format.
//	@Tags			system
//	@Produce		plain
//	@Success		200	{string}	string	"goshield_scans_total 1250"
//	@Router			/metrics [get]
func (h *MetricsHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	m := metrics.Read()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "goshield_scans_total %d\n", m.ScansTotal)
	fmt.Fprintf(w, "goshield_scans_safe_total %d\n", m.ScansSafe)
	fmt.Fprintf(w, "goshield_scans_blocked_total %d\n", m.ScansBlocked)
	fmt.Fprintf(w, "goshield_cache_hits_total %d\n", m.CacheHits)
	fmt.Fprintf(w, "goshield_scan_duration_ms_avg %d\n", m.ScanDurationMs)
}
