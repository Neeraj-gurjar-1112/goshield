package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/neerajgurjar/goshield/backend/internal/security"
	"github.com/neerajgurjar/goshield/backend/internal/service"
)

// BulkScanner is the bulk service surface the handler depends on.
type BulkScanner interface {
	ScanAll(ctx context.Context, urls []string) ([]service.BulkItem, error)
}

// BulkScanRequest is the body of POST /api/v1/scans/bulk.
type BulkScanRequest struct {
	URLs []string `json:"urls" example:"https://example.com,http://free-money-login.xyz/verify"`
}

// BulkScanResponse is the body returned by a bulk scan. Each entry of Results
// is either a scan object or a per-URL error object.
type BulkScanResponse struct {
	Results    []any `json:"results"`
	Total      int   `json:"total"`
	DurationMs int64 `json:"duration_ms"`
}

// BulkErrorItem replaces the scan object for a URL that could not be scanned.
type BulkErrorItem struct {
	URL   string    `json:"url"`
	Error ErrorBody `json:"error"`
}

// Bulk scans a batch of URLs through the worker pool.
//
//	@Summary		Scan up to 100 URLs
//	@Description	Scans a batch of URLs through a bounded worker pool. Results come back in input order; an entry that could not be scanned carries an error object instead of a scan, so one bad URL does not fail the batch.
//	@Tags			scans
//	@Accept			json
//	@Produce		json
//	@Param			request	body		BulkScanRequest	true	"URLs to scan, at most 100"
//	@Success		200		{object}	BulkScanResponse
//	@Failure		400		{object}	ErrorEnvelope	"INVALID_REQUEST"
//	@Failure		429		{object}	ErrorEnvelope	"RATE_LIMIT_EXCEEDED"
//	@Failure		500		{object}	ErrorEnvelope	"INTERNAL_SERVER_ERROR"
//	@Router			/api/v1/scans/bulk [post]
func (h *ScanHandler) Bulk(w http.ResponseWriter, r *http.Request) {
	var req BulkScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.URLs) == 0 {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Field 'urls' must contain at least one URL")
		return
	}
	if len(req.URLs) > service.MaxBulkURLs {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("Field 'urls' must contain at most %d URLs", service.MaxBulkURLs))
		return
	}

	start := time.Now()
	items, err := h.bulk.ScanAll(r.Context(), req.URLs)
	if err != nil {
		slog.ErrorContext(r.Context(), "bulk scan failed", "error", err, "urls", len(req.URLs))
		writeError(w, http.StatusInternalServerError, CodeInternal, "Something went wrong while scanning the URLs")
		return
	}

	results := make([]any, 0, len(items))
	for _, item := range items {
		results = append(results, bulkResult(item))
	}

	writeJSON(w, http.StatusOK, BulkScanResponse{
		Results:    results,
		Total:      len(results),
		DurationMs: time.Since(start).Milliseconds(),
	})
}

// bulkResult renders one bulk entry: the scan when it succeeded, an error
// object carrying the offending URL when it did not.
func bulkResult(item service.BulkItem) any {
	if item.Err == nil && item.Scan != nil {
		return item.Scan
	}

	body := ErrorBody{Code: CodeInternal, Message: "Something went wrong while scanning this URL"}
	switch {
	case errors.Is(item.Err, security.ErrInvalidURL):
		body = ErrorBody{Code: CodeInvalidURL, Message: "The provided URL is invalid"}
	case item.Err == nil:
		// The worker pool returned a zero result, which only happens when the
		// request was cancelled mid-batch.
		body = ErrorBody{Code: CodeServiceUnavail, Message: "The scan did not complete"}
	}
	return BulkErrorItem{URL: item.URL, Error: body}
}
