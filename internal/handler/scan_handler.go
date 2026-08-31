package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/neerajgurjar/goshield/internal/model"
	"github.com/neerajgurjar/goshield/internal/security"
	"github.com/neerajgurjar/goshield/internal/service"
)

// maxBodyBytes caps request bodies well above the largest legal scan request.
const maxBodyBytes = 64 * 1024

// Scanner is the service surface the handler depends on.
type Scanner interface {
	Scan(ctx context.Context, rawURL string) (*model.Scan, error)
	GetByID(ctx context.Context, id uuid.UUID) (*model.Scan, error)
	List(ctx context.Context, q service.ListQuery) (service.ListResult, error)
}

// ScanHandler serves the scan endpoints.
type ScanHandler struct {
	svc  Scanner
	bulk BulkScanner
}

// NewScanHandler builds a ScanHandler.
func NewScanHandler(svc Scanner, bulk BulkScanner) *ScanHandler {
	return &ScanHandler{svc: svc, bulk: bulk}
}

// ScanRequest is the body of POST /api/v1/scan.
type ScanRequest struct {
	URL string `json:"url" example:"http://free-money-login.xyz/verify"`
}

// Scan analyses a single URL.
//
//	@Summary		Scan a URL
//	@Description	Analyses a URL offline (the scanner never sends traffic to it) and returns a risk score, level and the reasons behind it. Repeat scans of the same normalized URL are served from the Redis cache.
//	@Tags			scans
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ScanRequest	true	"URL to scan"
//	@Success		200		{object}	model.Scan
//	@Failure		400		{object}	ErrorEnvelope	"INVALID_URL or INVALID_REQUEST"
//	@Failure		429		{object}	ErrorEnvelope	"RATE_LIMIT_EXCEEDED"
//	@Failure		500		{object}	ErrorEnvelope	"INTERNAL_SERVER_ERROR"
//	@Router			/api/v1/scan [post]
func (h *ScanHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.URL == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Field 'url' is required")
		return
	}
	if len(req.URL) > security.MaxURLLength {
		writeError(w, http.StatusBadRequest, CodeInvalidURL, "The provided URL is invalid")
		return
	}

	scan, err := h.svc.Scan(r.Context(), req.URL)
	if err != nil {
		if errors.Is(err, security.ErrInvalidURL) {
			writeError(w, http.StatusBadRequest, CodeInvalidURL, "The provided URL is invalid")
			return
		}
		slog.ErrorContext(r.Context(), "scan failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "Something went wrong while scanning the URL")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// GetByID returns a stored scan by id.
//
//	@Summary		Get a scan by id
//	@Description	Returns a single previously stored scan.
//	@Tags			scans
//	@Produce		json
//	@Param			id	path		string	true	"Scan id (UUID)"
//	@Success		200	{object}	model.Scan
//	@Failure		404	{object}	ErrorEnvelope	"SCAN_NOT_FOUND"
//	@Failure		429	{object}	ErrorEnvelope	"RATE_LIMIT_EXCEEDED"
//	@Failure		500	{object}	ErrorEnvelope	"INTERNAL_SERVER_ERROR"
//	@Router			/api/v1/scans/{id} [get]
func (h *ScanHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, CodeScanNotFound, "No scan exists with that id")
		return
	}

	scan, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrScanNotFound) {
			writeError(w, http.StatusNotFound, CodeScanNotFound, "No scan exists with that id")
			return
		}
		slog.ErrorContext(r.Context(), "scan lookup failed", "error", err, "scan_id", id)
		writeError(w, http.StatusInternalServerError, CodeInternal, "Something went wrong while loading the scan")
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

// decodeJSON reads a JSON body into dst, writing an error envelope and
// returning false when the body is unusable.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Request body must be valid JSON")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Request body must contain a single JSON object")
		return false
	}
	return true
}

// Pagination describes the page returned by a list endpoint.
type Pagination struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// ListScansResponse is the body of GET /api/v1/scans.
type ListScansResponse struct {
	Data       []*model.Scan `json:"data"`
	Pagination Pagination    `json:"pagination"`
}

// validRiskLevels and validStatuses gate the enum query parameters.
var (
	validRiskLevels = map[string]bool{"SAFE": true, "LOW": true, "MEDIUM": true, "HIGH": true}
	validStatuses   = map[string]bool{"SAFE": true, "SUSPICIOUS": true, "BLOCKED": true}
)

// List returns a filtered, paged slice of scan history.
//
//	@Summary		List scan history
//	@Description	Returns scans newest first, with optional filtering and paging.
//	@Tags			scans
//	@Produce		json
//	@Param			page		query		int		false	"Page number, 1-based"
//	@Param			limit		query		int		false	"Page size, max 100"
//	@Param			risk_level	query		string	false	"Filter by risk level"	Enums(SAFE, LOW, MEDIUM, HIGH)
//	@Param			status		query		string	false	"Filter by status"		Enums(SAFE, SUSPICIOUS, BLOCKED)
//	@Param			domain		query		string	false	"Filter by exact domain"
//	@Param			from		query		string	false	"Only scans created at or after this RFC3339 timestamp"
//	@Param			to			query		string	false	"Only scans created at or before this RFC3339 timestamp"
//	@Success		200			{object}	ListScansResponse
//	@Failure		400			{object}	ErrorEnvelope	"INVALID_REQUEST"
//	@Failure		429			{object}	ErrorEnvelope	"RATE_LIMIT_EXCEEDED"
//	@Failure		500			{object}	ErrorEnvelope	"INTERNAL_SERVER_ERROR"
//	@Router			/api/v1/scans [get]
func (h *ScanHandler) List(w http.ResponseWriter, r *http.Request) {
	q, ok := parseListQuery(w, r)
	if !ok {
		return
	}

	result, err := h.svc.List(r.Context(), q)
	if err != nil {
		slog.ErrorContext(r.Context(), "scan listing failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "Something went wrong while loading scans")
		return
	}

	writeJSON(w, http.StatusOK, ListScansResponse{
		Data: result.Scans,
		Pagination: Pagination{
			Page:       q.Page,
			Limit:      q.Limit,
			Total:      result.Total,
			TotalPages: totalPages(result.Total, q.Limit),
		},
	})
}

// parseListQuery validates the query string, writing an error envelope and
// returning false on the first bad parameter.
func parseListQuery(w http.ResponseWriter, r *http.Request) (service.ListQuery, bool) {
	query := r.URL.Query()
	q := service.ListQuery{Page: service.DefaultPage, Limit: service.DefaultLimit}

	if raw := query.Get("page"); raw != "" {
		page, err := strconv.Atoi(raw)
		if err != nil || page < 1 {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Parameter 'page' must be a positive integer")
			return q, false
		}
		q.Page = page
	}

	if raw := query.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Parameter 'limit' must be a positive integer")
			return q, false
		}
		if limit > service.MaxLimit {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				fmt.Sprintf("Parameter 'limit' must not exceed %d", service.MaxLimit))
			return q, false
		}
		q.Limit = limit
	}

	if raw := query.Get("risk_level"); raw != "" {
		level := strings.ToUpper(raw)
		if !validRiskLevels[level] {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"Parameter 'risk_level' must be one of SAFE, LOW, MEDIUM, HIGH")
			return q, false
		}
		q.RiskLevel = level
	}

	if raw := query.Get("status"); raw != "" {
		status := strings.ToUpper(raw)
		if !validStatuses[status] {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"Parameter 'status' must be one of SAFE, SUSPICIOUS, BLOCKED")
			return q, false
		}
		q.Status = status
	}

	if raw := query.Get("domain"); raw != "" {
		if len(raw) > 255 {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Parameter 'domain' is too long")
			return q, false
		}
		q.Domain = strings.ToLower(strings.TrimSpace(raw))
	}

	from, ok := parseTimeParam(w, query.Get("from"), "from")
	if !ok {
		return q, false
	}
	q.From = from

	to, ok := parseTimeParam(w, query.Get("to"), "to")
	if !ok {
		return q, false
	}
	q.To = to

	if q.From != nil && q.To != nil && q.To.Before(*q.From) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, "Parameter 'to' must not be before 'from'")
		return q, false
	}
	return q, true
}

// parseTimeParam parses an optional RFC3339 timestamp parameter.
func parseTimeParam(w http.ResponseWriter, raw, name string) (*time.Time, bool) {
	if raw == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			fmt.Sprintf("Parameter '%s' must be an RFC3339 timestamp", name))
		return nil, false
	}
	return &t, true
}

func totalPages(total, limit int) int {
	if total <= 0 || limit <= 0 {
		return 0
	}
	return (total + limit - 1) / limit
}
