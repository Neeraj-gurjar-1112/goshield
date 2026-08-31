package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/neerajgurjar/goshield/internal/model"
	"github.com/neerajgurjar/goshield/internal/security"
	"github.com/neerajgurjar/goshield/internal/service"
)

// fakeScanner stands in for the scan service.
type fakeScanner struct {
	scan     *model.Scan
	scanErr  error
	getErr   error
	listErr  error
	list     service.ListResult
	gotURL   string
	gotID    uuid.UUID
	gotQuery service.ListQuery
}

func (f *fakeScanner) Scan(_ context.Context, rawURL string) (*model.Scan, error) {
	f.gotURL = rawURL
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	return f.scan, nil
}

func (f *fakeScanner) GetByID(_ context.Context, id uuid.UUID) (*model.Scan, error) {
	f.gotID = id
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.scan, nil
}

func (f *fakeScanner) List(_ context.Context, q service.ListQuery) (service.ListResult, error) {
	f.gotQuery = q
	if f.listErr != nil {
		return service.ListResult{}, f.listErr
	}
	return f.list, nil
}

func sampleScan() *model.Scan {
	return &model.Scan{
		ID:            uuid.MustParse("8f14e45f-ea2b-4c5d-9f1a-0d1b2c3d4e5f"),
		URL:           "https://example.com/login",
		NormalizedURL: "https://example.com/login",
		Domain:        "example.com",
		Protocol:      "https",
		Safe:          true,
		RiskScore:     10,
		RiskLevel:     model.RiskLevelSafe,
		Status:        model.StatusSafe,
		Reasons:       []string{"Contains suspicious keyword: login"},
	}
}

func routerFor(svc Scanner) http.Handler {
	return routerWith(svc, &fakeBulk{})
}

func routerWith(svc Scanner, bulk BulkScanner) http.Handler {
	h := NewScanHandler(svc, bulk)
	r := chi.NewRouter()
	r.Post("/api/v1/scan", h.Scan)
	r.Post("/api/v1/scans/bulk", h.Bulk)
	r.Get("/api/v1/scans", h.List)
	r.Get("/api/v1/scans/{id}", h.GetByID)
	return r
}

func decodeEnvelope(t *testing.T, body []byte) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode error envelope: %v (body: %s)", err, body)
	}
	return env
}

func TestScanHandler_Success(t *testing.T) {
	svc := &fakeScanner{scan: sampleScan()}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
		strings.NewReader(`{"url":"https://example.com/login"}`))

	routerFor(svc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}
	if svc.gotURL != "https://example.com/login" {
		t.Errorf("service received %q", svc.gotURL)
	}

	var got model.Scan
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.ID != sampleScan().ID || got.RiskLevel != model.RiskLevelSafe {
		t.Errorf("body = %+v", got)
	}
}

func TestScanHandler_BadRequests(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		scanErr  error
		wantCode int
		wantErr  string
	}{
		{"malformed json", `{"url":`, nil, http.StatusBadRequest, CodeInvalidRequest},
		{"unknown field", `{"target":"https://example.com"}`, nil, http.StatusBadRequest, CodeInvalidRequest},
		{"missing url", `{}`, nil, http.StatusBadRequest, CodeInvalidRequest},
		{"empty url", `{"url":""}`, nil, http.StatusBadRequest, CodeInvalidRequest},
		{"trailing garbage", `{"url":"https://example.com"}{}`, nil, http.StatusBadRequest, CodeInvalidRequest},
		{
			name: "too long url", wantCode: http.StatusBadRequest, wantErr: CodeInvalidURL,
			body: fmt.Sprintf(`{"url":"https://example.com/%s"}`, strings.Repeat("a", security.MaxURLLength)),
		},
		{
			name: "unparseable url", body: `{"url":"ftp://example.com"}`,
			scanErr:  fmt.Errorf("%w: scheme must be http or https", security.ErrInvalidURL),
			wantCode: http.StatusBadRequest, wantErr: CodeInvalidURL,
		},
		{
			name: "service failure", body: `{"url":"https://example.com"}`,
			scanErr:  fmt.Errorf("persist scan: connection refused"),
			wantCode: http.StatusInternalServerError, wantErr: CodeInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeScanner{scan: sampleScan(), scanErr: tt.scanErr}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(tt.body))

			routerFor(svc).ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantCode, rec.Body)
			}
			if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != tt.wantErr {
				t.Errorf("error code = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestScanHandler_GetByID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		getErr   error
		wantCode int
		wantErr  string
	}{
		{"found", sampleScan().ID.String(), nil, http.StatusOK, ""},
		{"unknown id", uuid.NewString(), service.ErrScanNotFound, http.StatusNotFound, CodeScanNotFound},
		{"malformed id", "junk-id", nil, http.StatusNotFound, CodeScanNotFound},
		{"repository failure", uuid.NewString(), fmt.Errorf("load scan: connection refused"), http.StatusInternalServerError, CodeInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeScanner{scan: sampleScan(), getErr: tt.getErr}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+tt.id, nil)

			routerFor(svc).ServeHTTP(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantCode, rec.Body)
			}
			if tt.wantErr == "" {
				return
			}
			if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != tt.wantErr {
				t.Errorf("error code = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestScanHandler_List(t *testing.T) {
	svc := &fakeScanner{list: service.ListResult{Scans: []*model.Scan{sampleScan()}, Total: 125}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans?page=2&limit=20&risk_level=high&status=safe&domain=Example.COM", nil)

	routerFor(svc).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}

	var got ListScansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	want := Pagination{Page: 2, Limit: 20, Total: 125, TotalPages: 7}
	if got.Pagination != want {
		t.Errorf("pagination = %+v, want %+v", got.Pagination, want)
	}
	if len(got.Data) != 1 {
		t.Errorf("data length = %d, want 1", len(got.Data))
	}
	if svc.gotQuery.RiskLevel != "HIGH" || svc.gotQuery.Status != "SAFE" {
		t.Errorf("enum params not upper-cased: %+v", svc.gotQuery)
	}
	if svc.gotQuery.Domain != "example.com" {
		t.Errorf("domain = %q, want lower-cased", svc.gotQuery.Domain)
	}
}

func TestScanHandler_ListDefaults(t *testing.T) {
	svc := &fakeScanner{list: service.ListResult{Scans: []*model.Scan{}, Total: 0}}
	rec := httptest.NewRecorder()

	routerFor(svc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got ListScansResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	want := Pagination{Page: service.DefaultPage, Limit: service.DefaultLimit, Total: 0, TotalPages: 0}
	if got.Pagination != want {
		t.Errorf("pagination = %+v, want %+v", got.Pagination, want)
	}
	if got.Data == nil {
		t.Error("data = null, want an empty array")
	}
}

func TestScanHandler_ListBadParams(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"page zero", "?page=0"},
		{"page negative", "?page=-1"},
		{"page not a number", "?page=abc"},
		{"limit zero", "?limit=0"},
		{"limit above max", "?limit=9999"},
		{"unknown risk level", "?risk_level=EXTREME"},
		{"unknown status", "?status=MAYBE"},
		{"from not rfc3339", "?from=2026-01-01"},
		{"to not rfc3339", "?to=yesterday"},
		{"to before from", "?from=2026-08-31T00:00:00Z&to=2026-08-30T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeScanner{}
			rec := httptest.NewRecorder()

			routerFor(svc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans"+tt.query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body)
			}
			if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != CodeInvalidRequest {
				t.Errorf("error code = %q, want %q", got, CodeInvalidRequest)
			}
		})
	}
}

func TestScanHandler_ListServiceFailure(t *testing.T) {
	svc := &fakeScanner{listErr: fmt.Errorf("list scans: connection refused")}
	rec := httptest.NewRecorder()

	routerFor(svc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != CodeInternal {
		t.Errorf("error code = %q, want %q", got, CodeInternal)
	}
}

func TestTotalPages(t *testing.T) {
	tests := []struct {
		total, limit, want int
	}{
		{0, 20, 0},
		{1, 20, 1},
		{20, 20, 1},
		{21, 20, 2},
		{1250, 20, 63},
		{5, 0, 0},
	}
	for _, tt := range tests {
		if got := totalPages(tt.total, tt.limit); got != tt.want {
			t.Errorf("totalPages(%d, %d) = %d, want %d", tt.total, tt.limit, got, tt.want)
		}
	}
}
