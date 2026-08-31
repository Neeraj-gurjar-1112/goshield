package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neerajgurjar/goshield/backend/internal/security"
	"github.com/neerajgurjar/goshield/backend/internal/service"
)

// fakeBulk stands in for the bulk scan service.
type fakeBulk struct {
	items   []service.BulkItem
	err     error
	gotURLs []string
}

func (f *fakeBulk) ScanAll(_ context.Context, urls []string) ([]service.BulkItem, error) {
	f.gotURLs = urls
	if f.err != nil {
		return nil, f.err
	}
	if f.items != nil {
		return f.items, nil
	}
	items := make([]service.BulkItem, 0, len(urls))
	for _, u := range urls {
		scan := sampleScan()
		scan.URL = u
		items = append(items, service.BulkItem{URL: u, Scan: scan})
	}
	return items, nil
}

func postBulk(t *testing.T, bulk BulkScanner, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans/bulk", strings.NewReader(body))
	routerWith(&fakeScanner{scan: sampleScan()}, bulk).ServeHTTP(rec, req)
	return rec
}

func TestBulkHandler_Success(t *testing.T) {
	bulk := &fakeBulk{}
	rec := postBulk(t, bulk, `{"urls":["https://a.example.com","https://b.example.com","https://a.example.com"]}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body)
	}

	var got BulkScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Total != 3 || len(got.Results) != 3 {
		t.Fatalf("total/results = %d/%d, want 3/3", got.Total, len(got.Results))
	}
	if got.DurationMs < 0 {
		t.Errorf("duration_ms = %d, want >= 0", got.DurationMs)
	}

	// Results must come back in the submitted order.
	wantOrder := []string{"https://a.example.com", "https://b.example.com", "https://a.example.com"}
	for i, want := range wantOrder {
		entry, ok := got.Results[i].(map[string]any)
		if !ok {
			t.Fatalf("results[%d] is not an object: %v", i, got.Results[i])
		}
		if entry["url"] != want {
			t.Errorf("results[%d].url = %v, want %q", i, entry["url"], want)
		}
	}
}

func TestBulkHandler_PerURLErrors(t *testing.T) {
	bulk := &fakeBulk{items: []service.BulkItem{
		{URL: "https://ok.example.com", Scan: sampleScan()},
		{URL: "ftp://bad.example.com", Err: fmt.Errorf("%w: scheme", security.ErrInvalidURL)},
		{URL: "https://boom.example.com", Err: fmt.Errorf("persist scan: db down")},
	}}

	rec := postBulk(t, bulk, `{"urls":["https://ok.example.com","ftp://bad.example.com","https://boom.example.com"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a bad URL must not fail the batch", rec.Code)
	}

	var got struct {
		Results []map[string]any `json:"results"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Total != 3 {
		t.Fatalf("total = %d, want 3", got.Total)
	}

	if _, isErr := got.Results[0]["error"]; isErr {
		t.Errorf("results[0] should be a scan, got %v", got.Results[0])
	}
	wantCodes := map[int]string{1: CodeInvalidURL, 2: CodeInternal}
	for idx, wantCode := range wantCodes {
		errObj, ok := got.Results[idx]["error"].(map[string]any)
		if !ok {
			t.Fatalf("results[%d] has no error object: %v", idx, got.Results[idx])
		}
		if errObj["code"] != wantCode {
			t.Errorf("results[%d].error.code = %v, want %q", idx, errObj["code"], wantCode)
		}
	}
}

func TestBulkHandler_BadRequests(t *testing.T) {
	tooMany := make([]string, service.MaxBulkURLs+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("https://example.com/%d", i)
	}
	payload, err := json.Marshal(BulkScanRequest{URLs: tooMany})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"urls":`},
		{"missing urls", `{}`},
		{"empty list", `{"urls":[]}`},
		{"above the batch limit", string(payload)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postBulk(t, &fakeBulk{}, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body)
			}
			if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != CodeInvalidRequest {
				t.Errorf("error code = %q, want %q", got, CodeInvalidRequest)
			}
		})
	}
}

func TestBulkHandler_AtBatchLimit(t *testing.T) {
	urls := make([]string, service.MaxBulkURLs)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://example.com/%d", i)
	}
	payload, err := json.Marshal(BulkScanRequest{URLs: urls})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	bulk := &fakeBulk{}
	rec := postBulk(t, bulk, string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 at exactly %d urls", rec.Code, service.MaxBulkURLs)
	}
	if len(bulk.gotURLs) != service.MaxBulkURLs {
		t.Errorf("service received %d urls, want %d", len(bulk.gotURLs), service.MaxBulkURLs)
	}
}

func TestBulkHandler_ServiceFailure(t *testing.T) {
	rec := postBulk(t, &fakeBulk{err: fmt.Errorf("bulk scan: pool stopped")}, `{"urls":["https://example.com"]}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := decodeEnvelope(t, rec.Body.Bytes()).Error.Code; got != CodeInternal {
		t.Errorf("error code = %q, want %q", got, CodeInternal)
	}
}
