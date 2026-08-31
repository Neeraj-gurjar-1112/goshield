package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// okHandler is a handler that always succeeds.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
})

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if seen == "" {
		t.Fatal("no request id on the context")
	}
	if got := rec.Header().Get(HeaderRequestID); got != seen {
		t.Errorf("%s header = %q, want %q", HeaderRequestID, got, seen)
	}
}

func TestRequestID_ReusesSuppliedID(t *testing.T) {
	const supplied = "abc-123"

	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(HeaderRequestID, supplied)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if seen != supplied {
		t.Errorf("request id = %q, want %q", seen, supplied)
	}
}

func TestRequestID_RejectsOversizedSuppliedID(t *testing.T) {
	oversized := strings.Repeat("x", maxSuppliedIDLength+1)

	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(HeaderRequestID, oversized)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen == oversized {
		t.Error("oversized supplied request id was accepted")
	}
	if seen == "" {
		t.Error("no replacement request id was generated")
	}
}

func TestRequestIDFrom_EmptyContext(t *testing.T) {
	if got := RequestIDFrom(context.Background()); got != "" {
		t.Errorf("RequestIDFrom(bare ctx) = %q, want empty", got)
	}
}

// logLine decodes a single JSON log record.
func logLine(t *testing.T, raw []byte) map[string]any {
	t.Helper()

	line := bytes.TrimSpace(raw)
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatalf("decode log line: %v (raw: %s)", err, raw)
	}
	return got
}

func TestLogger_LogsRequestDetailsWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewJSONHandler(&buf, nil)))

	h := RequestID(Logger(logger)(okHandler))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	req.Header.Set(HeaderRequestID, "req-42")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := logLine(t, buf.Bytes())
	if got["method"] != http.MethodPost {
		t.Errorf("method = %v, want POST", got["method"])
	}
	if got["path"] != "/api/v1/scan" {
		t.Errorf("path = %v", got["path"])
	}
	if got["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", got["status"])
	}
	if got["request_id"] != "req-42" {
		t.Errorf("request_id = %v, want req-42", got["request_id"])
	}
	if _, ok := got["duration_ms"]; !ok {
		t.Error("duration_ms missing from the log line")
	}
}

func TestLogger_LevelFollowsStatus(t *testing.T) {
	tests := []struct {
		status    int
		wantLevel string
	}{
		{http.StatusOK, "INFO"},
		{http.StatusBadRequest, "WARN"},
		{http.StatusInternalServerError, "ERROR"},
	}

	for _, tt := range tests {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))

		h := Logger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.status)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

		if got := logLine(t, buf.Bytes())["level"]; got != tt.wantLevel {
			t.Errorf("status %d logged at %v, want %s", tt.status, got, tt.wantLevel)
		}
	}
}

func TestLogger_DefaultsToOKWhenHandlerWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	h := Logger(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	if got := logLine(t, buf.Bytes())["status"]; got != float64(http.StatusOK) {
		t.Errorf("status = %v, want 200", got)
	}
}

func TestRecovery_TurnsPanicIntoErrorEnvelope(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	h := Recovery(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom: secret internal detail")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (body: %s)", err, rec.Body)
	}
	if body.Error.Code != "INTERNAL_SERVER_ERROR" {
		t.Errorf("error code = %q", body.Error.Code)
	}
	if strings.Contains(rec.Body.String(), "secret internal detail") {
		t.Error("panic value leaked into the response body")
	}

	logged := buf.String()
	if !strings.Contains(logged, "recovered from panic") {
		t.Error("panic was not logged")
	}
	if !strings.Contains(logged, "stack") {
		t.Error("stack trace was not logged")
	}
}

func TestRecovery_PassesThroughNormalRequests(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))

	rec := httptest.NewRecorder()
	Recovery(logger)(okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRateLimiter_BlocksAfterLimit(t *testing.T) {
	limiter := NewRateLimiter(5, time.Minute)
	h := limiter.Middleware(okHandler)

	var allowed, limited int
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "203.0.113.5:1234"
		h.ServeHTTP(rec, req)

		switch rec.Code {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			limited++
			if got := rec.Header().Get("Retry-After"); got != "60" {
				t.Errorf("Retry-After = %q, want 60", got)
			}
			var body map[string]map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode 429 body: %v", err)
			}
			if body["error"]["code"] != "RATE_LIMIT_EXCEEDED" {
				t.Errorf("429 code = %q", body["error"]["code"])
			}
		default:
			t.Fatalf("unexpected status %d", rec.Code)
		}
	}

	if allowed != 5 {
		t.Errorf("allowed %d requests, want 5", allowed)
	}
	if limited != 5 {
		t.Errorf("limited %d requests, want 5", limited)
	}
}

func TestRateLimiter_IsPerClientIP(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	h := limiter.Middleware(okHandler)

	call := func(addr string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Exhaust the first client.
	call("198.51.100.1:1111")
	call("198.51.100.1:2222")
	if got := call("198.51.100.1:3333"); got != http.StatusTooManyRequests {
		t.Errorf("third request from the same IP = %d, want 429", got)
	}

	// A different client still has a full bucket.
	if got := call("198.51.100.2:1111"); got != http.StatusOK {
		t.Errorf("first request from a second IP = %d, want 200", got)
	}
	if limiter.Buckets() != 2 {
		t.Errorf("tracked %d buckets, want 2", limiter.Buckets())
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	// One request per 50ms, burst of one.
	limiter := NewRateLimiter(1, 50*time.Millisecond)
	h := limiter.Middleware(okHandler)

	call := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "192.0.2.9:5555"
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call(); got != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got)
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("immediate second request = %d, want 429", got)
	}

	time.Sleep(80 * time.Millisecond)
	if got := call(); got != http.StatusOK {
		t.Errorf("request after refill = %d, want 200", got)
	}
}

func TestRateLimiter_DisabledWhenLimitIsZero(t *testing.T) {
	limiter := NewRateLimiter(0, time.Minute)
	h := limiter.Middleware(okHandler)

	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "192.0.2.10:1234"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 with limiting disabled", i, rec.Code)
		}
	}
	if limiter.Buckets() != 0 {
		t.Errorf("tracked %d buckets, want none", limiter.Buckets())
	}
}

func TestRateLimiter_ConcurrentClients(t *testing.T) {
	limiter := NewRateLimiter(100, time.Minute)
	h := limiter.Middleware(okHandler)

	var wg sync.WaitGroup
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/health", nil)
				req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
				h.ServeHTTP(rec, req)
			}
		}(i)
	}
	wg.Wait()

	if got := limiter.Buckets(); got != 20 {
		t.Errorf("tracked %d buckets, want 20", got)
	}
}

func TestRateLimiter_SweepsIdleBuckets(t *testing.T) {
	limiter := NewRateLimiter(10, time.Minute)

	now := time.Now()
	limiter.now = func() time.Time { return now }

	limiter.allow("203.0.113.1")
	if limiter.Buckets() != 1 {
		t.Fatalf("buckets = %d, want 1", limiter.Buckets())
	}

	// Move past the idle TTL and the sweep interval, then touch another client.
	now = now.Add(idleTTL + sweepInterval + time.Second)
	limiter.allow("203.0.113.2")

	if got := limiter.Buckets(); got != 1 {
		t.Errorf("buckets after sweep = %d, want 1 (the idle one dropped)", got)
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		forwarded  string
		want       string
	}{
		{remoteAddr: "203.0.113.7:4321", want: "203.0.113.7"},
		{remoteAddr: "[2001:db8::1]:4321", want: "2001:db8::1"},
		{remoteAddr: "203.0.113.7", want: "203.0.113.7"},
		// A forged X-Forwarded-For must not change the identity.
		{remoteAddr: "203.0.113.7:4321", forwarded: "1.2.3.4", want: "203.0.113.7"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = tt.remoteAddr
		if tt.forwarded != "" {
			req.Header.Set("X-Forwarded-For", tt.forwarded)
		}
		if got := clientIP(req); got != tt.want {
			t.Errorf("clientIP(%q) = %q, want %q", tt.remoteAddr, got, tt.want)
		}
	}
}
