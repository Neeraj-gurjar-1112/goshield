package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsRequest(t *testing.T, h http.Handler, method, origin string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, "/api/v1/scan", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCORS_AllowedOrigin(t *testing.T) {
	h := CORS([]string{"http://localhost:3000", "http://localhost:5173/"})(okHandler)

	for _, origin := range []string{"http://localhost:3000", "http://localhost:5173"} {
		rec := corsRequest(t, h, http.MethodGet, origin)

		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("Allow-Origin for %q = %q, want the origin echoed back", origin, got)
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Errorf("Vary = %q, want Origin", got)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	}
}

func TestCORS_UnknownOriginGetsNoHeaders(t *testing.T) {
	h := CORS([]string{"http://localhost:3000"})(okHandler)

	rec := corsRequest(t, h, http.MethodGet, "http://evil.example.com")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for an unknown origin", got)
	}
	// The request itself still succeeds; it is the browser that blocks the read.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCORS_Preflight(t *testing.T) {
	h := CORS([]string{"http://localhost:3000"})(okHandler)

	rec := corsRequest(t, h, http.MethodOptions, "http://localhost:3000")

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Allow-Methods missing on the preflight response")
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Errorf("Max-Age = %q, want 600", got)
	}
}

func TestCORS_Wildcard(t *testing.T) {
	h := CORS([]string{"*"})(okHandler)

	rec := corsRequest(t, h, http.MethodGet, "http://anything.example.com")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://anything.example.com" {
		t.Errorf("Allow-Origin = %q, want the origin echoed back", got)
	}
}

func TestCORS_NoOriginHeader(t *testing.T) {
	h := CORS([]string{"http://localhost:3000"})(okHandler)

	rec := corsRequest(t, h, http.MethodGet, "")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty when there is no Origin header", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
