package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// preflightMaxAge is how long a browser may cache a preflight result.
const preflightMaxAge = 10 * time.Minute

// CORS allows the dashboard, served from a different origin than the API, to
// call it from the browser. Only the configured origins are echoed back; an
// unknown origin gets no CORS headers and the browser blocks the response.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	allowAny := false
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		switch {
		case o == "":
		case o == "*":
			allowAny = true
		default:
			allowed[strings.ToLower(strings.TrimSuffix(o, "/"))] = true
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && (allowAny || allowed[strings.ToLower(origin)]) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, "+HeaderRequestID)
				h.Set("Access-Control-Expose-Headers", HeaderRequestID)
				h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
