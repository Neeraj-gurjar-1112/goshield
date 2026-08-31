package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/neerajgurjar/goshield/backend/internal/handler"
)

// idleTTL is how long an unused per-IP bucket is kept before it is swept, so a
// long-running server does not accumulate a limiter per address seen.
const idleTTL = 10 * time.Minute

// sweepInterval is the minimum gap between sweeps of idle buckets.
const sweepInterval = time.Minute

// bucket is one client's token bucket plus when it was last used.
type bucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter allows `limit` requests per `window` per client IP, using a token
// bucket that refills continuously rather than resetting on a fixed boundary.
type RateLimiter struct {
	limit  int
	window time.Duration

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	now       func() time.Time
}

// NewRateLimiter builds a limiter. A limit below one disables limiting.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		limit:     limit,
		window:    window,
		buckets:   make(map[string]*bucket),
		lastSweep: time.Now(),
		now:       time.Now,
	}
}

// Middleware rejects requests from a client that has exhausted its bucket with
// a 429 error envelope.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl.limit < 1 {
			next.ServeHTTP(w, r)
			return
		}

		if !rl.allow(clientIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
			handler.WriteError(w, http.StatusTooManyRequests, handler.CodeRateLimit,
				"Too many requests, please slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow takes a token from the client's bucket, creating it on first sight.
func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	rl.sweepLocked(now)

	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{
			limiter: rate.NewLimiter(rate.Limit(float64(rl.limit)/rl.window.Seconds()), rl.limit),
		}
		rl.buckets[ip] = b
	}
	b.lastSeen = now

	return b.limiter.Allow()
}

// sweepLocked drops buckets that have been idle longer than idleTTL. The caller
// must hold the mutex.
func (rl *RateLimiter) sweepLocked(now time.Time) {
	if now.Sub(rl.lastSweep) < sweepInterval {
		return
	}
	rl.lastSweep = now

	for ip, b := range rl.buckets {
		if now.Sub(b.lastSeen) > idleTTL {
			delete(rl.buckets, ip)
		}
	}
}

// Buckets returns how many client buckets are currently tracked.
func (rl *RateLimiter) Buckets() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// clientIP identifies the caller. The service is expected to be reached
// directly, so the connection address is authoritative; X-Forwarded-For is
// deliberately ignored because a client can forge it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
