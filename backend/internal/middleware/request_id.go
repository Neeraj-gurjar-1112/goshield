// Package middleware holds the HTTP middleware chain: request ids, access
// logging, panic recovery and per-IP rate limiting.
package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// HeaderRequestID is the header a request id is read from and echoed back on.
const HeaderRequestID = "X-Request-ID"

// maxSuppliedIDLength caps an upstream-supplied id so it cannot be used to
// bloat logs.
const maxSuppliedIDLength = 64

type requestIDKey struct{}

// RequestID attaches a request id to the context and the response header,
// reusing the incoming one when a caller supplied it.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if id == "" || len(id) > maxSuppliedIDLength {
			id = uuid.NewString()
		}

		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// WithRequestID stores a request id on the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request id on the context, or an empty string.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
