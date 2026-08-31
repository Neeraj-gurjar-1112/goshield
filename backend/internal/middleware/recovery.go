package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/neerajgurjar/goshield/backend/internal/handler"
)

// Recovery turns a panic into a 500 error envelope. The stack trace goes to the
// log and never to the client.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					// The caller went away mid-response; nothing to report.
					panic(rec)
				}

				logger.ErrorContext(r.Context(), "recovered from panic",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				handler.WriteError(w, http.StatusInternalServerError,
					handler.CodeInternal, "Something went wrong")
			}()

			next.ServeHTTP(w, r)
		})
	}
}
