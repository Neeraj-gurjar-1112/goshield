package handler

import "net/http"

// Error codes returned in the error envelope.
const (
	CodeInvalidURL     = "INVALID_URL"
	CodeInvalidRequest = "INVALID_REQUEST"
	CodeScanNotFound   = "SCAN_NOT_FOUND"
	CodeRateLimit      = "RATE_LIMIT_EXCEEDED"
	CodeInternal       = "INTERNAL_SERVER_ERROR"
	CodeServiceUnavail = "SERVICE_UNAVAILABLE"
)

// ErrorEnvelope is the body of every non-2xx response.
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the machine readable code and a human readable message.
type ErrorBody struct {
	Code    string `json:"code" example:"INVALID_URL"`
	Message string `json:"message" example:"The provided URL is invalid"`
}

// WriteError renders the standard error envelope. It is exported so the
// middleware chain can produce the same shape as the handlers.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorEnvelope{Error: ErrorBody{Code: code, Message: message}})
}

// writeError is the in-package alias for WriteError.
func writeError(w http.ResponseWriter, status int, code, message string) {
	WriteError(w, status, code, message)
}
