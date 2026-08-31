package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON serialises v as the response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode response body", "error", err)
	}
}
