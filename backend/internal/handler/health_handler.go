package handler

import "net/http"

// Version is the service version reported by the health endpoint.
const Version = "1.0.0"

// HealthResponse is the payload returned by GET /health.
type HealthResponse struct {
	Status  string `json:"status" example:"ok"`
	Service string `json:"service" example:"goshield"`
	Version string `json:"version" example:"1.0.0"`
}

// HealthHandler serves liveness information about the service.
type HealthHandler struct{}

// NewHealthHandler builds a HealthHandler.
func NewHealthHandler() *HealthHandler { return &HealthHandler{} }

// Health responds with the service status.
//
//	@Summary		Health check
//	@Description	Liveness probe for the service.
//	@Tags			system
//	@Produce		json
//	@Success		200	{object}	HealthResponse
//	@Router			/health [get]
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Service: "goshield",
		Version: Version,
	})
}
