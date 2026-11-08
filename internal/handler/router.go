package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/middleware"
	"github.com/daiko-dev/relayhook/internal/observability"
)

type RouterDeps struct {
	Store      domain.Store
	WorkerPool *dispatcher.WorkerPool
	Metrics    *observability.Metrics
	Logger     *slog.Logger
}

func NewRouter(deps RouterDeps) http.Handler {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Metrics == nil {
		deps.Metrics = observability.NewMetrics()
	}

	mux := http.NewServeMux()

	// Probes & Observability
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz(deps.Store, deps.WorkerPool))
	mux.Handle("GET /metrics", deps.Metrics.Handler())

	// Apps
	mux.HandleFunc("POST /api/v1/apps", handleCreateApp(deps.Store))
	mux.HandleFunc("GET /api/v1/apps", handleListApps(deps.Store))
	mux.HandleFunc("GET /api/v1/apps/{id}", handleGetApp(deps.Store))

	// Endpoints
	mux.HandleFunc("POST /api/v1/apps/{id}/endpoints", handleCreateEndpoint(deps.Store, true))
	mux.HandleFunc("GET /api/v1/apps/{id}/endpoints", handleListAppEndpoints(deps.Store))
	mux.HandleFunc("POST /api/v1/endpoints", handleCreateEndpoint(deps.Store, false))
	mux.HandleFunc("GET /api/v1/endpoints", handleListEndpoints(deps.Store))
	mux.HandleFunc("GET /api/v1/endpoints/{id}", handleGetEndpoint(deps.Store))
	mux.HandleFunc("DELETE /api/v1/endpoints/{id}", handleDeleteEndpoint(deps.Store))

	// Events
	mux.HandleFunc("POST /api/v1/events", handleIngestEvent(deps.Store, deps.WorkerPool, deps.Metrics, deps.Logger))

	// Deliveries & DLQ
	mux.HandleFunc("GET /api/v1/deliveries", handleListDeliveries(deps.Store))
	mux.HandleFunc("GET /api/v1/deliveries/{id}", handleGetDelivery(deps.Store))
	mux.HandleFunc("POST /api/v1/deliveries/{id}/replay", handleReplayDelivery(deps.WorkerPool))
	mux.HandleFunc("GET /api/v1/dlq", handleListDLQ(deps.Store))
	mux.HandleFunc("POST /api/v1/dlq/{id}/replay", handleReplayDelivery(deps.WorkerPool))

	// Apply middleware stack: Recoverer -> Logging
	var handler http.Handler = mux
	handler = middleware.Logging(deps.Logger)(handler)
	handler = middleware.Recoverer(deps.Logger)(handler)

	return handler
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func mapDomainError(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, "resource not found"
	case errors.Is(err, domain.ErrDuplicate):
		return http.StatusConflict, "resource already exists"
	case errors.Is(err, domain.ErrInvalidInput):
		return http.StatusBadRequest, "invalid input"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
