package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/observability"
)

type ingestEventRequest struct {
	AppID          string          `json:"app_id"`
	EventType      string          `json:"event_type"`
	Payload        json.RawMessage `json:"payload"`
	IdempotencyKey string          `json:"idempotency_key"`
}

type ingestEventResponse struct {
	EventID          string   `json:"event_id"`
	ID               string   `json:"id"`
	Status           string   `json:"status"`
	DeliveriesQueued int      `json:"deliveries_queued"`
	DeliveryIDs      []string `json:"delivery_ids"`
}

func handleIngestEvent(
	store domain.Store,
	pool *dispatcher.WorkerPool,
	metrics *observability.Metrics,
	logger *slog.Logger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		var req ingestEventRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		eventType := strings.TrimSpace(req.EventType)
		if eventType == "" {
			writeError(w, http.StatusBadRequest, "event_type is required")
			return
		}

		appID := strings.TrimSpace(req.AppID)
		if appID == "" {
			appID = domain.DefaultAppID
		}

		idempotencyKey := strings.TrimSpace(req.IdempotencyKey)
		if idempotencyKey == "" {
			idempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		}
		if idempotencyKey == "" {
			idempotencyKey = strings.TrimSpace(r.Header.Get("X-Idempotency-Key"))
		}

		payload := req.Payload
		if len(payload) == 0 || string(payload) == "null" {
			writeError(w, http.StatusBadRequest, "payload is required")
			return
		}
		if !json.Valid(payload) {
			writeError(w, http.StatusBadRequest, "invalid payload json")
			return
		}

		event := &domain.Event{
			ID:             randomID("evt_"),
			AppID:          appID,
			EventType:      eventType,
			Payload:        payload,
			IdempotencyKey: idempotencyKey,
			CreatedAt:      time.Now().UTC(),
		}

		ev, created, err := store.CreateEvent(r.Context(), event)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}

		if !created {
			// Idempotent duplicate: fetch existing deliveries
			dlvs, err := store.ListDeliveries(r.Context(), domain.DeliveryFilter{EventID: ev.ID})
			deliveryIDs := make([]string, 0, len(dlvs))
			if err == nil {
				for _, d := range dlvs {
					deliveryIDs = append(deliveryIDs, d.ID)
				}
			}
			writeJSON(w, http.StatusOK, ingestEventResponse{
				EventID:          ev.ID,
				ID:               ev.ID,
				Status:           "queued",
				DeliveriesQueued: len(deliveryIDs),
				DeliveryIDs:      deliveryIDs,
			})
			return
		}

		if metrics != nil {
			metrics.IncEventsIngested()
		}

		// Find matching active endpoints
		endpoints, err := store.ListEndpoints(r.Context(), ev.AppID)
		if err != nil {
			logger.Error("failed to list endpoints for app", "app_id", ev.AppID, "error", err)
			endpoints = nil
		}

		deliveryIDs := make([]string, 0)
		for _, ep := range endpoints {
			if !ep.IsActive {
				continue
			}
			if !matchesEventType(ep.EventTypes, ev.EventType) {
				continue
			}

			maxRetries := ep.MaxRetries
			if maxRetries <= 0 {
				maxRetries = domain.DefaultMaxRetries
			}

			dlv := &domain.DeliveryAttempt{
				ID:           randomID("dlv_"),
				EventID:      ev.ID,
				EndpointID:   ep.ID,
				Status:       domain.StatusQueued,
				AttemptCount: 0,
				MaxRetries:   maxRetries,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}

			if err := store.CreateDelivery(r.Context(), dlv); err != nil {
				logger.Error("failed to create delivery attempt", "event_id", ev.ID, "endpoint_id", ep.ID, "error", err)
				continue
			}

			if pool != nil {
				if err := pool.Enqueue(dlv.ID); err != nil {
					logger.Error("failed to enqueue delivery", "delivery_id", dlv.ID, "error", err)
				}
			}
			deliveryIDs = append(deliveryIDs, dlv.ID)
		}

		writeJSON(w, http.StatusAccepted, ingestEventResponse{
			EventID:          ev.ID,
			ID:               ev.ID,
			Status:           "queued",
			DeliveriesQueued: len(deliveryIDs),
			DeliveryIDs:      deliveryIDs,
		})
	}
}

func matchesEventType(subscribed []string, eventType string) bool {
	if len(subscribed) == 0 {
		return true
	}
	for _, sub := range subscribed {
		sub = strings.TrimSpace(sub)
		if sub == "*" || sub == "" || sub == eventType {
			return true
		}
	}
	return false
}
