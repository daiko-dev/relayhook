package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
)

func handleListDeliveries(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		filter := domain.DeliveryFilter{
			EndpointID: strings.TrimSpace(q.Get("endpoint_id")),
			EventID:    strings.TrimSpace(q.Get("event_id")),
		}

		if st := strings.TrimSpace(q.Get("status")); st != "" {
			upperStatus := domain.DeliveryStatus(strings.ToUpper(st))
			switch upperStatus {
			case domain.StatusQueued, domain.StatusProcessing, domain.StatusDelivered, domain.StatusFailed, domain.StatusDeadLetter:
				filter.Status = upperStatus
			default:
				writeError(w, http.StatusBadRequest, "invalid status filter")
				return
			}
		}

		deliveries, err := store.ListDeliveries(r.Context(), filter)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		if deliveries == nil {
			deliveries = make([]*domain.DeliveryAttempt, 0)
		}

		offset := 0
		if oStr := q.Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		}
		if offset > len(deliveries) {
			deliveries = make([]*domain.DeliveryAttempt, 0)
		} else {
			deliveries = deliveries[offset:]
		}

		if lStr := q.Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l >= 0 && l < len(deliveries) {
				deliveries = deliveries[:l]
			}
		}

		writeJSON(w, http.StatusOK, deliveries)
	}
}

func handleGetDelivery(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if strings.TrimSpace(id) == "" {
			writeError(w, http.StatusBadRequest, "delivery id is required")
			return
		}

		delivery, err := store.GetDelivery(r.Context(), id)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, delivery)
	}
}

func handleListDLQ(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := domain.DeliveryFilter{
			Status: domain.StatusDeadLetter,
		}
		deliveries, err := store.ListDeliveries(r.Context(), filter)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		if deliveries == nil {
			deliveries = make([]*domain.DeliveryAttempt, 0)
		}
		writeJSON(w, http.StatusOK, deliveries)
	}
}

func handleReplayDelivery(pool *dispatcher.WorkerPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if strings.TrimSpace(id) == "" {
			writeError(w, http.StatusBadRequest, "delivery id is required")
			return
		}

		if pool == nil {
			writeError(w, http.StatusInternalServerError, "worker pool not available")
			return
		}

		delivery, err := pool.Replay(r.Context(), id)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}

		writeJSON(w, http.StatusOK, delivery)
	}
}
