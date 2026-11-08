package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/handler"
	"github.com/daiko-dev/relayhook/internal/observability"
	"github.com/daiko-dev/relayhook/internal/storage/memory"
)

func setupTestRouter(t *testing.T) (http.Handler, domain.Store, *dispatcher.WorkerPool, *observability.Metrics) {
	t.Helper()
	store := memory.NewMemoryStore()
	metrics := observability.NewMetrics()
	pool := dispatcher.NewWorkerPool(dispatcher.WorkerPoolConfig{
		WorkerCount: 2,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    50 * time.Millisecond,
		MaxRetries:  3,
	}, store, nil, nil, nil, nil, metrics, nil)
	pool.Start()
	t.Cleanup(func() {
		pool.Stop()
		_ = store.Close()
	})

	router := handler.NewRouter(handler.RouterDeps{
		Store:      store,
		WorkerPool: pool,
		Metrics:    metrics,
	})
	return router, store, pool, metrics
}

func doReq(router http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = bytes.NewReader([]byte(v))
		case []byte:
			bodyReader = bytes.NewReader(v)
		default:
			b, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(b)
		}
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestHandler_HealthzAndReadyzAndMetrics(t *testing.T) {
	router, _, _, _ := setupTestRouter(t)

	rrHealth := doReq(router, http.MethodGet, "/healthz", nil, nil)
	if rrHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /healthz, got %d", rrHealth.Code)
	}

	rrReady := doReq(router, http.MethodGet, "/readyz", nil, nil)
	if rrReady.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /readyz, got %d", rrReady.Code)
	}

	rrMetrics := doReq(router, http.MethodGet, "/metrics", nil, nil)
	if rrMetrics.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", rrMetrics.Code)
	}
	if !bytes.Contains(rrMetrics.Body.Bytes(), []byte("relayhook_events_ingested_total")) {
		t.Fatal("expected metrics body to contain relayhook_events_ingested_total")
	}
}

func TestHandler_AppCRUD(t *testing.T) {
	router, _, _, _ := setupTestRouter(t)

	// Create App
	rrCreate := doReq(router, http.MethodPost, "/api/v1/apps", map[string]any{"id": "app-test-1", "name": "Test App"}, nil)
	if rrCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rrCreate.Code, rrCreate.Body.String())
	}

	// Duplicate App -> 409
	rrDup := doReq(router, http.MethodPost, "/api/v1/apps", map[string]any{"id": "app-test-1", "name": "Test App"}, nil)
	if rrDup.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d", rrDup.Code)
	}

	// Empty Name -> 400
	rrEmpty := doReq(router, http.MethodPost, "/api/v1/apps", map[string]any{"name": ""}, nil)
	if rrEmpty.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rrEmpty.Code)
	}

	// Get App
	rrGet := doReq(router, http.MethodGet, "/api/v1/apps/app-test-1", nil, nil)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrGet.Code)
	}

	// Get Missing App -> 404
	rrGet404 := doReq(router, http.MethodGet, "/api/v1/apps/non-existent-app", nil, nil)
	if rrGet404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rrGet404.Code)
	}

	// List Apps
	rrList := doReq(router, http.MethodGet, "/api/v1/apps", nil, nil)
	if rrList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrList.Code)
	}
	var apps []*domain.App
	_ = json.Unmarshal(rrList.Body.Bytes(), &apps)
	if len(apps) < 2 { // default app + app-test-1
		t.Fatalf("expected at least 2 apps, got %d", len(apps))
	}
}

func TestHandler_EndpointCRUD(t *testing.T) {
	router, _, _, _ := setupTestRouter(t)

	// Create endpoint under app in path
	rrEP1 := doReq(router, http.MethodPost, "/api/v1/apps/default/endpoints", map[string]any{
		"url":         "https://example.com/webhook",
		"event_types": []string{"order.created"},
	}, nil)
	if rrEP1.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rrEP1.Code, rrEP1.Body.String())
	}
	var ep1 domain.Endpoint
	_ = json.Unmarshal(rrEP1.Body.Bytes(), &ep1)
	if ep1.Secret == "" || !ep1.IsActive || ep1.MaxRetries != 5 {
		t.Fatalf("unexpected ep defaults: %+v", ep1)
	}

	// Create endpoint without path app_id -> defaults to "default"
	rrEP2 := doReq(router, http.MethodPost, "/api/v1/endpoints", map[string]any{
		"url": "https://example.com/webhook2",
	}, nil)
	if rrEP2.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rrEP2.Code, rrEP2.Body.String())
	}

	// List endpoints
	rrList := doReq(router, http.MethodGet, "/api/v1/endpoints", nil, nil)
	if rrList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrList.Code)
	}

	// Get endpoint
	rrGet := doReq(router, http.MethodGet, "/api/v1/endpoints/"+ep1.ID, nil, nil)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrGet.Code)
	}

	// Delete endpoint
	rrDel := doReq(router, http.MethodDelete, "/api/v1/endpoints/"+ep1.ID, nil, nil)
	if rrDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrDel.Code)
	}
}

func TestHandler_EventIngestAndIdempotency(t *testing.T) {
	router, store, _, _ := setupTestRouter(t)

	// Create endpoint subscribed to "user.*" or "*"
	_ = store.CreateEndpoint(context.Background(), &domain.Endpoint{
		ID:         "ep-ingest-1",
		AppID:      "default",
		URL:        "http://127.0.0.1:9999/wh",
		Secret:     "whsec_test",
		EventTypes: []string{"user.created"},
		IsActive:   true,
		MaxRetries: 3,
		CreatedAt:  time.Now(),
	})

	// Ingest event with idempotency key
	rrEv1 := doReq(router, http.MethodPost, "/api/v1/events", map[string]any{
		"event_type":      "user.created",
		"payload":         map[string]any{"user_id": 42},
		"idempotency_key": "idem-key-test-1",
	}, nil)
	if rrEv1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rrEv1.Code, rrEv1.Body.String())
	}

	var resp1 struct {
		EventID     string   `json:"event_id"`
		DeliveryIDs []string `json:"delivery_ids"`
	}
	_ = json.Unmarshal(rrEv1.Body.Bytes(), &resp1)
	if resp1.EventID == "" || len(resp1.DeliveryIDs) != 1 {
		t.Fatalf("expected non-empty event_id and 1 delivery_id, got %+v", resp1)
	}

	// Re-ingest with same idempotency key -> returns existing event and deliveries
	rrEv2 := doReq(router, http.MethodPost, "/api/v1/events", map[string]any{
		"event_type":      "user.created",
		"payload":         map[string]any{"user_id": 42},
		"idempotency_key": "idem-key-test-1",
	}, nil)
	if rrEv2.Code != http.StatusOK && rrEv2.Code != http.StatusAccepted {
		t.Fatalf("expected 200/202 from idempotent ingest, got %d: %s", rrEv2.Code, rrEv2.Body.String())
	}
	var resp2 struct {
		EventID     string   `json:"event_id"`
		DeliveryIDs []string `json:"delivery_ids"`
	}
	_ = json.Unmarshal(rrEv2.Body.Bytes(), &resp2)
	if resp2.EventID != resp1.EventID || len(resp2.DeliveryIDs) != len(resp1.DeliveryIDs) {
		t.Fatalf("expected identical event_id %q and deliveries %v, got %+v", resp1.EventID, resp1.DeliveryIDs, resp2)
	}
}

func TestHandler_DeliveriesAndDLQAndReplay(t *testing.T) {
	router, store, _, _ := setupTestRouter(t)

	dlv := &domain.DeliveryAttempt{
		ID:           "dlv-test-replay",
		EventID:      "ev-test-1",
		EndpointID:   "ep-test-1",
		Status:       domain.StatusDeadLetter,
		AttemptCount: 3,
		MaxRetries:   3,
		StatusCode:   500,
		LastError:    "server error 500",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	_ = store.CreateDelivery(context.Background(), dlv)

	// List Deliveries
	rrList := doReq(router, http.MethodGet, "/api/v1/deliveries", nil, nil)
	if rrList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrList.Code)
	}

	// List DLQ
	rrDLQ := doReq(router, http.MethodGet, "/api/v1/dlq", nil, nil)
	if rrDLQ.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/dlq, got %d", rrDLQ.Code)
	}
	var dlqItems []*domain.DeliveryAttempt
	_ = json.Unmarshal(rrDLQ.Body.Bytes(), &dlqItems)
	if len(dlqItems) != 1 || dlqItems[0].ID != dlv.ID {
		t.Fatalf("expected 1 item in DLQ matching ID %q, got %v", dlv.ID, dlqItems)
	}

	// Replay delivery
	rrReplay := doReq(router, http.MethodPost, "/api/v1/deliveries/"+dlv.ID+"/replay", nil, nil)
	if rrReplay.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from replay, got %d: %s", rrReplay.Code, rrReplay.Body.String())
	}
	var replayed domain.DeliveryAttempt
	_ = json.Unmarshal(rrReplay.Body.Bytes(), &replayed)
	if replayed.Status != domain.StatusQueued || replayed.AttemptCount != 0 {
		t.Fatalf("expected status=QUEUED and attempt=0 after replay, got %+v", replayed)
	}
}

func BenchmarkIngestEvent(b *testing.B) {
	store := memory.NewMemoryStore()
	defer store.Close()
	metrics := observability.NewMetrics()
	pool := dispatcher.NewWorkerPool(dispatcher.WorkerPoolConfig{
		WorkerCount: 4,
	}, store, nil, nil, nil, nil, metrics, nil)
	pool.Start()
	defer pool.Stop()

	_ = store.CreateEndpoint(context.Background(), &domain.Endpoint{
		ID:         "bench-ep",
		AppID:      "default",
		URL:        "http://127.0.0.1:9099/wh",
		Secret:     "whsec_bench",
		EventTypes: []string{"*"},
		IsActive:   true,
		MaxRetries: 3,
		CreatedAt:  time.Now(),
	})

	router := handler.NewRouter(handler.RouterDeps{
		Store:      store,
		WorkerPool: pool,
		Metrics:    metrics,
	})

	payloadBytes := []byte(`{"event_type":"benchmark.run","payload":{"test":true,"num":12345}}`)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", fmt.Sprintf("idem-%d", i))
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			b.Fatalf("expected 202 Accepted, got %d", rr.Code)
		}
	}
}
