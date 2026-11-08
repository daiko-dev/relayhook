package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/observability"
	"github.com/daiko-dev/relayhook/internal/queue"
	"github.com/daiko-dev/relayhook/internal/security"
	"github.com/daiko-dev/relayhook/internal/storage/memory"
)

func waitForStatus(t *testing.T, store domain.Store, deliveryID string, want domain.DeliveryStatus, timeout time.Duration) *domain.DeliveryAttempt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		d, err := store.GetDelivery(context.Background(), deliveryID)
		if err == nil && d.Status == want {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
	d, _ := store.GetDelivery(context.Background(), deliveryID)
	t.Fatalf("timed out waiting for delivery %s to reach %s (current: %+v)", deliveryID, want, d)
	return nil
}

func TestWebhookClient_SignedHeadersAnd64KBTruncate(t *testing.T) {
	secret := "whsec_test_secret_123"
	payload := []byte(`{"order_id":"ord_99","amount":4200}`)

	var gotMethod, gotCT, gotUA, gotID, gotEvent, gotTS, gotSig string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		gotID = r.Header.Get("X-RelayHook-ID")
		gotEvent = r.Header.Get("X-RelayHook-Event")
		gotTS = r.Header.Get("X-RelayHook-Timestamp")
		gotSig = r.Header.Get("X-RelayHook-Signature")
		gotBody, _ = io.ReadAll(r.Body)

		// Write 128KB response body to verify 64KB LimitReader cap.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("A"), 128*1024))
	}))
	defer srv.Close()

	client := NewWebhookClient(2 * time.Second)
	defer client.CloseIdleConnections()

	res := client.Send(context.Background(), DeliveryRequest{
		DeliveryID: "del-101",
		EventID:    "evt-101",
		EventType:  "order.completed",
		URL:        srv.URL,
		Secret:     secret,
		Payload:    payload,
	})

	if res.Err != nil {
		t.Fatalf("unexpected Send error: %v", res.Err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if len(res.ResponseBody) != MaxResponseBodyBytes {
		t.Fatalf("expected response body capped at %d bytes, got %d", MaxResponseBodyBytes, len(res.ResponseBody))
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" || gotUA != DefaultUserAgent {
		t.Fatalf("unexpected headers: method=%s ct=%s ua=%s", gotMethod, gotCT, gotUA)
	}
	if gotID != "del-101" || gotEvent != "order.completed" {
		t.Fatalf("unexpected relayhook headers: id=%s event=%s", gotID, gotEvent)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("payload mismatch: %s", string(gotBody))
	}
	if err := security.VerifyHeaders(secret, gotSig, gotTS, gotBody, 5*time.Minute); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestWebhookClient_TimeoutAndInvalidURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewWebhookClient(30 * time.Millisecond)
	res := client.Send(context.Background(), DeliveryRequest{
		DeliveryID: "del-timeout",
		EventID:    "evt-timeout",
		EventType:  "test.timeout",
		URL:        srv.URL,
		Secret:     "sec",
		Payload:    nil,
	})
	if res.Err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	badRes := client.Send(context.Background(), DeliveryRequest{
		DeliveryID: "del-bad-url",
		URL:        "://invalid-url",
	})
	if badRes.Err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestWorkerPool_TransientFailureRetryAndSuccess(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if n == 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := memory.NewMemoryStore()
	ctx := context.Background()
	_ = store.CreateEndpoint(ctx, &domain.Endpoint{
		ID:         "ep-flaky",
		AppID:      domain.DefaultAppID,
		URL:        srv.URL,
		Secret:     "sec_flaky",
		IsActive:   true,
		MaxRetries: 4,
	})
	_, _, _ = store.CreateEvent(ctx, &domain.Event{
		ID:        "ev-flaky",
		AppID:     domain.DefaultAppID,
		EventType: "payment.retry",
		Payload:   json.RawMessage(`{"try":true}`),
	})
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:         "del-flaky",
		EventID:    "ev-flaky",
		EndpointID: "ep-flaky",
		Status:     domain.StatusQueued,
		MaxRetries: 4,
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	metrics := observability.NewMetrics()
	q := queue.NewChannelQueue(100)
	sched := queue.NewScheduler(q)

	wp := NewWorkerPool(WorkerPoolConfig{
		WorkerCount: 2,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		MaxRetries:  4,
	}, store, q, sched, NewWebhookClient(time.Second), nil, metrics, logger)

	wp.Start()
	defer wp.Stop()

	if !wp.IsRunning() {
		t.Fatal("expected WorkerPool IsRunning() == true")
	}
	if metrics.ActiveWorkers() != 2 {
		t.Fatalf("expected 2 active workers, got %d", metrics.ActiveWorkers())
	}

	if err := wp.Enqueue("del-flaky"); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	d := waitForStatus(t, store, "del-flaky", domain.StatusDelivered, 2*time.Second)
	wp.Stop()

	if d.AttemptCount != 3 {
		t.Fatalf("expected 3 attempts, got %d", d.AttemptCount)
	}
	if d.LastError != "" || d.NextRetryAt != nil {
		t.Fatalf("expected clean LastError and nil NextRetryAt on DELIVERED, got err=%q next=%v", d.LastError, d.NextRetryAt)
	}
	if metrics.DeliveriesTotal("delivered") != 1 || metrics.DeliveriesTotal("failed") != 2 || metrics.RetryAttemptsTotal() != 2 {
		t.Fatalf("unexpected metrics: delivered=%d failed=%d retries=%d",
			metrics.DeliveriesTotal("delivered"), metrics.DeliveriesTotal("failed"), metrics.RetryAttemptsTotal())
	}
	if !strings.Contains(logBuf.String(), `"event_id":"ev-flaky"`) || !strings.Contains(logBuf.String(), `"delivery_id":"del-flaky"`) {
		t.Fatalf("expected structured logs to contain event_id and delivery_id, got:\n%s", logBuf.String())
	}
}

func TestWorkerPool_DLQTransitionAndManualReplay(t *testing.T) {
	var shouldSucceed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldSucceed.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	store := memory.NewMemoryStore()
	ctx := context.Background()
	_ = store.CreateEndpoint(ctx, &domain.Endpoint{
		ID:         "ep-dlq",
		AppID:      domain.DefaultAppID,
		URL:        srv.URL,
		Secret:     "sec_dlq",
		IsActive:   true,
		MaxRetries: 3,
	})
	_, _, _ = store.CreateEvent(ctx, &domain.Event{
		ID:        "ev-dlq",
		AppID:     domain.DefaultAppID,
		EventType: "invoice.failed",
		Payload:   json.RawMessage(`{"id":1}`),
	})
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:         "del-dlq",
		EventID:    "ev-dlq",
		EndpointID: "ep-dlq",
		Status:     domain.StatusQueued,
		MaxRetries: 3,
	})

	metrics := observability.NewMetrics()
	wp := NewWorkerPool(WorkerPoolConfig{
		WorkerCount: 2,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    15 * time.Millisecond,
		MaxRetries:  3,
	}, store, nil, nil, nil, nil, metrics, nil)

	wp.Start()
	defer wp.Stop()

	if err := wp.Enqueue("del-dlq"); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	d := waitForStatus(t, store, "del-dlq", domain.StatusDeadLetter, 2*time.Second)
	if d.AttemptCount != 3 || d.NextRetryAt != nil {
		t.Fatalf("expected AttemptCount=3 and NextRetryAt=nil in DEAD_LETTER, got %+v", d)
	}
	if metrics.DeliveriesTotal("dead_letter") != 1 {
		t.Fatalf("expected dead_letter metric == 1, got %d", metrics.DeliveriesTotal("dead_letter"))
	}

	// Now fix the receiver and trigger manual Replay.
	shouldSucceed.Store(true)
	replayed, err := wp.Replay(ctx, "del-dlq")
	if err != nil {
		t.Fatalf("Replay failed: %v", err)
	}
	if replayed.Status != domain.StatusQueued || replayed.AttemptCount != 0 || replayed.LastError != "" {
		t.Fatalf("expected Replay snapshot to have QUEUED, AttemptCount=0, LastError='', got %+v", replayed)
	}

	delivered := waitForStatus(t, store, "del-dlq", domain.StatusDelivered, 2*time.Second)
	if delivered.AttemptCount != 1 {
		t.Fatalf("expected 1 attempt after replay, got %d", delivered.AttemptCount)
	}

	if _, err := wp.Replay(ctx, "non-existent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing delivery replay, got %v", err)
	}
}

func TestWorkerPool_CircuitBreakerOpenSkipsNetworkIO(t *testing.T) {
	var httpCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := memory.NewMemoryStore()
	ctx := context.Background()
	_ = store.CreateEndpoint(ctx, &domain.Endpoint{
		ID:         "ep-cb",
		AppID:      domain.DefaultAppID,
		URL:        srv.URL,
		Secret:     "sec_cb",
		IsActive:   true,
		MaxRetries: 2,
	})
	_, _, _ = store.CreateEvent(ctx, &domain.Event{
		ID:        "ev-cb",
		AppID:     domain.DefaultAppID,
		EventType: "cb.test",
		Payload:   json.RawMessage(`{}`),
	})

	metrics := observability.NewMetrics()
	breakers := NewCircuitBreakerRegistry(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     30 * time.Second,
		OnStateChange: func(endpointID string, state CircuitState) {
			metrics.SetCircuitBreakerState(endpointID, int(state))
		},
	})

	wp := NewWorkerPool(WorkerPoolConfig{
		WorkerCount: 1,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		MaxRetries:  2,
	}, store, nil, nil, nil, breakers, metrics, nil)
	wp.Start()
	defer wp.Stop()

	// First delivery fails twice -> trips breaker (threshold = 2).
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:         "del-cb-1",
		EventID:    "ev-cb",
		EndpointID: "ep-cb",
		Status:     domain.StatusQueued,
		MaxRetries: 2,
	})
	_ = wp.Enqueue("del-cb-1")
	waitForStatus(t, store, "del-cb-1", domain.StatusDeadLetter, 2*time.Second)

	if breakers.State("ep-cb") != StateOpen {
		t.Fatalf("expected breaker to be OPEN, got %v", breakers.State("ep-cb"))
	}
	callsBefore := httpCalls.Load()

	// Second delivery (already attempted once) while breaker is OPEN must reach DEAD_LETTER with 0 additional HTTP calls.
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:           "del-cb-2",
		EventID:      "ev-cb",
		EndpointID:   "ep-cb",
		Status:       domain.StatusQueued,
		AttemptCount: 1,
		MaxRetries:   2,
	})
	_ = wp.Enqueue("del-cb-2")
	d2 := waitForStatus(t, store, "del-cb-2", domain.StatusDeadLetter, 2*time.Second)

	if httpCalls.Load() != callsBefore {
		t.Fatalf("expected 0 HTTP calls while breaker is OPEN, before=%d after=%d", callsBefore, httpCalls.Load())
	}
	if !strings.Contains(d2.LastError, "circuit breaker is open") {
		t.Fatalf("expected LastError to mention circuit breaker is open, got %q", d2.LastError)
	}
	// Third delivery with MaxRetries=3 while breaker is OPEN exercises circuit-open retry reschedule (AttemptCount < MaxRetries) before DLQ.
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:           "del-cb-3",
		EventID:      "ev-cb",
		EndpointID:   "ep-cb",
		Status:       domain.StatusQueued,
		AttemptCount: 1,
		MaxRetries:   3,
	})
	_ = wp.Enqueue("del-cb-3")
	d3 := waitForStatus(t, store, "del-cb-3", domain.StatusDeadLetter, 2*time.Second)
	if d3.AttemptCount != 3 {
		t.Fatalf("expected 3 fast-fail attempts while breaker is OPEN, got %d", d3.AttemptCount)
	}
}

func TestWorkerPool_DeletedEndpointAnd100ConcurrentEvents(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := memory.NewMemoryStore()
	ctx := context.Background()
	_ = store.CreateEndpoint(ctx, &domain.Endpoint{
		ID:         "ep-100",
		AppID:      domain.DefaultAppID,
		URL:        srv.URL,
		Secret:     "sec_100",
		IsActive:   true,
		MaxRetries: 3,
	})

	// Also create a delivery for a deleted endpoint to test graceful handling.
	_, _, _ = store.CreateEvent(ctx, &domain.Event{
		ID:        "ev-deleted-ep",
		AppID:     domain.DefaultAppID,
		EventType: "user.deleted",
		Payload:   json.RawMessage(`{}`),
	})
	_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
		ID:         "del-orphan",
		EventID:    "ev-deleted-ep",
		EndpointID: "ep-missing",
		Status:     domain.StatusQueued,
		MaxRetries: 0, // tests fallback to wp.cfg.MaxRetries
	})

	discardLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	q := queue.NewChannelQueue(1000)
	wp := NewWorkerPool(WorkerPoolConfig{
		WorkerCount: 0, // tests default WorkerCount, BaseDelay, MaxDelay, MaxRetries
	}, store, q, nil, nil, nil, nil, discardLogger)
	wp.Start()

	_ = wp.Enqueue("del-orphan")
	waitForStatus(t, store, "del-orphan", domain.StatusDeadLetter, time.Second)

	// Re-enqueuing an already DEAD_LETTER delivery or missing delivery is a safe no-op.
	_ = wp.Enqueue("del-orphan")
	_ = wp.Enqueue("del-does-not-exist")

	const total = 100
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			evID := fmt.Sprintf("ev-burst-%d", idx)
			delID := fmt.Sprintf("del-burst-%d", idx)
			_, _, _ = store.CreateEvent(ctx, &domain.Event{
				ID:        evID,
				AppID:     domain.DefaultAppID,
				EventType: "burst.event",
				Payload:   json.RawMessage(fmt.Sprintf(`{"seq":%d}`, idx)),
			})
			_ = store.CreateDelivery(ctx, &domain.DeliveryAttempt{
				ID:         delID,
				EventID:    evID,
				EndpointID: "ep-100",
				Status:     domain.StatusQueued,
				MaxRetries: 3,
			})
			if err := wp.Enqueue(delID); err != nil {
				t.Errorf("Enqueue %s failed: %v", delID, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < total; i++ {
		waitForStatus(t, store, fmt.Sprintf("del-burst-%d", i), domain.StatusDelivered, 5*time.Second)
	}
	if got := received.Load(); got != total {
		t.Fatalf("expected %d deliveries received, got %d", total, got)
	}

	q.Close()
	wp.Stop()
	if wp.IsRunning() {
		t.Fatal("expected IsRunning() == false after Stop()")
	}
	if err := wp.Enqueue("del-after-stop"); !errors.Is(err, domain.ErrQueueClosed) {
		t.Fatalf("expected ErrQueueClosed after Stop(), got %v", err)
	}
}
