package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

func TestNewMemoryStore_DefaultAppPreSeeded(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	app, err := s.GetApp(ctx, domain.DefaultAppID)
	if err != nil {
		t.Fatalf("expected default app, got error: %v", err)
	}
	if app.ID != domain.DefaultAppID || app.Name != "Default App" || app.CreatedAt.IsZero() {
		t.Fatalf("unexpected default app: %+v", app)
	}

	apps, err := s.ListApps(ctx)
	if err != nil {
		t.Fatalf("ListApps failed: %v", err)
	}
	if len(apps) != 1 || apps[0].ID != domain.DefaultAppID {
		t.Fatalf("expected 1 default app in ListApps, got %+v", apps)
	}
}

func TestMemoryStore_AppCRUD(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if err := s.CreateApp(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for nil app, got %v", err)
	}
	if err := s.CreateApp(ctx, &domain.App{ID: "", Name: "X"}); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty ID, got %v", err)
	}
	if _, err := s.GetApp(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty GetApp id, got %v", err)
	}

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	app1 := &domain.App{ID: "app-b", Name: "App B", CreatedAt: t1}
	app2 := &domain.App{ID: "app-a", Name: "App A", CreatedAt: t1}
	app3 := &domain.App{ID: "app-c", Name: "App C"} // zero CreatedAt auto-populated
	if err := s.CreateApp(ctx, app1); err != nil {
		t.Fatalf("CreateApp app1 failed: %v", err)
	}
	if err := s.CreateApp(ctx, app2); err != nil {
		t.Fatalf("CreateApp app2 failed: %v", err)
	}
	if err := s.CreateApp(ctx, app3); err != nil {
		t.Fatalf("CreateApp app3 failed: %v", err)
	}

	if err := s.CreateApp(ctx, app1); !errors.Is(err, domain.ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	if _, err := s.GetApp(ctx, "nonexistent"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	apps, err := s.ListApps(ctx)
	if err != nil {
		t.Fatalf("ListApps failed: %v", err)
	}
	if len(apps) != 4 {
		t.Fatalf("expected 4 apps, got %d", len(apps))
	}
	if apps[0].ID != "app-a" || apps[1].ID != "app-b" {
		t.Fatalf("unexpected sort order: %s, %s", apps[0].ID, apps[1].ID)
	}
}

func TestMemoryStore_EndpointCRUDAndDefaults(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if err := s.CreateEndpoint(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, err := s.GetEndpoint(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty GetEndpoint ID, got %v", err)
	}
	if err := s.DeleteEndpoint(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty DeleteEndpoint ID, got %v", err)
	}

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ep1 := &domain.Endpoint{
		ID:       "ep-1",
		URL:      "https://example.com/wh1",
		Secret:   "sec1",
		IsActive: true,
	}
	if err := s.CreateEndpoint(ctx, ep1); err != nil {
		t.Fatalf("CreateEndpoint failed: %v", err)
	}
	if ep1.AppID != "" {
		t.Fatalf("expected caller ep1.AppID to remain untouched, got %q", ep1.AppID)
	}

	got, err := s.GetEndpoint(ctx, "ep-1")
	if err != nil {
		t.Fatalf("GetEndpoint failed: %v", err)
	}
	if got.AppID != domain.DefaultAppID || got.MaxRetries != domain.DefaultMaxRetries || got.EventTypes == nil {
		t.Fatalf("unexpected endpoint defaults: %+v", got)
	}

	if err := s.CreateEndpoint(ctx, ep1); !errors.Is(err, domain.ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	ep2 := &domain.Endpoint{
		ID:         "ep-2",
		AppID:      "app-2",
		URL:        "https://example.com/wh2",
		Secret:     "sec2",
		EventTypes: []string{"user.created"},
		IsActive:   true,
		MaxRetries: 3,
		CreatedAt:  t1,
	}
	ep3 := &domain.Endpoint{
		ID:         "ep-0",
		AppID:      "app-2",
		URL:        "https://example.com/wh0",
		Secret:     "sec0",
		EventTypes: []string{"*"},
		IsActive:   true,
		MaxRetries: 3,
		CreatedAt:  t1,
	}
	if err := s.CreateEndpoint(ctx, ep2); err != nil {
		t.Fatalf("CreateEndpoint ep2 failed: %v", err)
	}
	if err := s.CreateEndpoint(ctx, ep3); err != nil {
		t.Fatalf("CreateEndpoint ep3 failed: %v", err)
	}

	allEps, err := s.ListEndpoints(ctx, "")
	if err != nil || len(allEps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d (err=%v)", len(allEps), err)
	}
	defEps, err := s.ListEndpoints(ctx, domain.DefaultAppID)
	if err != nil || len(defEps) != 1 || defEps[0].ID != "ep-1" {
		t.Fatalf("unexpected default endpoints: %+v (err=%v)", defEps, err)
	}
	app2Eps, err := s.ListEndpoints(ctx, "app-2")
	if err != nil || len(app2Eps) != 2 || app2Eps[0].ID != "ep-0" || app2Eps[1].ID != "ep-2" {
		t.Fatalf("unexpected app-2 endpoints: %+v (err=%v)", app2Eps, err)
	}

	if err := s.DeleteEndpoint(ctx, "ep-1"); err != nil {
		t.Fatalf("DeleteEndpoint failed: %v", err)
	}
	if _, err := s.GetEndpoint(ctx, "ep-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := s.DeleteEndpoint(ctx, "ep-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
}

func TestMemoryStore_CreateEventIdempotency(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if _, _, err := s.CreateEvent(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for nil event, got %v", err)
	}
	if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "bad", EventType: "test", Payload: json.RawMessage(`{invalid`)}); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for invalid JSON payload, got %v", err)
	}
	if _, err := s.GetEvent(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput for empty GetEvent ID, got %v", err)
	}
	if _, err := s.GetEvent(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing event, got %v", err)
	}

	t1 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	ev1 := &domain.Event{
		ID:             "ev-1",
		AppID:          domain.DefaultAppID,
		EventType:      "order.created",
		Payload:        json.RawMessage(`{"id":1}`),
		IdempotencyKey: "idem-123",
		CreatedAt:      t1,
	}
	out1, created, err := s.CreateEvent(ctx, ev1)
	if err != nil || !created || out1.ID != "ev-1" {
		t.Fatalf("expected created=true for ev-1, got created=%v, err=%v", created, err)
	}

	// Duplicate IdempotencyKey in same app -> returns existing ev-1 with created=false
	ev2 := &domain.Event{
		ID:             "ev-2",
		AppID:          domain.DefaultAppID,
		EventType:      "order.created",
		Payload:        json.RawMessage(`{"id":2}`),
		IdempotencyKey: "idem-123",
	}
	out2, created, err := s.CreateEvent(ctx, ev2)
	if err != nil || created || out2.ID != "ev-1" {
		t.Fatalf("expected idempotent hit returning ev-1, got %+v, created=%v, err=%v", out2, created, err)
	}

	// Same IdempotencyKey in different app -> creates new event
	ev3 := &domain.Event{
		ID:             "ev-3",
		AppID:          "app-2",
		EventType:      "order.created",
		Payload:        json.RawMessage(`{"id":3}`),
		IdempotencyKey: "idem-123",
	}
	out3, created, err := s.CreateEvent(ctx, ev3)
	if err != nil || !created || out3.ID != "ev-3" {
		t.Fatalf("expected created=true for different AppID, got %+v, created=%v, err=%v", out3, created, err)
	}

	// Empty IdempotencyKey multiple times -> both succeed
	for i := 4; i <= 5; i++ {
		ev := &domain.Event{
			ID:        fmt.Sprintf("ev-%d", i),
			EventType: "ping",
		}
		_, created, err := s.CreateEvent(ctx, ev)
		if err != nil || !created {
			t.Fatalf("expected created=true for empty IdempotencyKey event %d, got err=%v", i, err)
		}
	}

	// Duplicate event ID without IdempotencyKey -> ErrDuplicate
	if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "ev-4", EventType: "ping"}); !errors.Is(err, domain.ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate for duplicate event ID, got %v", err)
	}
}

func TestMemoryStore_DeliveryLifecycleAndFiltering(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if err := s.CreateDelivery(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, err := s.GetDelivery(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, err := s.GetDelivery(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := s.UpdateDelivery(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{ID: "missing"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	t1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	zeroTime := time.Time{}
	d1 := &domain.DeliveryAttempt{
		ID:          "del-2",
		EventID:     "ev-1",
		EndpointID:  "ep-1",
		NextRetryAt: &zeroTime,
		CreatedAt:   t1,
		UpdatedAt:   t1,
	}
	d2 := &domain.DeliveryAttempt{
		ID:         "del-1",
		EventID:    "ev-1",
		EndpointID: "ep-2",
		Status:     domain.StatusDelivered,
		CreatedAt:  t1,
	}
	d3 := &domain.DeliveryAttempt{
		ID:         "del-3",
		EventID:    "ev-2",
		EndpointID: "ep-1",
		Status:     domain.StatusDeadLetter,
	}
	for _, d := range []*domain.DeliveryAttempt{d1, d2, d3} {
		if err := s.CreateDelivery(ctx, d); err != nil {
			t.Fatalf("CreateDelivery %s failed: %v", d.ID, err)
		}
	}
	if err := s.CreateDelivery(ctx, d1); !errors.Is(err, domain.ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	retryAt := time.Now().UTC().Add(30 * time.Second)
	upd := &domain.DeliveryAttempt{
		ID:           "del-2",
		Status:       domain.StatusFailed,
		AttemptCount: 2,
		StatusCode:   502,
		ResponseTime: 145,
		LastError:    "bad gateway",
		NextRetryAt:  &retryAt,
		CreatedAt:    t1,
		UpdatedAt:    retryAt,
	}
	if err := s.UpdateDelivery(ctx, upd); err != nil {
		t.Fatalf("UpdateDelivery failed: %v", err)
	}

	got, err := s.GetDelivery(ctx, "del-2")
	if err != nil {
		t.Fatalf("GetDelivery failed: %v", err)
	}
	if got.Status != domain.StatusFailed || got.AttemptCount != 2 || got.EventID != "ev-1" || got.EndpointID != "ep-1" || got.MaxRetries != domain.DefaultMaxRetries {
		t.Fatalf("unexpected updated delivery: %+v", got)
	}
	if got.NextRetryAt == nil || !got.NextRetryAt.Equal(retryAt) {
		t.Fatalf("NextRetryAt mismatch: got %v, want %v", got.NextRetryAt, retryAt)
	}

	// Clear NextRetryAt using zero time pointer
	if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{
		ID:          "del-2",
		Status:      domain.StatusDelivered,
		NextRetryAt: &zeroTime,
	}); err != nil {
		t.Fatalf("UpdateDelivery zero time failed: %v", err)
	}
	gotCleared, _ := s.GetDelivery(ctx, "del-2")
	if gotCleared.NextRetryAt != nil {
		t.Fatalf("expected nil NextRetryAt after clearing, got %v", gotCleared.NextRetryAt)
	}

	dlq, err := s.ListDeliveries(ctx, domain.DeliveryFilter{Status: domain.StatusDeadLetter})
	if err != nil || len(dlq) != 1 || dlq[0].ID != "del-3" {
		t.Fatalf("expected 1 DEAD_LETTER delivery, got %+v (err=%v)", dlq, err)
	}

	byEp, err := s.ListDeliveries(ctx, domain.DeliveryFilter{EndpointID: "ep-1"})
	if err != nil || len(byEp) != 2 {
		t.Fatalf("expected 2 deliveries for ep-1, got %d", len(byEp))
	}

	byEvAndEp, err := s.ListDeliveries(ctx, domain.DeliveryFilter{EventID: "ev-1", EndpointID: "ep-2"})
	if err != nil || len(byEvAndEp) != 1 || byEvAndEp[0].ID != "del-1" {
		t.Fatalf("expected del-1, got %+v", byEvAndEp)
	}
}

func TestMemoryStore_DeepCopyIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if copyApp(nil) != nil || copyEndpoint(nil) != nil || copyEvent(nil) != nil || copyDelivery(nil) != nil {
		t.Fatalf("expected copy helpers to return nil on nil input")
	}

	tags := []string{"a.b", "c.d"}
	ep := &domain.Endpoint{ID: "ep-iso", URL: "https://example.com", EventTypes: tags}
	if err := s.CreateEndpoint(ctx, ep); err != nil {
		t.Fatalf("CreateEndpoint failed: %v", err)
	}
	tags[0] = "mutated"
	gotEp, _ := s.GetEndpoint(ctx, "ep-iso")
	if gotEp.EventTypes[0] != "a.b" {
		t.Fatalf("CreateEndpoint did not deep-copy EventTypes: %v", gotEp.EventTypes)
	}
	gotEp.EventTypes[0] = "mutated-again"
	gotEp2, _ := s.GetEndpoint(ctx, "ep-iso")
	if gotEp2.EventTypes[0] != "a.b" {
		t.Fatalf("GetEndpoint did not deep-copy EventTypes: %v", gotEp2.EventTypes)
	}

	raw := json.RawMessage(`{"ok":true}`)
	ev := &domain.Event{ID: "ev-iso", EventType: "test", Payload: raw}
	_, _, err := s.CreateEvent(ctx, ev)
	if err != nil {
		t.Fatalf("CreateEvent failed: %v", err)
	}
	raw[2] = 'X'
	gotEv, _ := s.GetEvent(ctx, "ev-iso")
	if string(gotEv.Payload) != `{"ok":true}` {
		t.Fatalf("CreateEvent did not deep-copy Payload: %s", gotEv.Payload)
	}
	gotEv.Payload[2] = 'Y'
	gotEv2, _ := s.GetEvent(ctx, "ev-iso")
	if string(gotEv2.Payload) != `{"ok":true}` {
		t.Fatalf("GetEvent did not deep-copy Payload: %s", gotEv2.Payload)
	}

	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	retryVar := t0
	del := &domain.DeliveryAttempt{ID: "del-iso", EventID: "ev-iso", EndpointID: "ep-iso", NextRetryAt: &retryVar}
	if err := s.CreateDelivery(ctx, del); err != nil {
		t.Fatalf("CreateDelivery failed: %v", err)
	}
	retryVar = t0.Add(1 * time.Hour)
	gotDel, _ := s.GetDelivery(ctx, "del-iso")
	if !gotDel.NextRetryAt.Equal(t0) {
		t.Fatalf("CreateDelivery did not deep-copy NextRetryAt: %v", gotDel.NextRetryAt)
	}
	*gotDel.NextRetryAt = t0.Add(2 * time.Hour)
	gotDel2, _ := s.GetDelivery(ctx, "del-iso")
	if !gotDel2.NextRetryAt.Equal(t0) {
		t.Fatalf("GetDelivery did not deep-copy NextRetryAt: %v", gotDel2.NextRetryAt)
	}
}

func TestMemoryStore_ConcurrentAccessAndSharedPointerRace(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	const workers = 50
	var wg sync.WaitGroup

	// 1. 50 goroutines passing the EXACT SAME *domain.Event pointer to CreateEvent
	sharedEv := &domain.Event{
		ID:             "ev-shared-ptr",
		EventType:      "payment.succeeded",
		Payload:        json.RawMessage(`{"amount":100}`),
		IdempotencyKey: "shared-ptr-idem-key",
	}
	wg.Add(workers)
	createdCount := 0
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			res, created, err := s.CreateEvent(ctx, sharedEv)
			if err != nil {
				t.Errorf("CreateEvent shared pointer failed: %v", err)
				return
			}
			mu.Lock()
			if created {
				createdCount++
			}
			if res.ID != "ev-shared-ptr" {
				t.Errorf("unexpected ID %q", res.ID)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if createdCount != 1 {
		t.Fatalf("expected 1 created from shared pointer, got %d", createdCount)
	}

	// 2. 50 goroutines with distinct Event structs and same IdempotencyKey
	wg.Add(workers)
	createdCount = 0
	winningIDs := make([]string, 0, workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			ev := &domain.Event{
				ID:             fmt.Sprintf("ev-race-%d", i),
				AppID:          domain.DefaultAppID,
				EventType:      "payment.succeeded",
				Payload:        json.RawMessage(`{"amount":100}`),
				IdempotencyKey: "concurrent-key-1",
			}
			res, created, err := s.CreateEvent(ctx, ev)
			if err != nil {
				t.Errorf("CreateEvent goroutine %d failed: %v", i, err)
				return
			}
			mu.Lock()
			if created {
				createdCount++
			}
			winningIDs = append(winningIDs, res.ID)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if createdCount != 1 {
		t.Fatalf("expected exactly 1 goroutine to create event, got %d", createdCount)
	}
	for _, id := range winningIDs {
		if id != winningIDs[0] {
			t.Fatalf("inconsistent winning event ID across goroutines: %q vs %q", id, winningIDs[0])
		}
	}

	// 3. Concurrent mixed CRUD and delivery updates
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			epID := fmt.Sprintf("ep-%d", i)
			_ = s.CreateEndpoint(ctx, &domain.Endpoint{
				ID:         epID,
				URL:        "https://example.com/hook",
				EventTypes: []string{"*"},
				IsActive:   true,
			})
			_, _ = s.ListEndpoints(ctx, "")

			delID := fmt.Sprintf("del-%d", i)
			_ = s.CreateDelivery(ctx, &domain.DeliveryAttempt{
				ID:         delID,
				EventID:    winningIDs[0],
				EndpointID: epID,
				Status:     domain.StatusQueued,
			})
			next := time.Now().UTC().Add(time.Second)
			_ = s.UpdateDelivery(ctx, &domain.DeliveryAttempt{
				ID:           delID,
				Status:       domain.StatusFailed,
				AttemptCount: 1,
				NextRetryAt:  &next,
			})
			d, err := s.GetDelivery(ctx, delID)
			if err == nil && d.NextRetryAt != nil {
				*d.NextRetryAt = time.Now().UTC()
			}
			_, _ = s.ListDeliveries(ctx, domain.DeliveryFilter{Status: domain.StatusFailed})
		}()
	}
	wg.Wait()
}

func TestMemoryStore_CanceledContextAndClosedStore(t *testing.T) {
	s := NewMemoryStore()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	// Verify canceled context returns context.Canceled on all operations
	if err := s.CreateApp(canceledCtx, &domain.App{ID: "a", Name: "A"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.GetApp(canceledCtx, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.ListApps(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := s.CreateEndpoint(canceledCtx, &domain.Endpoint{ID: "e", URL: "http://x"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.GetEndpoint(canceledCtx, "e"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.ListEndpoints(canceledCtx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := s.DeleteEndpoint(canceledCtx, "e"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, _, err := s.CreateEvent(canceledCtx, &domain.Event{ID: "ev", EventType: "t"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.GetEvent(canceledCtx, "ev"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := s.CreateDelivery(canceledCtx, &domain.DeliveryAttempt{ID: "d", EventID: "ev", EndpointID: "ep"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.GetDelivery(canceledCtx, "d"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := s.UpdateDelivery(canceledCtx, &domain.DeliveryAttempt{ID: "d"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if _, err := s.ListDeliveries(canceledCtx, domain.DeliveryFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if err := s.Ping(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Verify closed store rejects all operations
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("expected Ping to succeed before Close, got %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := s.Ping(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.CreateApp(ctx, &domain.App{ID: "a", Name: "A"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.GetApp(ctx, "default"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.ListApps(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.CreateEndpoint(ctx, &domain.Endpoint{ID: "e", URL: "http://x"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.GetEndpoint(ctx, "e"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.ListEndpoints(ctx, ""); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.DeleteEndpoint(ctx, "e"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "ev", EventType: "t"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.GetEvent(ctx, "ev"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.CreateDelivery(ctx, &domain.DeliveryAttempt{ID: "d", EventID: "ev", EndpointID: "ep"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.GetDelivery(ctx, "d"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{ID: "d"}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.ListDeliveries(ctx, domain.DeliveryFilter{}); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
}
