package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

func openTestStores(t *testing.T) []*SQLiteStore {
	t.Helper()
	memStore, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore(:memory:) failed: %v", err)
	}
	t.Cleanup(func() { _ = memStore.Close() })

	dbPath := filepath.Join(t.TempDir(), "relayhook_test.db")
	fileStore, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore(%s) failed: %v", dbPath, err)
	}
	t.Cleanup(func() { _ = fileStore.Close() })

	return []*SQLiteStore{memStore, fileStore}
}

func TestSQLiteStore_DefaultAppSeededAndAppsCRUD(t *testing.T) {
	ctx := context.Background()
	for _, s := range openTestStores(t) {
		defApp, err := s.GetApp(ctx, domain.DefaultAppID)
		if err != nil {
			t.Fatalf("GetApp(default) failed: %v", err)
		}
		if defApp.ID != domain.DefaultAppID || defApp.Name != "Default App" || defApp.CreatedAt.IsZero() {
			t.Fatalf("unexpected default app: %+v", defApp)
		}

		if err := s.CreateApp(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for nil app, got %v", err)
		}
		if err := s.CreateApp(ctx, &domain.App{ID: "", Name: "NoID"}); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for empty ID, got %v", err)
		}
		if _, err := s.GetApp(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for empty GetApp id, got %v", err)
		}

		app := &domain.App{ID: "app-custom", Name: "Custom App"}
		if err := s.CreateApp(ctx, app); err != nil {
			t.Fatalf("CreateApp failed: %v", err)
		}
		if err := s.CreateApp(ctx, app); !errors.Is(err, domain.ErrDuplicate) {
			t.Fatalf("expected ErrDuplicate, got %v", err)
		}
		if _, err := s.GetApp(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}

		apps, err := s.ListApps(ctx)
		if err != nil || len(apps) != 2 {
			t.Fatalf("expected 2 apps, got %d (err=%v)", len(apps), err)
		}
	}
}

func TestSQLiteStore_EndpointsCRUDAndJSONEventTypes(t *testing.T) {
	ctx := context.Background()
	for _, s := range openTestStores(t) {
		if err := s.CreateEndpoint(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
		if _, err := s.GetEndpoint(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}
		if err := s.DeleteEndpoint(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput, got %v", err)
		}

		ep1 := &domain.Endpoint{
			ID:         "ep-1",
			URL:        "https://example.com/wh1",
			Secret:     "sec-1",
			EventTypes: []string{"order.created", "payment.succeeded"},
			IsActive:   true,
		}
		if err := s.CreateEndpoint(ctx, ep1); err != nil {
			t.Fatalf("CreateEndpoint ep1 failed: %v", err)
		}
		if err := s.CreateEndpoint(ctx, ep1); !errors.Is(err, domain.ErrDuplicate) {
			t.Fatalf("expected ErrDuplicate, got %v", err)
		}

		got1, err := s.GetEndpoint(ctx, "ep-1")
		if err != nil {
			t.Fatalf("GetEndpoint ep-1 failed: %v", err)
		}
		if got1.AppID != domain.DefaultAppID || got1.MaxRetries != domain.DefaultMaxRetries || len(got1.EventTypes) != 2 {
			t.Fatalf("unexpected ep-1: %+v", got1)
		}

		ep2 := &domain.Endpoint{
			ID:         "ep-2",
			AppID:      "app-2",
			URL:        "https://example.com/wh2",
			Secret:     "sec-2",
			EventTypes: nil,
			IsActive:   false,
			MaxRetries: 3,
		}
		if err := s.CreateEndpoint(ctx, ep2); err != nil {
			t.Fatalf("CreateEndpoint ep2 failed: %v", err)
		}
		got2, err := s.GetEndpoint(ctx, "ep-2")
		if err != nil {
			t.Fatalf("GetEndpoint ep-2 failed: %v", err)
		}
		if got2.EventTypes == nil || len(got2.EventTypes) != 0 || got2.IsActive || got2.MaxRetries != 3 {
			t.Fatalf("unexpected ep-2: %+v", got2)
		}

		all, err := s.ListEndpoints(ctx, "")
		if err != nil || len(all) != 2 {
			t.Fatalf("expected 2 endpoints, got %d (err=%v)", len(all), err)
		}
		filtered, err := s.ListEndpoints(ctx, "app-2")
		if err != nil || len(filtered) != 1 || filtered[0].ID != "ep-2" {
			t.Fatalf("unexpected filtered endpoints: %+v (err=%v)", filtered, err)
		}

		if err := s.DeleteEndpoint(ctx, "ep-1"); err != nil {
			t.Fatalf("DeleteEndpoint failed: %v", err)
		}
		if err := s.DeleteEndpoint(ctx, "ep-1"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound on second delete, got %v", err)
		}
		if _, err := s.GetEndpoint(ctx, "ep-1"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound after delete, got %v", err)
		}
	}
}

func TestSQLiteStore_EventsIdempotencyAndEmptyKey(t *testing.T) {
	ctx := context.Background()
	for _, s := range openTestStores(t) {
		if _, _, err := s.CreateEvent(ctx, nil); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for nil event, got %v", err)
		}
		if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "bad", EventType: "x", Payload: json.RawMessage(`{bad`)}); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for invalid JSON payload, got %v", err)
		}
		if _, err := s.GetEvent(ctx, ""); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatalf("expected ErrInvalidInput for empty GetEvent ID, got %v", err)
		}
		if _, err := s.GetEvent(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for missing GetEvent ID, got %v", err)
		}

		t1 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
		ev1 := &domain.Event{
			ID:             "ev-1",
			AppID:          domain.DefaultAppID,
			EventType:      "invoice.paid",
			Payload:        json.RawMessage(`{"amount":500}`),
			IdempotencyKey: "key-1",
			CreatedAt:      t1,
		}
		res1, created, err := s.CreateEvent(ctx, ev1)
		if err != nil || !created || res1.ID != "ev-1" {
			t.Fatalf("expected created=true for ev-1, got %+v, created=%v, err=%v", res1, created, err)
		}
		gotEv1, err := s.GetEvent(ctx, "ev-1")
		if err != nil || gotEv1.ID != "ev-1" {
			t.Fatalf("GetEvent ev-1 failed: %v", err)
		}

		ev2 := &domain.Event{
			ID:             "ev-2",
			AppID:          domain.DefaultAppID,
			EventType:      "invoice.paid",
			Payload:        json.RawMessage(`{"amount":999}`),
			IdempotencyKey: "key-1",
		}
		res2, created, err := s.CreateEvent(ctx, ev2)
		if err != nil || created || res2.ID != "ev-1" {
			t.Fatalf("expected idempotent return of ev-1, got %+v, created=%v, err=%v", res2, created, err)
		}

		ev3 := &domain.Event{
			ID:             "ev-3",
			AppID:          "app-2",
			EventType:      "invoice.paid",
			Payload:        json.RawMessage(`{"amount":500}`),
			IdempotencyKey: "key-1",
		}
		res3, created, err := s.CreateEvent(ctx, ev3)
		if err != nil || !created || res3.ID != "ev-3" {
			t.Fatalf("expected created=true for different AppID, got %+v, created=%v, err=%v", res3, created, err)
		}

		for i := 4; i <= 6; i++ {
			ev := &domain.Event{
				ID:        fmt.Sprintf("ev-%d", i),
				EventType: "ping",
			}
			_, created, err := s.CreateEvent(ctx, ev)
			if err != nil || !created {
				t.Fatalf("expected created=true for empty IdempotencyKey %d, got err=%v", i, err)
			}
		}

		if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "ev-4", EventType: "ping"}); !errors.Is(err, domain.ErrDuplicate) {
			t.Fatalf("expected ErrDuplicate for duplicate event ID, got %v", err)
		}
	}
}

func TestSQLiteStore_DeliveriesCRUDAndNullableNextRetryAt(t *testing.T) {
	ctx := context.Background()
	for _, s := range openTestStores(t) {
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
		if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{ID: "missing", Status: domain.StatusFailed}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for missing delivery update, got %v", err)
		}

		retryAt := time.Date(2026, 11, 8, 1, 0, 0, 123456789, time.UTC)
		d1 := &domain.DeliveryAttempt{
			ID:          "del-1",
			EventID:     "ev-1",
			EndpointID:  "ep-1",
			NextRetryAt: &retryAt,
		}
		if err := s.CreateDelivery(ctx, d1); err != nil {
			t.Fatalf("CreateDelivery d1 failed: %v", err)
		}
		if err := s.CreateDelivery(ctx, d1); !errors.Is(err, domain.ErrDuplicate) {
			t.Fatalf("expected ErrDuplicate, got %v", err)
		}

		got1, err := s.GetDelivery(ctx, "del-1")
		if err != nil {
			t.Fatalf("GetDelivery del-1 failed: %v", err)
		}
		if got1.Status != domain.StatusQueued || got1.NextRetryAt == nil || !got1.NextRetryAt.Equal(retryAt) {
			t.Fatalf("unexpected del-1: %+v", got1)
		}

		if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{
			ID:           "del-1",
			Status:       domain.StatusDelivered,
			AttemptCount: 2,
			StatusCode:   200,
			ResponseTime: 42,
			NextRetryAt:  nil,
		}); err != nil {
			t.Fatalf("UpdateDelivery failed: %v", err)
		}

		gotUpdated, err := s.GetDelivery(ctx, "del-1")
		if err != nil {
			t.Fatalf("GetDelivery after update failed: %v", err)
		}
		if gotUpdated.NextRetryAt != nil || gotUpdated.Status != domain.StatusDelivered || gotUpdated.EventID != "ev-1" || gotUpdated.EndpointID != "ep-1" || gotUpdated.MaxRetries != domain.DefaultMaxRetries {
			t.Fatalf("unexpected updated delivery: %+v", gotUpdated)
		}

		d2 := &domain.DeliveryAttempt{
			ID:         "del-2",
			EventID:    "ev-2",
			EndpointID: "ep-1",
			Status:     domain.StatusDeadLetter,
		}
		if err := s.CreateDelivery(ctx, d2); err != nil {
			t.Fatalf("CreateDelivery d2 failed: %v", err)
		}

		dlq, err := s.ListDeliveries(ctx, domain.DeliveryFilter{Status: domain.StatusDeadLetter})
		if err != nil || len(dlq) != 1 || dlq[0].ID != "del-2" {
			t.Fatalf("expected 1 DLQ delivery, got %+v (err=%v)", dlq, err)
		}
		byEp, err := s.ListDeliveries(ctx, domain.DeliveryFilter{EndpointID: "ep-1"})
		if err != nil || len(byEp) != 2 {
			t.Fatalf("expected 2 deliveries for ep-1, got %d", len(byEp))
		}
		byEv, err := s.ListDeliveries(ctx, domain.DeliveryFilter{EventID: "ev-1"})
		if err != nil || len(byEv) != 1 || byEv[0].ID != "del-1" {
			t.Fatalf("expected del-1 for ev-1, got %+v", byEv)
		}
	}
}

func TestSQLiteStore_ConcurrentAccessAndIdempotencyRace(t *testing.T) {
	ctx := context.Background()
	for _, s := range openTestStores(t) {
		const workers = 50
		var wg sync.WaitGroup

		// 1. 50 goroutines passing the EXACT SAME *domain.Event pointer to CreateEvent
		sharedEv := &domain.Event{
			ID:             "ev-shared-ptr",
			EventType:      "order.created",
			Payload:        json.RawMessage(`{"total":42}`),
			IdempotencyKey: "shared-idem-key",
		}
		wg.Add(workers)
		var mu sync.Mutex
		createdCount := 0
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				existing, created, err := s.CreateEvent(ctx, sharedEv)
				if err != nil {
					t.Errorf("CreateEvent shared pointer failed: %v", err)
					return
				}
				mu.Lock()
				if created {
					createdCount++
				}
				if existing.ID != "ev-shared-ptr" {
					t.Errorf("unexpected ID %q", existing.ID)
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
		if createdCount != 1 {
			t.Fatalf("expected 1 created from shared pointer, got %d", createdCount)
		}

		// 2. 50 goroutines with distinct IDs and same IdempotencyKey
		wg.Add(workers)
		createdCount = 0
		winningIDs := make([]string, 0, workers)

		for i := 0; i < workers; i++ {
			i := i
			go func() {
				defer wg.Done()
				ev := &domain.Event{
					ID:             fmt.Sprintf("ev-%d", i),
					AppID:          domain.DefaultAppID,
					EventType:      "order.created",
					Payload:        json.RawMessage(`{"total":42}`),
					IdempotencyKey: "concurrent-idem-key",
				}
				existing, created, err := s.CreateEvent(ctx, ev)
				if err != nil {
					t.Errorf("CreateEvent goroutine %d failed: %v", i, err)
					return
				}
				mu.Lock()
				if created {
					createdCount++
				}
				winningIDs = append(winningIDs, existing.ID)
				mu.Unlock()
			}()
		}
		wg.Wait()

		if createdCount != 1 {
			t.Fatalf("expected exactly 1 created event, got %d", createdCount)
		}
		for _, id := range winningIDs {
			if id != winningIDs[0] {
				t.Fatalf("mismatched winning event IDs: %q vs %q", id, winningIDs[0])
			}
		}

		// 3. Concurrent delivery creations, updates, reads, and filtered listings
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			i := i
			go func() {
				defer wg.Done()
				delID := fmt.Sprintf("del-%d", i)
				if err := s.CreateDelivery(ctx, &domain.DeliveryAttempt{
					ID:         delID,
					EventID:    winningIDs[0],
					EndpointID: "ep-concurrent",
					Status:     domain.StatusQueued,
				}); err != nil {
					t.Errorf("CreateDelivery %d failed: %v", i, err)
					return
				}
				retryTime := time.Now().UTC().Add(5 * time.Second)
				if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{
					ID:           delID,
					Status:       domain.StatusFailed,
					AttemptCount: 1,
					LastError:    "timeout",
					NextRetryAt:  &retryTime,
				}); err != nil {
					t.Errorf("UpdateDelivery %d failed: %v", i, err)
					return
				}
				if _, err := s.GetDelivery(ctx, delID); err != nil {
					t.Errorf("GetDelivery %d failed: %v", i, err)
				}
				if _, err := s.ListDeliveries(ctx, domain.DeliveryFilter{Status: domain.StatusFailed}); err != nil {
					t.Errorf("ListDeliveries %d failed: %v", i, err)
				}
			}()
		}
		wg.Wait()
	}
}

func TestSQLiteStore_PingCloseAndHelpers(t *testing.T) {
	ctx := context.Background()

	var nilStore *SQLiteStore
	if err := nilStore.Ping(ctx); err == nil {
		t.Fatalf("expected error on nilStore.Ping")
	}
	if err := nilStore.Close(); err != nil {
		t.Fatalf("expected nil on nilStore.Close, got %v", err)
	}
	if isUniqueConstraintError(nil) {
		t.Fatalf("expected false for nil error")
	}
	if _, err := parseTime("2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("parseTime RFC3339 failed: %v", err)
	}

	s, err := NewSQLiteStore("")
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping before Close failed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := s.Ping(ctx); err == nil {
		t.Fatalf("expected Ping after Close to return error")
	}
	if err := s.CreateApp(ctx, &domain.App{ID: "a", Name: "A"}); err == nil {
		t.Fatalf("expected CreateApp after Close to return error")
	}
	if _, err := s.GetApp(ctx, "default"); err == nil {
		t.Fatalf("expected GetApp after Close to return error")
	}
	if _, err := s.ListApps(ctx); err == nil {
		t.Fatalf("expected ListApps after Close to return error")
	}
	if err := s.CreateEndpoint(ctx, &domain.Endpoint{ID: "e", URL: "http://x"}); err == nil {
		t.Fatalf("expected CreateEndpoint after Close to return error")
	}
	if _, err := s.GetEndpoint(ctx, "e"); err == nil {
		t.Fatalf("expected GetEndpoint after Close to return error")
	}
	if _, err := s.ListEndpoints(ctx, ""); err == nil {
		t.Fatalf("expected ListEndpoints after Close to return error")
	}
	if err := s.DeleteEndpoint(ctx, "e"); err == nil {
		t.Fatalf("expected DeleteEndpoint after Close to return error")
	}
	if _, _, err := s.CreateEvent(ctx, &domain.Event{ID: "ev", EventType: "t"}); err == nil {
		t.Fatalf("expected CreateEvent after Close to return error")
	}
	if _, err := s.GetEvent(ctx, "ev"); err == nil {
		t.Fatalf("expected GetEvent after Close to return error")
	}
	if err := s.CreateDelivery(ctx, &domain.DeliveryAttempt{ID: "d", EventID: "ev", EndpointID: "ep"}); err == nil {
		t.Fatalf("expected CreateDelivery after Close to return error")
	}
	if _, err := s.GetDelivery(ctx, "d"); err == nil {
		t.Fatalf("expected GetDelivery after Close to return error")
	}
	if err := s.UpdateDelivery(ctx, &domain.DeliveryAttempt{ID: "d"}); err == nil {
		t.Fatalf("expected UpdateDelivery after Close to return error")
	}
	if _, err := s.ListDeliveries(ctx, domain.DeliveryFilter{}); err == nil {
		t.Fatalf("expected ListDeliveries after Close to return error")
	}
}
