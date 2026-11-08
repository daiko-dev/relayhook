package observability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetrics_FreshServerExposesAllFamilies(t *testing.T) {
	m := NewMetrics()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected content-type: %q", ct)
	}

	body := rec.Body.String()
	requiredFamilies := []string{
		"# TYPE relayhook_events_ingested_total counter",
		"relayhook_events_ingested_total 0",
		"# TYPE relayhook_deliveries_total counter",
		`relayhook_deliveries_total{status="delivered"} 0`,
		`relayhook_deliveries_total{status="failed"} 0`,
		`relayhook_deliveries_total{status="dead_letter"} 0`,
		"# TYPE relayhook_retry_attempts_total counter",
		"relayhook_retry_attempts_total 0",
		"# TYPE relayhook_delivery_duration_seconds histogram",
		`relayhook_delivery_duration_seconds_bucket{le="+Inf"} 0`,
		"relayhook_delivery_duration_seconds_sum 0.000000",
		"relayhook_delivery_duration_seconds_count 0",
		"# TYPE relayhook_active_workers gauge",
		"relayhook_active_workers 0",
		"# TYPE relayhook_queue_depth gauge",
		"relayhook_queue_depth 0",
		"# TYPE relayhook_circuit_breaker_state gauge",
	}

	for _, line := range requiredFamilies {
		if !strings.Contains(body, line) {
			t.Errorf("expected /metrics output to contain %q, got:\n%s", line, body)
		}
	}
}

func TestMetrics_CountersGaugesAndHistogram(t *testing.T) {
	m := NewMetrics()

	m.IncEventsIngested()
	m.IncEventsIngested()
	m.IncDeliveries("delivered")
	m.IncDeliveries("DELIVERED")
	m.IncDeliveries("failed")
	m.IncDeliveries("dead_letter")
	m.IncDeliveries("unknown_ignored")
	m.IncRetryAttempts()
	m.ObserveDeliveryDuration(20 * time.Millisecond)
	m.ObserveDeliveryDuration(-5 * time.Millisecond) // clamped to 0
	m.SetActiveWorkers(4)
	m.AddActiveWorkers(2)
	m.SetQueueDepth(7)
	m.SetCircuitBreakerState("", 1) // ignored empty endpoint
	m.SetCircuitBreakerState("ep-1", 2)
	m.SetCircuitBreakerState("ep-2", 0)
	m.RemoveCircuitBreakerState("ep-2")

	if m.EventsIngestedTotal() != 2 {
		t.Fatalf("expected 2 events ingested, got %d", m.EventsIngestedTotal())
	}
	if m.DeliveriesTotal("delivered") != 2 || m.DeliveriesTotal("failed") != 1 || m.DeliveriesTotal("dead_letter") != 1 || m.DeliveriesTotal("other") != 0 {
		t.Fatalf("unexpected delivery totals")
	}
	if m.RetryAttemptsTotal() != 1 {
		t.Fatalf("expected 1 retry attempt, got %d", m.RetryAttemptsTotal())
	}
	if m.ActiveWorkers() != 6 {
		t.Fatalf("expected 6 active workers, got %d", m.ActiveWorkers())
	}
	if m.QueueDepth() != 7 {
		t.Fatalf("expected queue depth 7, got %d", m.QueueDepth())
	}

	m.SetQueueDepthFunc(func() int { return 12 })
	if m.QueueDepth() != 12 {
		t.Fatalf("expected dynamic queue depth 12, got %d", m.QueueDepth())
	}

	rendered := m.Render()
	expectedLines := []string{
		"relayhook_events_ingested_total 2",
		`relayhook_deliveries_total{status="delivered"} 2`,
		`relayhook_deliveries_total{status="failed"} 1`,
		`relayhook_deliveries_total{status="dead_letter"} 1`,
		"relayhook_retry_attempts_total 1",
		`relayhook_delivery_duration_seconds_bucket{le="0.025"} 2`,
		`relayhook_delivery_duration_seconds_bucket{le="+Inf"} 2`,
		"relayhook_delivery_duration_seconds_count 2",
		"relayhook_active_workers 6",
		"relayhook_queue_depth 12",
		`relayhook_circuit_breaker_state{endpoint_id="ep-1"} 2`,
	}
	for _, exp := range expectedLines {
		if !strings.Contains(rendered, exp) {
			t.Errorf("missing expected line %q in:\n%s", exp, rendered)
		}
	}
	if strings.Contains(rendered, "ep-2") {
		t.Errorf("expected removed endpoint ep-2 not to appear in:\n%s", rendered)
	}
}

func TestMetrics_ConcurrentUpdatesAndScrapes(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				m.IncEventsIngested()
				m.IncDeliveries("delivered")
				m.IncDeliveries("failed")
				m.IncDeliveries("dead_letter")
				m.IncRetryAttempts()
				m.ObserveDeliveryDuration(time.Duration(j) * time.Millisecond)
				m.SetActiveWorkers(id)
				m.SetQueueDepth(j)
				m.SetCircuitBreakerState(fmt.Sprintf("ep-%d", id%4), j%3)
			}
		}(i)
	}

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				rec := httptest.NewRecorder()
				m.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("unexpected status %d", rec.Code)
				}
			}
		}()
	}

	wg.Wait()
}
