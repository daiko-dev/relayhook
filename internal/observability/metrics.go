package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var defaultHistogramBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

type Metrics struct {
	eventsIngestedTotal atomic.Uint64
	deliveredTotal      atomic.Uint64
	failedTotal         atomic.Uint64
	deadLetterTotal     atomic.Uint64
	retryAttemptsTotal  atomic.Uint64
	activeWorkers       atomic.Int64
	queueDepth          atomic.Int64

	mu                   sync.RWMutex
	durationBuckets      []float64
	durationBucketCounts []uint64
	durationCount        uint64
	durationSum          float64
	breakerStates        map[string]int
	queueDepthFn         func() int
}

func NewMetrics() *Metrics {
	buckets := make([]float64, len(defaultHistogramBuckets))
	copy(buckets, defaultHistogramBuckets)
	return &Metrics{
		durationBuckets:      buckets,
		durationBucketCounts: make([]uint64, len(buckets)),
		breakerStates:        make(map[string]int),
	}
}

func (m *Metrics) SetQueueDepthFunc(fn func() int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.queueDepthFn = fn
}

func (m *Metrics) IncEventsIngested() {
	m.eventsIngestedTotal.Add(1)
}

func (m *Metrics) EventsIngestedTotal() uint64 {
	return m.eventsIngestedTotal.Load()
}

func (m *Metrics) IncDeliveries(status string) {
	switch strings.ToLower(status) {
	case "delivered":
		m.deliveredTotal.Add(1)
	case "failed":
		m.failedTotal.Add(1)
	case "dead_letter":
		m.deadLetterTotal.Add(1)
	}
}

func (m *Metrics) DeliveriesTotal(status string) uint64 {
	switch strings.ToLower(status) {
	case "delivered":
		return m.deliveredTotal.Load()
	case "failed":
		return m.failedTotal.Load()
	case "dead_letter":
		return m.deadLetterTotal.Load()
	default:
		return 0
	}
}

func (m *Metrics) IncRetryAttempts() {
	m.retryAttemptsTotal.Add(1)
}

func (m *Metrics) RetryAttemptsTotal() uint64 {
	return m.retryAttemptsTotal.Load()
}

func (m *Metrics) ObserveDeliveryDuration(d time.Duration) {
	secs := d.Seconds()
	if secs < 0 {
		secs = 0
	}
	m.mu.Lock()
	m.durationCount++
	m.durationSum += secs
	for i, bound := range m.durationBuckets {
		if secs <= bound {
			m.durationBucketCounts[i]++
		}
	}
	m.mu.Unlock()
}

func (m *Metrics) SetActiveWorkers(count int) {
	m.activeWorkers.Store(int64(count))
}

func (m *Metrics) AddActiveWorkers(delta int) {
	m.activeWorkers.Add(int64(delta))
}

func (m *Metrics) ActiveWorkers() int64 {
	return m.activeWorkers.Load()
}

func (m *Metrics) SetQueueDepth(depth int) {
	m.queueDepth.Store(int64(depth))
}

func (m *Metrics) QueueDepth() int64 {
	m.mu.RLock()
	fn := m.queueDepthFn
	m.mu.RUnlock()
	if fn != nil {
		return int64(fn())
	}
	return m.queueDepth.Load()
}

func (m *Metrics) SetCircuitBreakerState(endpointID string, state int) {
	if endpointID == "" {
		return
	}
	m.mu.Lock()
	m.breakerStates[endpointID] = state
	m.mu.Unlock()
}

func (m *Metrics) RemoveCircuitBreakerState(endpointID string) {
	m.mu.Lock()
	delete(m.breakerStates, endpointID)
	m.mu.Unlock()
}

func (m *Metrics) Render() string {
	m.mu.RLock()
	buckets := make([]float64, len(m.durationBuckets))
	copy(buckets, m.durationBuckets)
	bucketCounts := make([]uint64, len(m.durationBucketCounts))
	copy(bucketCounts, m.durationBucketCounts)
	durCount := m.durationCount
	durSum := m.durationSum
	qFn := m.queueDepthFn

	epIDs := make([]string, 0, len(m.breakerStates))
	for epID := range m.breakerStates {
		epIDs = append(epIDs, epID)
	}
	sort.Strings(epIDs)
	breakerCopy := make(map[string]int, len(m.breakerStates))
	for k, v := range m.breakerStates {
		breakerCopy[k] = v
	}
	m.mu.RUnlock()

	qDepth := m.queueDepth.Load()
	if qFn != nil {
		qDepth = int64(qFn())
	}

	var b strings.Builder

	b.WriteString("# HELP relayhook_events_ingested_total Total number of events ingested.\n")
	b.WriteString("# TYPE relayhook_events_ingested_total counter\n")
	fmt.Fprintf(&b, "relayhook_events_ingested_total %d\n", m.eventsIngestedTotal.Load())

	b.WriteString("# HELP relayhook_deliveries_total Total number of webhook deliveries by status.\n")
	b.WriteString("# TYPE relayhook_deliveries_total counter\n")
	fmt.Fprintf(&b, "relayhook_deliveries_total{status=\"delivered\"} %d\n", m.deliveredTotal.Load())
	fmt.Fprintf(&b, "relayhook_deliveries_total{status=\"failed\"} %d\n", m.failedTotal.Load())
	fmt.Fprintf(&b, "relayhook_deliveries_total{status=\"dead_letter\"} %d\n", m.deadLetterTotal.Load())

	b.WriteString("# HELP relayhook_retry_attempts_total Total number of scheduled delivery retry attempts.\n")
	b.WriteString("# TYPE relayhook_retry_attempts_total counter\n")
	fmt.Fprintf(&b, "relayhook_retry_attempts_total %d\n", m.retryAttemptsTotal.Load())

	b.WriteString("# HELP relayhook_delivery_duration_seconds Webhook HTTP delivery latency distribution in seconds.\n")
	b.WriteString("# TYPE relayhook_delivery_duration_seconds histogram\n")
	for i, bound := range buckets {
		fmt.Fprintf(&b, "relayhook_delivery_duration_seconds_bucket{le=\"%g\"} %d\n", bound, bucketCounts[i])
	}
	fmt.Fprintf(&b, "relayhook_delivery_duration_seconds_bucket{le=\"+Inf\"} %d\n", durCount)
	fmt.Fprintf(&b, "relayhook_delivery_duration_seconds_sum %.6f\n", durSum)
	fmt.Fprintf(&b, "relayhook_delivery_duration_seconds_count %d\n", durCount)

	b.WriteString("# HELP relayhook_active_workers Number of active delivery worker goroutines.\n")
	b.WriteString("# TYPE relayhook_active_workers gauge\n")
	fmt.Fprintf(&b, "relayhook_active_workers %d\n", m.activeWorkers.Load())

	b.WriteString("# HELP relayhook_queue_depth Current number of deliveries queued in the channel buffer.\n")
	b.WriteString("# TYPE relayhook_queue_depth gauge\n")
	fmt.Fprintf(&b, "relayhook_queue_depth %d\n", qDepth)

	b.WriteString("# HELP relayhook_circuit_breaker_state Circuit breaker state per endpoint (0=closed, 1=half-open, 2=open).\n")
	b.WriteString("# TYPE relayhook_circuit_breaker_state gauge\n")
	for _, epID := range epIDs {
		escapedID := strings.ReplaceAll(strings.ReplaceAll(epID, `\`, `\\`), `"`, `\"`)
		fmt.Fprintf(&b, "relayhook_circuit_breaker_state{endpoint_id=\"%s\"} %d\n", escapedID, breakerCopy[epID])
	}

	return b.String()
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m.Render()))
	})
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Handler().ServeHTTP(w, r)
}
