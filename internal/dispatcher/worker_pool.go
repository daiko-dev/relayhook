package dispatcher

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/observability"
	"github.com/daiko-dev/relayhook/internal/queue"
)

const (
	DefaultWorkerCount = 8
	DefaultBaseDelay   = 100 * time.Millisecond
	DefaultMaxDelay    = 10 * time.Second
)

type WorkerPoolConfig struct {
	WorkerCount int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	MaxRetries  int
}

type WorkerPool struct {
	cfg       WorkerPoolConfig
	store     domain.Store
	queue     domain.Queue
	scheduler *queue.Scheduler
	client    *WebhookClient
	breakers  *CircuitBreakerRegistry
	metrics   *observability.Metrics
	logger    *slog.Logger

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   atomic.Bool
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewWorkerPool(
	cfg WorkerPoolConfig,
	store domain.Store,
	q domain.Queue,
	sched *queue.Scheduler,
	client *WebhookClient,
	breakers *CircuitBreakerRegistry,
	metrics *observability.Metrics,
	logger *slog.Logger,
) *WorkerPool {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = DefaultBaseDelay
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = DefaultMaxDelay
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = domain.DefaultMaxRetries
	}
	if q == nil {
		q = queue.NewChannelQueue(queue.DefaultQueueCapacity)
	}
	if sched == nil {
		sched = queue.NewScheduler(q)
	}
	if client == nil {
		client = NewWebhookClient(DefaultClientTimeout)
	}
	if metrics == nil {
		metrics = observability.NewMetrics()
	}
	if breakers == nil {
		breakers = NewCircuitBreakerRegistry(CircuitBreakerConfig{
			FailureThreshold: DefaultFailureThreshold,
			ResetTimeout:     DefaultResetTimeout,
			OnStateChange: func(endpointID string, state CircuitState) {
				metrics.SetCircuitBreakerState(endpointID, int(state))
			},
		})
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}

	metrics.SetQueueDepthFunc(q.Len)
	metrics.SetQueueDepth(q.Len())

	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		cfg:       cfg,
		store:     store,
		queue:     q,
		scheduler: sched,
		client:    client,
		breakers:  breakers,
		metrics:   metrics,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (wp *WorkerPool) Start() {
	wp.startOnce.Do(func() {
		wp.running.Store(true)
		wp.metrics.SetActiveWorkers(wp.cfg.WorkerCount)
		for i := 0; i < wp.cfg.WorkerCount; i++ {
			wp.wg.Add(1)
			go wp.worker(i)
		}
	})
}

func (wp *WorkerPool) Stop() {
	wp.stopOnce.Do(func() {
		wp.running.Store(false)
		if wp.scheduler != nil {
			wp.scheduler.Stop()
		}
		wp.cancel()
		wp.wg.Wait()
		if wp.metrics != nil {
			wp.metrics.SetActiveWorkers(0)
		}
		if wp.client != nil {
			wp.client.CloseIdleConnections()
		}
	})
}

func (wp *WorkerPool) IsRunning() bool {
	return wp.running.Load()
}

func (wp *WorkerPool) Enqueue(deliveryID string) error {
	if wp.ctx.Err() != nil {
		return domain.ErrQueueClosed
	}
	err := wp.queue.Enqueue(deliveryID)
	if wp.metrics != nil {
		wp.metrics.SetQueueDepth(wp.queue.Len())
	}
	return err
}

// Replay resets a delivery to QUEUED with AttemptCount=0, resets the endpoint circuit breaker, and re-enqueues it.
func (wp *WorkerPool) Replay(ctx context.Context, deliveryID string) (*domain.DeliveryAttempt, error) {
	if wp.store == nil {
		return nil, domain.ErrNotFound
	}
	d, err := wp.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return nil, err
	}

	if wp.scheduler != nil {
		wp.scheduler.Cancel(deliveryID)
	}

	d.Status = domain.StatusQueued
	d.AttemptCount = 0
	d.StatusCode = 0
	d.ResponseTime = 0
	d.LastError = ""
	d.NextRetryAt = nil
	d.UpdatedAt = time.Now().UTC()

	if wp.breakers != nil {
		wp.breakers.Reset(d.EndpointID)
	}
	if wp.metrics != nil {
		wp.metrics.SetCircuitBreakerState(d.EndpointID, int(StateClosed))
	}

	if err := wp.store.UpdateDelivery(ctx, d); err != nil {
		return nil, err
	}

	// Copy before Enqueue so the caller receives the clean QUEUED state even if a worker processes it immediately.
	snapshot := *d

	if err := wp.Enqueue(d.ID); err != nil {
		return nil, err
	}

	wp.logger.Info("delivery replay queued",
		"event_id", d.EventID,
		"delivery_id", d.ID,
		"endpoint_id", d.EndpointID,
		"status", string(d.Status),
	)
	return &snapshot, nil
}

func (wp *WorkerPool) worker(_ int) {
	defer wp.wg.Done()
	ch := wp.queue.Dequeue()
	for {
		select {
		case <-wp.ctx.Done():
			return
		case deliveryID, ok := <-ch:
			if !ok {
				return
			}
			if wp.metrics != nil {
				wp.metrics.SetQueueDepth(wp.queue.Len())
			}
			wp.processDelivery(deliveryID)
		}
	}
}

func (wp *WorkerPool) processDelivery(deliveryID string) {
	if wp.store == nil {
		return
	}
	// Use an uncanceled context so an in-flight delivery completes and persists its result during graceful Stop.
	storeCtx := context.Background()

	d, err := wp.store.GetDelivery(storeCtx, deliveryID)
	if err != nil || d == nil {
		return
	}
	if d.Status == domain.StatusDelivered || d.Status == domain.StatusDeadLetter {
		return
	}

	ev, err := wp.store.GetEvent(storeCtx, d.EventID)
	if err != nil || ev == nil {
		return
	}

	ep, err := wp.store.GetEndpoint(storeCtx, d.EndpointID)
	if err != nil || ep == nil || !ep.IsActive {
		d.Status = domain.StatusDeadLetter
		d.LastError = "endpoint not found or inactive"
		d.NextRetryAt = nil
		d.UpdatedAt = time.Now().UTC()
		_ = wp.store.UpdateDelivery(storeCtx, d)
		return
	}

	maxRetries := d.MaxRetries
	if maxRetries <= 0 {
		maxRetries = ep.MaxRetries
	}
	if maxRetries <= 0 {
		maxRetries = wp.cfg.MaxRetries
	}
	d.MaxRetries = maxRetries

	allowed := true
	if wp.breakers != nil {
		if wp.breakers.State(ep.ID) != StateClosed && d.AttemptCount >= maxRetries-1 {
			allowed = false
		} else {
			allowed = wp.breakers.Allow(ep.ID, d.AttemptCount)
		}
		if wp.metrics != nil {
			wp.metrics.SetCircuitBreakerState(ep.ID, int(wp.breakers.State(ep.ID)))
		}
	}

	if !allowed {
		rem := time.Duration(0)
		if wp.breakers != nil {
			rem = wp.breakers.RemainingResetTimeout(ep.ID)
		}
		isHalfOpen := wp.breakers != nil && wp.breakers.State(ep.ID) == StateHalfOpen
		if (rem > wp.cfg.MaxDelay || d.AttemptCount >= maxRetries-1) && !isHalfOpen && d.AttemptCount > 0 {
			d.AttemptCount++
		}
		d.LastError = "circuit breaker is open"
		d.UpdatedAt = time.Now().UTC()

		if d.AttemptCount >= maxRetries {
			d.Status = domain.StatusDeadLetter
			d.NextRetryAt = nil
			if wp.metrics != nil {
				wp.metrics.IncDeliveries("dead_letter")
			}
			_ = wp.store.UpdateDelivery(storeCtx, d)
			wp.logger.Warn("delivery moved to dead letter queue (circuit open)",
				"event_id", ev.ID,
				"delivery_id", d.ID,
				"endpoint_id", ep.ID,
				"attempt", d.AttemptCount,
				"max_retries", maxRetries,
				"status", string(d.Status),
			)
			return
		}

		d.Status = domain.StatusFailed
		delay := CalculateBackoff(d.AttemptCount, wp.cfg.BaseDelay, wp.cfg.MaxDelay)
		if wp.breakers != nil {
			if rem := wp.breakers.RemainingResetTimeout(ep.ID); rem > 0 && rem <= wp.cfg.MaxDelay {
				if delay < rem {
					delay = rem + time.Duration(rand.Int64N(int64(4*time.Millisecond)+1))
				}
			}
		}
		if isHalfOpen {
			delay = 10 * time.Millisecond + time.Duration(rand.Int64N(int64(5*time.Millisecond)+1))
		}
		if delay < 10*time.Millisecond {
			delay = 10*time.Millisecond + time.Duration(rand.Int64N(int64(5*time.Millisecond)+1))
		}
		nextRetry := time.Now().UTC().Add(delay)
		d.NextRetryAt = &nextRetry
		if wp.metrics != nil {
			wp.metrics.IncDeliveries("failed")
			wp.metrics.IncRetryAttempts()
		}
		_ = wp.store.UpdateDelivery(storeCtx, d)

		wp.logger.Info("delivery rescheduled due to open circuit breaker",
			"event_id", ev.ID,
			"delivery_id", d.ID,
			"endpoint_id", ep.ID,
			"attempt", d.AttemptCount,
			"delay_ms", delay.Milliseconds(),
			"status", string(d.Status),
		)
		if wp.scheduler != nil && wp.ctx.Err() == nil {
			wp.scheduler.Schedule(d.ID, delay)
		}
		return
	}

	d.Status = domain.StatusProcessing
	d.UpdatedAt = time.Now().UTC()
	_ = wp.store.UpdateDelivery(storeCtx, d)

	start := time.Now()
	res := wp.client.Send(storeCtx, DeliveryRequest{
		DeliveryID: d.ID,
		EventID:    ev.ID,
		EventType:  ev.EventType,
		URL:        ep.URL,
		Secret:     ep.Secret,
		Payload:    ev.Payload,
	})
	elapsed := time.Since(start)
	if wp.metrics != nil {
		wp.metrics.ObserveDeliveryDuration(elapsed)
	}

	d.AttemptCount++
	d.StatusCode = res.StatusCode
	d.ResponseTime = res.ResponseTime
	d.UpdatedAt = time.Now().UTC()

	if res.Err == nil && res.StatusCode >= 200 && res.StatusCode < 300 {
		if wp.breakers != nil {
			wp.breakers.RecordSuccess(ep.ID)
			if wp.metrics != nil {
				wp.metrics.SetCircuitBreakerState(ep.ID, int(wp.breakers.State(ep.ID)))
			}
		}
		d.Status = domain.StatusDelivered
		d.LastError = ""
		d.NextRetryAt = nil
		if wp.metrics != nil {
			wp.metrics.IncDeliveries("delivered")
		}
		_ = wp.store.UpdateDelivery(storeCtx, d)
		wp.logger.Info("webhook delivered",
			"event_id", ev.ID,
			"delivery_id", d.ID,
			"endpoint_id", ep.ID,
			"attempt", d.AttemptCount,
			"status_code", res.StatusCode,
			"response_time_ms", res.ResponseTime,
			"status", string(d.Status),
		)
		return
	}

	if wp.breakers != nil {
		wp.breakers.RecordFailure(ep.ID)
		if wp.metrics != nil {
			wp.metrics.SetCircuitBreakerState(ep.ID, int(wp.breakers.State(ep.ID)))
		}
	}

	if res.Err != nil {
		d.LastError = res.Err.Error()
	} else {
		d.LastError = fmt.Sprintf("unexpected status code: %d", res.StatusCode)
	}

	if d.AttemptCount < maxRetries {
		d.Status = domain.StatusFailed
		delay := CalculateBackoff(d.AttemptCount, wp.cfg.BaseDelay, wp.cfg.MaxDelay)
		if wp.breakers != nil {
			if rem := wp.breakers.RemainingResetTimeout(ep.ID); rem > 0 && rem <= wp.cfg.MaxDelay {
				if delay < rem {
					delay = rem + time.Duration(rand.Int64N(int64(4*time.Millisecond)+1))
				}
			}
		}
		nextRetry := time.Now().UTC().Add(delay)
		d.NextRetryAt = &nextRetry
		if wp.metrics != nil {
			wp.metrics.IncDeliveries("failed")
			wp.metrics.IncRetryAttempts()
		}
		_ = wp.store.UpdateDelivery(storeCtx, d)

		wp.logger.Warn("webhook delivery failed, scheduling retry",
			"event_id", ev.ID,
			"delivery_id", d.ID,
			"endpoint_id", ep.ID,
			"attempt", d.AttemptCount,
			"max_retries", maxRetries,
			"status_code", res.StatusCode,
			"error", d.LastError,
			"delay_ms", delay.Milliseconds(),
			"status", string(d.Status),
		)
		if wp.scheduler != nil && wp.ctx.Err() == nil {
			wp.scheduler.Schedule(d.ID, delay)
		}
		return
	}

	d.Status = domain.StatusDeadLetter
	d.NextRetryAt = nil
	if wp.metrics != nil {
		wp.metrics.IncDeliveries("dead_letter")
	}
	_ = wp.store.UpdateDelivery(storeCtx, d)
	wp.logger.Error("webhook delivery exhausted retries, moved to DLQ",
		"event_id", ev.ID,
		"delivery_id", d.ID,
		"endpoint_id", ep.ID,
		"attempt", d.AttemptCount,
		"max_retries", maxRetries,
		"status_code", res.StatusCode,
		"error", d.LastError,
		"status", string(d.Status),
	)
}
