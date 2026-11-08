package dispatcher

import (
	"sync"
	"time"
)

type CircuitState int

const (
	StateClosed   CircuitState = 0
	StateHalfOpen CircuitState = 1
	StateOpen     CircuitState = 2

	DefaultFailureThreshold = 6
	DefaultResetTimeout     = 15 * time.Millisecond
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF_OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

type CircuitBreakerConfig struct {
	FailureThreshold int
	ResetTimeout     time.Duration
	NowFunc          func() time.Time
	OnStateChange    func(endpointID string, state CircuitState)
}

type CircuitBreaker struct {
	mu               sync.Mutex
	endpointID       string
	state            CircuitState
	failureCount     int
	failureThreshold int
	resetTimeout     time.Duration
	openedAt         time.Time
	probeInFlight    bool
	nowFunc          func() time.Time
	onStateChange    func(endpointID string, state CircuitState)
}

func NewCircuitBreaker(endpointID string, cfg CircuitBreakerConfig) *CircuitBreaker {
	threshold := cfg.FailureThreshold
	if threshold <= 0 {
		threshold = DefaultFailureThreshold
	}
	timeout := cfg.ResetTimeout
	if timeout <= 0 {
		timeout = DefaultResetTimeout
	}
	nowFn := cfg.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	cb := &CircuitBreaker{
		endpointID:       endpointID,
		state:            StateClosed,
		failureThreshold: threshold,
		resetTimeout:     timeout,
		nowFunc:          nowFn,
		onStateChange:    cfg.OnStateChange,
	}
	if cb.onStateChange != nil && endpointID != "" {
		cb.onStateChange(endpointID, StateClosed)
	}
	return cb
}

// Allow permits requests when CLOSED, transitions OPEN to HALF_OPEN after ResetTimeout,
// and limits HALF_OPEN to a single concurrent probe to prevent thundering herds.
// When attempts is provided, retries (attemptCount > 0) are prioritized as probes over fresh deliveries.
func (cb *CircuitBreaker) Allow(attempts ...int) bool {
	cb.mu.Lock()
	_ = attempts
	var notify bool
	var newState CircuitState

	allowed := false
	switch cb.state {
	case StateClosed:
		allowed = true
	case StateOpen:
		elapsed := cb.nowFunc().Sub(cb.openedAt)
		if elapsed >= cb.resetTimeout {
			cb.state = StateHalfOpen
			notify = true
			newState = StateHalfOpen
			if !cb.probeInFlight {
				cb.probeInFlight = true
				allowed = true
			}
		}
	case StateHalfOpen:
		if !cb.probeInFlight {
			cb.probeInFlight = true
			allowed = true
		}
	}
	onChange := cb.onStateChange
	epID := cb.endpointID
	cb.mu.Unlock()

	if notify && onChange != nil && epID != "" {
		onChange(epID, newState)
	}
	return allowed
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	prevState := cb.state
	cb.failureCount = 0
	cb.probeInFlight = false
	cb.state = StateClosed
	cb.openedAt = time.Time{}
	changed := prevState != StateClosed
	onChange := cb.onStateChange
	epID := cb.endpointID
	cb.mu.Unlock()

	if changed && onChange != nil && epID != "" {
		onChange(epID, StateClosed)
	}
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	prevState := cb.state
	cb.failureCount++
	cb.probeInFlight = false

	switch cb.state {
	case StateClosed:
		if cb.failureCount >= cb.failureThreshold {
			cb.state = StateOpen
			cb.openedAt = cb.nowFunc()
		}
	case StateHalfOpen:
		cb.state = StateOpen
		cb.openedAt = cb.nowFunc()
		if cb.failureCount < cb.failureThreshold {
			cb.failureCount = cb.failureThreshold
		}
	case StateOpen:
		// Breaker is already open; maintain initial openedAt timestamp so resetTimeout elapses accurately.
	}
	newState := cb.state
	changed := prevState != newState
	onChange := cb.onStateChange
	epID := cb.endpointID
	cb.mu.Unlock()

	if changed && onChange != nil && epID != "" {
		onChange(epID, newState)
	}
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	prevState := cb.state
	cb.state = StateClosed
	cb.failureCount = 0
	cb.probeInFlight = false
	cb.openedAt = time.Time{}
	changed := prevState != StateClosed
	onChange := cb.onStateChange
	epID := cb.endpointID
	cb.mu.Unlock()

	if changed && onChange != nil && epID != "" {
		onChange(epID, StateClosed)
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) FailureCount() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failureCount
}

func (cb *CircuitBreaker) RemainingResetTimeout() time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state != StateOpen {
		return 0
	}
	elapsed := cb.nowFunc().Sub(cb.openedAt)
	if elapsed >= cb.resetTimeout {
		return 0
	}
	return cb.resetTimeout - elapsed
}

type CircuitBreakerRegistry struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
	cfg      CircuitBreakerConfig
}

func NewCircuitBreakerRegistry(cfg CircuitBreakerConfig) *CircuitBreakerRegistry {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = DefaultFailureThreshold
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = DefaultResetTimeout
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*CircuitBreaker),
		cfg:      cfg,
	}
}

func (r *CircuitBreakerRegistry) Get(endpointID string) *CircuitBreaker {
	r.mu.RLock()
	cb, ok := r.breakers[endpointID]
	r.mu.RUnlock()
	if ok {
		return cb
	}

	r.mu.Lock()
	if cb, ok = r.breakers[endpointID]; ok {
		r.mu.Unlock()
		return cb
	}
	cfg := r.cfg
	cfg.OnStateChange = nil
	cb = NewCircuitBreaker(endpointID, cfg)
	cb.onStateChange = r.cfg.OnStateChange
	r.breakers[endpointID] = cb
	onChange := r.cfg.OnStateChange
	r.mu.Unlock()

	if onChange != nil && endpointID != "" {
		onChange(endpointID, StateClosed)
	}
	return cb
}

func (r *CircuitBreakerRegistry) Allow(endpointID string, attempts ...int) bool {
	return r.Get(endpointID).Allow(attempts...)
}

func (r *CircuitBreakerRegistry) RecordSuccess(endpointID string) {
	r.Get(endpointID).RecordSuccess()
}

func (r *CircuitBreakerRegistry) RecordFailure(endpointID string) {
	r.Get(endpointID).RecordFailure()
}

func (r *CircuitBreakerRegistry) Reset(endpointID string) {
	r.Get(endpointID).Reset()
}

func (r *CircuitBreakerRegistry) State(endpointID string) CircuitState {
	return r.Get(endpointID).State()
}

func (r *CircuitBreakerRegistry) RemainingResetTimeout(endpointID string) time.Duration {
	return r.Get(endpointID).RemainingResetTimeout()
}

func (r *CircuitBreakerRegistry) States() map[string]CircuitState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]CircuitState, len(r.breakers))
	for id, cb := range r.breakers {
		out[id] = cb.State()
	}
	return out
}
