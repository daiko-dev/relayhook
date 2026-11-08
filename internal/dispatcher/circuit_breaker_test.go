package dispatcher

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_StateLifecycleAndHalfOpenSingleProbe(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	currentNow := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	var transitions []CircuitState
	cb := NewCircuitBreaker("ep-1", CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     10 * time.Second,
		NowFunc:          currentNow,
		OnStateChange: func(_ string, state CircuitState) {
			transitions = append(transitions, state)
		},
	})

	if cb.State() != StateClosed || cb.State().String() != "CLOSED" {
		t.Fatalf("expected initial state CLOSED, got %v", cb.State())
	}
	if CircuitState(99).String() != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN for invalid state")
	}

	// Two failures keep breaker CLOSED.
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateClosed || cb.FailureCount() != 2 || !cb.Allow() {
		t.Fatalf("expected CLOSED with 2 failures, got state=%v count=%d", cb.State(), cb.FailureCount())
	}

	// Third consecutive failure trips breaker to OPEN.
	cb.RecordFailure()
	if cb.State() != StateOpen || cb.State().String() != "OPEN" {
		t.Fatalf("expected OPEN after 3 failures, got %v", cb.State())
	}
	if cb.Allow() {
		t.Fatal("expected Allow() == false while OPEN before ResetTimeout")
	}

	// Advance clock past ResetTimeout -> first Allow() transitions to HALF_OPEN and permits 1 probe.
	advance(11 * time.Second)
	if !cb.Allow() {
		t.Fatal("expected first probe Allow() == true after ResetTimeout")
	}
	if cb.State() != StateHalfOpen || cb.State().String() != "HALF_OPEN" {
		t.Fatalf("expected HALF_OPEN, got %v", cb.State())
	}
	// Second concurrent call in HALF_OPEN while probe is in-flight must be rejected.
	if cb.Allow() {
		t.Fatal("expected second concurrent Allow() in HALF_OPEN to return false")
	}

	// Probe fails -> immediately re-opens breaker.
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected failed HALF_OPEN probe to re-open breaker, got %v", cb.State())
	}
	if cb.Allow() {
		t.Fatal("expected Allow() == false immediately after re-opening")
	}

	// Advance clock again -> probe succeeds -> transitions to CLOSED.
	advance(11 * time.Second)
	if !cb.Allow() {
		t.Fatal("expected probe Allow() == true after second ResetTimeout")
	}
	cb.RecordSuccess()
	if cb.State() != StateClosed || cb.FailureCount() != 0 || !cb.Allow() {
		t.Fatalf("expected CLOSED with 0 failures after probe success, got state=%v count=%d", cb.State(), cb.FailureCount())
	}

	expectedTransitions := []CircuitState{
		StateClosed,
		StateOpen,
		StateHalfOpen,
		StateOpen,
		StateHalfOpen,
		StateClosed,
	}
	if len(transitions) != len(expectedTransitions) {
		t.Fatalf("expected transitions %v, got %v", expectedTransitions, transitions)
	}
	for i := range expectedTransitions {
		if transitions[i] != expectedTransitions[i] {
			t.Fatalf("transition %d: expected %v, got %v", i, expectedTransitions[i], transitions[i])
		}
	}
}

func TestCircuitBreaker_ResetAndRegistryIsolation(t *testing.T) {
	reg := NewCircuitBreakerRegistry(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     30 * time.Second,
	})

	reg.RecordFailure("ep-bad")
	reg.RecordFailure("ep-bad")

	if reg.State("ep-bad") != StateOpen || reg.Allow("ep-bad") {
		t.Fatalf("expected ep-bad to be OPEN")
	}
	if reg.State("ep-good") != StateClosed || !reg.Allow("ep-good") {
		t.Fatalf("expected ep-good to remain CLOSED")
	}

	states := reg.States()
	if states["ep-bad"] != StateOpen || states["ep-good"] != StateClosed {
		t.Fatalf("unexpected registry states: %v", states)
	}

	reg.Reset("ep-bad")
	if reg.State("ep-bad") != StateClosed || !reg.Allow("ep-bad") {
		t.Fatalf("expected ep-bad to be CLOSED after manual Reset")
	}
}

func TestCircuitBreakerRegistry_Concurrency(t *testing.T) {
	reg := NewCircuitBreakerRegistry(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     2 * time.Millisecond,
	})

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ep := fmt.Sprintf("ep-%d", id%4)
			for i := 0; i < 100; i++ {
				_ = reg.Allow(ep)
				if i%3 == 0 {
					reg.RecordFailure(ep)
				} else {
					reg.RecordSuccess(ep)
				}
				if i%25 == 0 {
					reg.Reset(ep)
				}
				_ = reg.State(ep)
				_ = reg.States()
			}
		}(g)
	}
	wg.Wait()
}
