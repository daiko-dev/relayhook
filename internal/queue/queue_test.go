package queue

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

func TestChannelQueue_BasicFIFOAndCapacity(t *testing.T) {
	q := NewChannelQueue(0)
	if cap(q.Dequeue()) != DefaultQueueCapacity {
		t.Fatalf("expected default capacity %d, got %d", DefaultQueueCapacity, cap(q.Dequeue()))
	}

	small := NewChannelQueue(3)
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("del-%d", i)
		if err := small.Enqueue(id); err != nil {
			t.Fatalf("unexpected enqueue error at %d: %v", i, err)
		}
		if small.Len() != i {
			t.Fatalf("expected len %d, got %d", i, small.Len())
		}
	}

	if err := small.Enqueue("del-4"); !errors.Is(err, domain.ErrQueueFull) {
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}

	for i := 1; i <= 3; i++ {
		got := <-small.Dequeue()
		want := fmt.Sprintf("del-%d", i)
		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	}
	if small.Len() != 0 {
		t.Fatalf("expected empty queue, got len %d", small.Len())
	}
}

func TestChannelQueue_CloseAndIdempotency(t *testing.T) {
	q := NewChannelQueue(5)
	if err := q.Enqueue("del-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	q.Close()
	q.Close() // idempotent second call

	if err := q.Enqueue("del-2"); !errors.Is(err, domain.ErrQueueClosed) {
		t.Fatalf("expected ErrQueueClosed after Close, got %v", err)
	}

	item, ok := <-q.Dequeue()
	if !ok || item != "del-1" {
		t.Fatalf("expected buffered item del-1 before channel drain, got %q (ok=%v)", item, ok)
	}
	_, ok = <-q.Dequeue()
	if ok {
		t.Fatal("expected dequeue channel to be closed")
	}
}

func TestChannelQueue_ConcurrentEnqueueAndClose_NoPanic(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		q := NewChannelQueue(64)
		var wg sync.WaitGroup
		start := make(chan struct{})

		for g := 0; g < 32; g++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				<-start
				for j := 0; j < 100; j++ {
					err := q.Enqueue(fmt.Sprintf("d-%d-%d", id, j))
					if err != nil && !errors.Is(err, domain.ErrQueueClosed) && !errors.Is(err, domain.ErrQueueFull) {
						t.Errorf("unexpected error: %v", err)
					}
				}
			}(g)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(time.Microsecond * 50)
			q.Close()
		}()

		close(start)
		wg.Wait()
	}
}

func TestScheduler_DelayedExecutionAndCancel(t *testing.T) {
	q := NewChannelQueue(100)
	s := NewScheduler(q)
	defer s.Stop()

	s.Schedule("del-fast", 15*time.Millisecond)
	s.Schedule("del-cancel", 80*time.Millisecond)
	s.Schedule("del-neg", -5*time.Millisecond)

	if s.PendingCount() < 1 {
		t.Fatalf("expected at least 1 pending timer, got %d", s.PendingCount())
	}

	s.Cancel("del-cancel")
	s.Cancel("non-existent")

	received := make(map[string]int)
	deadline := time.After(150 * time.Millisecond)
	for len(received) < 2 {
		select {
		case id := <-q.Dequeue():
			received[id]++
		case <-deadline:
			t.Fatalf("timed out waiting for scheduled items, got %v", received)
		}
	}

	time.Sleep(80 * time.Millisecond)
	select {
	case id := <-q.Dequeue():
		t.Fatalf("unexpected item dequeued after cancel: %s", id)
	default:
	}

	if received["del-fast"] != 1 || received["del-neg"] != 1 {
		t.Fatalf("unexpected received counts: %v", received)
	}
	if s.PendingCount() != 0 {
		t.Fatalf("expected 0 pending timers, got %d", s.PendingCount())
	}
}

func TestScheduler_RescheduleReplacesExistingTimer(t *testing.T) {
	var count atomic.Int32
	s := NewSchedulerFunc(func(deliveryID string) error {
		count.Add(1)
		return nil
	})
	defer s.Stop()

	s.Schedule("del-dup", 60*time.Millisecond)
	s.Schedule("del-dup", 15*time.Millisecond)

	if s.PendingCount() != 1 {
		t.Fatalf("expected 1 pending timer after reschedule, got %d", s.PendingCount())
	}

	time.Sleep(100 * time.Millisecond)
	if got := count.Load(); got != 1 {
		t.Fatalf("expected callback to fire exactly once, got %d", got)
	}
	if s.PendingCount() != 0 {
		t.Fatalf("expected 0 pending timers, got %d", s.PendingCount())
	}
}

func TestScheduler_ConcurrentScheduleCancelAndStop(t *testing.T) {
	var enqueued atomic.Int64
	s := NewSchedulerFunc(func(deliveryID string) error {
		enqueued.Add(1)
		return nil
	})

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				id := fmt.Sprintf("del-%d-%d", worker, i%10)
				s.Schedule(id, time.Duration(i%5)*time.Millisecond)
				if i%3 == 0 {
					s.Cancel(id)
				}
			}
		}(g)
	}

	time.Sleep(10 * time.Millisecond)
	s.Stop()
	s.Stop() // idempotent second call
	wg.Wait()

	if s.PendingCount() != 0 {
		t.Fatalf("expected 0 pending timers after Stop, got %d", s.PendingCount())
	}

	before := enqueued.Load()
	s.Schedule("del-after-stop", 1*time.Millisecond)
	time.Sleep(15 * time.Millisecond)
	if after := enqueued.Load(); after != before {
		t.Fatalf("expected no callbacks after Stop, before=%d after=%d", before, after)
	}
}
