package queue

import (
	"sync"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

type timerEntry struct {
	id    uint64
	timer *time.Timer
}

type Scheduler struct {
	mu        sync.Mutex
	timers    map[string]timerEntry
	seq       uint64
	stopped   bool
	enqueueFn func(deliveryID string) error
	wg        sync.WaitGroup
}

func NewScheduler(q domain.Queue) *Scheduler {
	var fn func(string) error
	if q != nil {
		fn = q.Enqueue
	}
	return NewSchedulerFunc(fn)
}

func NewSchedulerFunc(enqueueFn func(deliveryID string) error) *Scheduler {
	return &Scheduler{
		timers:    make(map[string]timerEntry),
		enqueueFn: enqueueFn,
	}
}

// Schedule registers a delayed re-enqueue. Monotonic timer IDs prevent a replaced timer from deleting a newer entry.
func (s *Scheduler) Schedule(deliveryID string, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}

	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}

	if prev, exists := s.timers[deliveryID]; exists {
		prev.timer.Stop()
		delete(s.timers, deliveryID)
	}

	s.seq++
	timerID := s.seq
	t := time.AfterFunc(delay, func() {
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			return
		}
		cur, ok := s.timers[deliveryID]
		if !ok || cur.id != timerID {
			s.mu.Unlock()
			return
		}
		delete(s.timers, deliveryID)
		s.wg.Add(1)
		s.mu.Unlock()

		defer s.wg.Done()
		if s.enqueueFn != nil {
			_ = s.enqueueFn(deliveryID)
		}
	})

	s.timers[deliveryID] = timerEntry{
		id:    timerID,
		timer: t,
	}
	s.mu.Unlock()
}

func (s *Scheduler) Cancel(deliveryID string) {
	s.mu.Lock()
	entry, exists := s.timers[deliveryID]
	if exists {
		delete(s.timers, deliveryID)
	}
	s.mu.Unlock()

	if exists {
		entry.timer.Stop()
	}
}

func (s *Scheduler) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.timers)
}

// Stop cancels all active timers outside the mutex and waits for any in-flight callbacks to finish.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		s.wg.Wait()
		return
	}
	s.stopped = true
	toStop := make([]*time.Timer, 0, len(s.timers))
	for k, entry := range s.timers {
		toStop = append(toStop, entry.timer)
		delete(s.timers, k)
	}
	s.mu.Unlock()

	for _, t := range toStop {
		t.Stop()
	}
	s.wg.Wait()
}
