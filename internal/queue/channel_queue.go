package queue

import (
	"sync"

	"github.com/daiko-dev/relayhook/internal/domain"
)

const DefaultQueueCapacity = 10000

var _ domain.Queue = (*ChannelQueue)(nil)

type ChannelQueue struct {
	mu     sync.RWMutex
	ch     chan string
	closed bool
}

func NewChannelQueue(capacity int) *ChannelQueue {
	if capacity <= 0 {
		capacity = DefaultQueueCapacity
	}
	return &ChannelQueue{
		ch: make(chan string, capacity),
	}
}

// Enqueue holds RLock during the non-blocking send so Close cannot close the channel concurrently.
func (q *ChannelQueue) Enqueue(deliveryID string) error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.closed {
		return domain.ErrQueueClosed
	}

	select {
	case q.ch <- deliveryID:
		return nil
	default:
		return domain.ErrQueueFull
	}
}

func (q *ChannelQueue) Dequeue() <-chan string {
	return q.ch
}

func (q *ChannelQueue) Len() int {
	return len(q.ch)
}

func (q *ChannelQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.closed {
		q.closed = true
		close(q.ch)
	}
}
