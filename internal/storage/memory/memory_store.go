package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

var (
	_ domain.Store = (*MemoryStore)(nil)

	ErrStoreClosed = errors.New("memory store is closed")
)

type MemoryStore struct {
	mu               sync.RWMutex
	apps             map[string]*domain.App
	endpoints        map[string]*domain.Endpoint
	events           map[string]*domain.Event
	idempotencyIndex map[string]string
	deliveries       map[string]*domain.DeliveryAttempt
	closed           bool
}

func NewMemoryStore() *MemoryStore {
	now := time.Now().UTC()
	s := &MemoryStore{
		apps:             make(map[string]*domain.App),
		endpoints:        make(map[string]*domain.Endpoint),
		events:           make(map[string]*domain.Event),
		idempotencyIndex: make(map[string]string),
		deliveries:       make(map[string]*domain.DeliveryAttempt),
	}
	s.apps[domain.DefaultAppID] = &domain.App{
		ID:        domain.DefaultAppID,
		Name:      "Default App",
		CreatedAt: now,
	}
	return s
}

func copyApp(a *domain.App) *domain.App {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

func copyEndpoint(ep *domain.Endpoint) *domain.Endpoint {
	if ep == nil {
		return nil
	}
	cp := *ep
	if ep.EventTypes != nil {
		cp.EventTypes = make([]string, len(ep.EventTypes))
		copy(cp.EventTypes, ep.EventTypes)
	} else {
		cp.EventTypes = []string{}
	}
	return &cp
}

func copyEvent(ev *domain.Event) *domain.Event {
	if ev == nil {
		return nil
	}
	cp := *ev
	if ev.Payload != nil {
		cp.Payload = make(json.RawMessage, len(ev.Payload))
		copy(cp.Payload, ev.Payload)
	}
	return &cp
}

func copyDelivery(d *domain.DeliveryAttempt) *domain.DeliveryAttempt {
	if d == nil {
		return nil
	}
	cp := *d
	if d.NextRetryAt != nil {
		t := d.NextRetryAt.UTC()
		cp.NextRetryAt = &t
	}
	return &cp
}

func (s *MemoryStore) CreateApp(ctx context.Context, app *domain.App) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if app == nil || strings.TrimSpace(app.ID) == "" || strings.TrimSpace(app.Name) == "" {
		return domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, exists := s.apps[app.ID]; exists {
		return domain.ErrDuplicate
	}

	cp := copyApp(app)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	} else {
		cp.CreatedAt = cp.CreatedAt.UTC()
	}
	s.apps[cp.ID] = cp
	return nil
}

func (s *MemoryStore) GetApp(ctx context.Context, id string) (*domain.App, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	a, ok := s.apps[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return copyApp(a), nil
}

func (s *MemoryStore) ListApps(ctx context.Context) ([]*domain.App, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	res := make([]*domain.App, 0, len(s.apps))
	for _, a := range s.apps {
		res = append(res, copyApp(a))
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].CreatedAt.Equal(res[j].CreatedAt) {
			return res[i].ID < res[j].ID
		}
		return res[i].CreatedAt.Before(res[j].CreatedAt)
	})
	return res, nil
}

func (s *MemoryStore) CreateEndpoint(ctx context.Context, ep *domain.Endpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ep == nil || strings.TrimSpace(ep.ID) == "" || strings.TrimSpace(ep.URL) == "" {
		return domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, exists := s.endpoints[ep.ID]; exists {
		return domain.ErrDuplicate
	}

	cp := copyEndpoint(ep)
	if strings.TrimSpace(cp.AppID) == "" {
		cp.AppID = domain.DefaultAppID
	}
	if cp.MaxRetries <= 0 {
		cp.MaxRetries = domain.DefaultMaxRetries
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	} else {
		cp.CreatedAt = cp.CreatedAt.UTC()
	}
	s.endpoints[cp.ID] = cp
	return nil
}

func (s *MemoryStore) GetEndpoint(ctx context.Context, id string) (*domain.Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	ep, ok := s.endpoints[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return copyEndpoint(ep), nil
}

func (s *MemoryStore) ListEndpoints(ctx context.Context, appID string) ([]*domain.Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	filterAppID := strings.TrimSpace(appID)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	res := make([]*domain.Endpoint, 0)
	for _, ep := range s.endpoints {
		if filterAppID == "" || ep.AppID == filterAppID {
			res = append(res, copyEndpoint(ep))
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].CreatedAt.Equal(res[j].CreatedAt) {
			return res[i].ID < res[j].ID
		}
		return res[i].CreatedAt.Before(res[j].CreatedAt)
	})
	return res, nil
}

func (s *MemoryStore) DeleteEndpoint(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, ok := s.endpoints[id]; !ok {
		return domain.ErrNotFound
	}
	delete(s.endpoints, id)
	return nil
}

func (s *MemoryStore) CreateEvent(ctx context.Context, ev *domain.Event) (*domain.Event, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if ev == nil || strings.TrimSpace(ev.ID) == "" || strings.TrimSpace(ev.EventType) == "" {
		return nil, false, domain.ErrInvalidInput
	}
	if len(ev.Payload) > 0 && !json.Valid(ev.Payload) {
		return nil, false, domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, ErrStoreClosed
	}

	cp := copyEvent(ev)
	if strings.TrimSpace(cp.AppID) == "" {
		cp.AppID = domain.DefaultAppID
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	} else {
		cp.CreatedAt = cp.CreatedAt.UTC()
	}
	if len(cp.Payload) == 0 {
		cp.Payload = json.RawMessage("{}")
	}

	if cp.IdempotencyKey != "" {
		idemKey := cp.AppID + "\x00" + cp.IdempotencyKey
		if existingID, ok := s.idempotencyIndex[idemKey]; ok {
			if existingEv, exists := s.events[existingID]; exists {
				return copyEvent(existingEv), false, nil
			}
		}
	}

	if _, exists := s.events[cp.ID]; exists {
		return nil, false, domain.ErrDuplicate
	}

	s.events[cp.ID] = cp
	if cp.IdempotencyKey != "" {
		s.idempotencyIndex[cp.AppID+"\x00"+cp.IdempotencyKey] = cp.ID
	}
	return copyEvent(cp), true, nil
}

func (s *MemoryStore) GetEvent(ctx context.Context, id string) (*domain.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	ev, ok := s.events[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return copyEvent(ev), nil
}

func (s *MemoryStore) CreateDelivery(ctx context.Context, d *domain.DeliveryAttempt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d == nil || strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.EventID) == "" || strings.TrimSpace(d.EndpointID) == "" {
		return domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, exists := s.deliveries[d.ID]; exists {
		return domain.ErrDuplicate
	}

	cp := copyDelivery(d)
	if cp.Status == "" {
		cp.Status = domain.StatusQueued
	}
	if cp.MaxRetries <= 0 {
		cp.MaxRetries = domain.DefaultMaxRetries
	}
	now := time.Now().UTC()
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	} else {
		cp.CreatedAt = cp.CreatedAt.UTC()
	}
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = cp.CreatedAt
	} else {
		cp.UpdatedAt = cp.UpdatedAt.UTC()
	}
	if cp.NextRetryAt != nil && cp.NextRetryAt.IsZero() {
		cp.NextRetryAt = nil
	}

	s.deliveries[cp.ID] = cp
	return nil
}

func (s *MemoryStore) GetDelivery(ctx context.Context, id string) (*domain.DeliveryAttempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		return nil, domain.ErrInvalidInput
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	d, ok := s.deliveries[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return copyDelivery(d), nil
}

func (s *MemoryStore) UpdateDelivery(ctx context.Context, d *domain.DeliveryAttempt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d == nil || strings.TrimSpace(d.ID) == "" {
		return domain.ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	existing, ok := s.deliveries[d.ID]
	if !ok {
		return domain.ErrNotFound
	}

	cp := copyDelivery(d)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = existing.CreatedAt
	} else {
		cp.CreatedAt = cp.CreatedAt.UTC()
	}
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	} else {
		cp.UpdatedAt = cp.UpdatedAt.UTC()
	}
	if strings.TrimSpace(cp.EventID) == "" {
		cp.EventID = existing.EventID
	}
	if strings.TrimSpace(cp.EndpointID) == "" {
		cp.EndpointID = existing.EndpointID
	}
	if cp.MaxRetries <= 0 {
		cp.MaxRetries = existing.MaxRetries
	}
	if cp.NextRetryAt != nil && cp.NextRetryAt.IsZero() {
		cp.NextRetryAt = nil
	}

	s.deliveries[d.ID] = cp
	return nil
}

func (s *MemoryStore) ListDeliveries(ctx context.Context, filter domain.DeliveryFilter) ([]*domain.DeliveryAttempt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}

	res := make([]*domain.DeliveryAttempt, 0)
	for _, d := range s.deliveries {
		if filter.Status != "" && d.Status != filter.Status {
			continue
		}
		if filter.EndpointID != "" && d.EndpointID != filter.EndpointID {
			continue
		}
		if filter.EventID != "" && d.EventID != filter.EventID {
			continue
		}
		res = append(res, copyDelivery(d))
	}

	sort.Slice(res, func(i, j int) bool {
		if res[i].CreatedAt.Equal(res[j].CreatedAt) {
			return res[i].ID < res[j].ID
		}
		return res[i].CreatedAt.Before(res[j].CreatedAt)
	})
	return res, nil
}

func (s *MemoryStore) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrStoreClosed
	}
	return nil
}

func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}
