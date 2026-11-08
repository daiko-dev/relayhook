package domain

import "context"

type Store interface {
	CreateApp(ctx context.Context, app *App) error
	GetApp(ctx context.Context, id string) (*App, error)
	ListApps(ctx context.Context) ([]*App, error)

	CreateEndpoint(ctx context.Context, ep *Endpoint) error
	GetEndpoint(ctx context.Context, id string) (*Endpoint, error)
	ListEndpoints(ctx context.Context, appID string) ([]*Endpoint, error)
	DeleteEndpoint(ctx context.Context, id string) error

	CreateEvent(ctx context.Context, ev *Event) (existing *Event, created bool, err error)
	GetEvent(ctx context.Context, id string) (*Event, error)

	CreateDelivery(ctx context.Context, d *DeliveryAttempt) error
	GetDelivery(ctx context.Context, id string) (*DeliveryAttempt, error)
	UpdateDelivery(ctx context.Context, d *DeliveryAttempt) error
	ListDeliveries(ctx context.Context, filter DeliveryFilter) ([]*DeliveryAttempt, error)

	Ping(ctx context.Context) error
	Close() error
}

type Queue interface {
	Enqueue(deliveryID string) error
	Dequeue() <-chan string
	Len() int
	Close()
}
