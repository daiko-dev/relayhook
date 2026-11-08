package domain

import (
	"encoding/json"
	"time"
)

type DeliveryStatus string

const (
	StatusQueued     DeliveryStatus = "QUEUED"
	StatusProcessing DeliveryStatus = "PROCESSING"
	StatusDelivered  DeliveryStatus = "DELIVERED"
	StatusFailed     DeliveryStatus = "FAILED"
	StatusDeadLetter DeliveryStatus = "DEAD_LETTER"

	DefaultAppID      = "default"
	DefaultMaxRetries = 5
)

type App struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Endpoint struct {
	ID         string    `json:"id"`
	AppID      string    `json:"app_id"`
	URL        string    `json:"url"`
	Secret     string    `json:"secret"`
	EventTypes []string  `json:"event_types"`
	IsActive   bool      `json:"is_active"`
	MaxRetries int       `json:"max_retries,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type Event struct {
	ID             string          `json:"id"`
	AppID          string          `json:"app_id"`
	EventType      string          `json:"event_type"`
	Payload        json.RawMessage `json:"payload"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type DeliveryAttempt struct {
	ID           string         `json:"id"`
	EventID      string         `json:"event_id"`
	EndpointID   string         `json:"endpoint_id"`
	Status       DeliveryStatus `json:"status"`
	AttemptCount int            `json:"attempt_count"`
	MaxRetries   int            `json:"max_retries"`
	StatusCode   int            `json:"status_code,omitempty"`
	ResponseTime int64          `json:"response_time_ms,omitempty"`
	LastError    string         `json:"last_error,omitempty"`
	NextRetryAt  *time.Time     `json:"next_retry_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

type DeliveryFilter struct {
	Status     DeliveryStatus
	EndpointID string
	EventID    string
}
