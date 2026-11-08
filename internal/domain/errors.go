package domain

import "errors"

var (
	ErrNotFound         = errors.New("resource not found")
	ErrDuplicate        = errors.New("duplicate resource")
	ErrInvalidInput     = errors.New("invalid input")
	ErrQueueFull        = errors.New("dispatch queue is full")
	ErrQueueClosed      = errors.New("dispatch queue is closed")
	ErrInvalidSignature = errors.New("invalid webhook signature")
	ErrTimestampExpired = errors.New("webhook timestamp expired")
)
