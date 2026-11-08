package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/daiko-dev/relayhook/pkg/sdk"
)

type CapturedRequest struct {
	Method     string      `json:"method"`
	Path       string      `json:"path"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
	DeliveryID string      `json:"delivery_id"`
	EventType  string      `json:"event_type"`
	ReceivedAt time.Time   `json:"received_at"`
	Attempt    int         `json:"attempt"`
	Status     int         `json:"status"`
}

type MockReceiver struct {
	secret      string
	failFirst   int
	delay       time.Duration
	failRate    float64
	fixedStatus int
	logger      *slog.Logger

	mu         sync.Mutex
	attempts   map[string]int
	requests   []CapturedRequest
	totalCount int
}

func NewMockReceiver(secret string, failFirst int, delay time.Duration, failRate float64, fixedStatus int, logger *slog.Logger) *MockReceiver {
	if fixedStatus <= 0 {
		fixedStatus = http.StatusOK
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return &MockReceiver{
		secret:      secret,
		failFirst:   failFirst,
		delay:       delay,
		failRate:    failRate,
		fixedStatus: fixedStatus,
		logger:      logger,
		attempts:    make(map[string]int),
		requests:    make([]CapturedRequest, 0),
	}
}

func (m *MockReceiver) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.requests)
	})

	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.attempts = make(map[string]int)
		m.requests = make([]CapturedRequest, 0)
		m.totalCount = 0
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reset":true}`))
	})

	handleWebhook := func(w http.ResponseWriter, r *http.Request) {
		var (
			body []byte
			err  error
		)

		if m.secret != "" {
			verifier := sdk.NewVerifier(m.secret, 5*time.Minute)
			body, err = verifier.VerifyRequest(r)
			if err != nil {
				m.logger.Warn("webhook signature verification failed", "error", err, "remote_addr", r.RemoteAddr)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized: " + err.Error()})
				return
			}
		} else {
			verifier := sdk.NewVerifier("dummy", 0)
			body, _ = verifier.VerifyRequest(r)
		}

		if m.delay > 0 {
			time.Sleep(m.delay)
		}

		deliveryID := r.Header.Get("X-RelayHook-ID")
		eventType := r.Header.Get("X-RelayHook-Event")

		m.mu.Lock()
		m.totalCount++
		currentAttempt := 1
		if deliveryID != "" {
			m.attempts[deliveryID]++
			currentAttempt = m.attempts[deliveryID]
		}

		status := m.fixedStatus
		if m.failFirst > 0 && deliveryID != "" {
			if currentAttempt <= m.failFirst {
				status = http.StatusInternalServerError
			} else {
				status = http.StatusOK
			}
		} else if m.failRate > 0 && rand.Float64() < m.failRate {
			status = http.StatusInternalServerError
		}

		m.requests = append(m.requests, CapturedRequest{
			Method:     r.Method,
			Path:       r.URL.Path,
			Headers:    r.Header.Clone(),
			Body:       string(body),
			DeliveryID: deliveryID,
			EventType:  eventType,
			ReceivedAt: time.Now().UTC(),
			Attempt:    currentAttempt,
			Status:     status,
		})
		m.mu.Unlock()

		m.logger.Info("webhook processed",
			"delivery_id", deliveryID,
			"event_type", eventType,
			"attempt", currentAttempt,
			"status", status,
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"received":    true,
			"attempt":     currentAttempt,
			"delivery_id": deliveryID,
			"status":      status,
		})
	}

	mux.HandleFunc("POST /webhook", handleWebhook)
	mux.HandleFunc("POST /", handleWebhook)

	return mux
}

func main() {
	var (
		port        int
		failFirst   int
		secret      string
		delay       time.Duration
		failRate    float64
		fixedStatus int
	)

	flag.IntVar(&port, "port", 9090, "Port for mock-receiver server")
	flag.IntVar(&failFirst, "fail-first", 0, "Number of initial failures per delivery ID before success")
	flag.StringVar(&secret, "secret", "", "Shared HMAC secret key for webhook verification")
	flag.DurationVar(&delay, "delay", 0, "Artificial response delay")
	flag.Float64Var(&failRate, "fail-rate", 0.0, "Probabilistic random failure rate (0.0 to 1.0)")
	flag.IntVar(&fixedStatus, "fixed-status", http.StatusOK, "Fixed HTTP response status code")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	receiver := NewMockReceiver(secret, failFirst, delay, failRate, fixedStatus, logger)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           receiver.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("starting mock-receiver server",
			"port", port,
			"fail_first", failFirst,
			"has_secret", secret != "",
			"delay", delay.String(),
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("mock-receiver server failed", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	logger.Info("mock-receiver stopped cleanly")
}
