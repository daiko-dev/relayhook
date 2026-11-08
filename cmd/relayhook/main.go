package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
	"github.com/daiko-dev/relayhook/internal/handler"
	"github.com/daiko-dev/relayhook/internal/observability"
	"github.com/daiko-dev/relayhook/internal/queue"
	"github.com/daiko-dev/relayhook/internal/storage/memory"
	"github.com/daiko-dev/relayhook/internal/storage/sqlite"
)

func main() {
	var (
		port       int
		workers    int
		dbPath     string
		baseDelay  time.Duration
		maxDelay   time.Duration
		timeout    time.Duration
	)

	flag.IntVar(&port, "port", 8080, "HTTP server listening port")
	flag.IntVar(&workers, "workers", dispatcher.DefaultWorkerCount, "Number of concurrent worker goroutines")
	flag.StringVar(&dbPath, "db", "", "Path to SQLite database file (empty for in-memory)")
	flag.DurationVar(&baseDelay, "base-delay", dispatcher.DefaultBaseDelay, "Initial retry delay")
	flag.DurationVar(&maxDelay, "max-delay", dispatcher.DefaultMaxDelay, "Maximum retry delay ceiling")
	flag.DurationVar(&timeout, "timeout", dispatcher.DefaultClientTimeout, "HTTP client timeout for webhook deliveries")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	var (
		store domain.Store
		err   error
	)

	if dbPath == "" {
		store = memory.NewMemoryStore()
		logger.Info("initialized in-memory store", "storage", "memory")
	} else {
		store, err = sqlite.NewSQLiteStore(dbPath)
		if err != nil {
			logger.Error("failed to open sqlite store", "path", dbPath, "error", err)
			os.Exit(1)
		}
		logger.Info("initialized persistent sqlite store", "path", dbPath)
	}
	defer store.Close()

	metrics := observability.NewMetrics()
	q := queue.NewChannelQueue(queue.DefaultQueueCapacity)
	sched := queue.NewScheduler(q)
	client := dispatcher.NewWebhookClient(timeout)

	breakers := dispatcher.NewCircuitBreakerRegistry(dispatcher.CircuitBreakerConfig{
		FailureThreshold: dispatcher.DefaultFailureThreshold,
		ResetTimeout:     dispatcher.DefaultResetTimeout,
		OnStateChange: func(endpointID string, state dispatcher.CircuitState) {
			metrics.SetCircuitBreakerState(endpointID, int(state))
		},
	})

	pool := dispatcher.NewWorkerPool(dispatcher.WorkerPoolConfig{
		WorkerCount: workers,
		BaseDelay:   baseDelay,
		MaxDelay:    maxDelay,
		MaxRetries:  domain.DefaultMaxRetries,
	}, store, q, sched, client, breakers, metrics, logger)

	pool.Start()
	defer pool.Stop()

	router := handler.NewRouter(handler.RouterDeps{
		Store:      store,
		WorkerPool: pool,
		Metrics:    metrics,
		Logger:     logger,
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		logger.Info("starting relayhook server",
			"port", port,
			"workers", workers,
			"base_delay", baseDelay.String(),
			"max_delay", maxDelay.String(),
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-serverErrCh:
		logger.Error("server listener failed", "error", err)
		os.Exit(1)
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful HTTP server shutdown failed", "error", err)
	} else {
		logger.Info("HTTP server stopped cleanly")
	}

	logger.Info("draining worker pool and closing storage...")
}
