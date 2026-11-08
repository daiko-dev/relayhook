package middleware_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daiko-dev/relayhook/internal/middleware"
)

func TestLogging_SetsRequestIDAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	handler := middleware.Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test-path", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rr.Code)
	}
	reqID := rr.Header().Get("X-Request-ID")
	if reqID == "" {
		t.Fatal("expected non-empty X-Request-ID header")
	}

	logOutput := buf.String()
	if !bytes.Contains([]byte(logOutput), []byte("/test-path")) {
		t.Fatalf("expected log to contain path, got: %s", logOutput)
	}
	if !bytes.Contains([]byte(logOutput), []byte(reqID)) {
		t.Fatalf("expected log to contain request ID %q, got: %s", reqID, logOutput)
	}
}

func TestLogging_PreservesExistingRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	handler := middleware.Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/existing-id", nil)
	req.Header.Set("X-Request-ID", "custom-req-12345")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-ID"); got != "custom-req-12345" {
		t.Fatalf("expected custom-req-12345, got %q", got)
	}
}

func TestRecoverer_RecoversPanicAndReturns500JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	handler := middleware.Recoverer(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went horribly wrong")
	}))

	req := httptest.NewRequest(http.MethodGet, "/panic-route", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	var jsonResp map[string]string
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		t.Fatalf("expected valid JSON response, got: %s", string(body))
	}
	if jsonResp["error"] != "internal server error" {
		t.Fatalf("expected error='internal server error', got: %v", jsonResp)
	}
}
