package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

func (w *statusResponseWriter) WriteHeader(code int) {
	if w.statusCode == 0 {
		w.statusCode = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

func generateRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

// Logging returns a middleware that logs incoming HTTP requests with slog and sets X-Request-ID.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			reqID := r.Header.Get("X-Request-ID")
			if reqID == "" {
				reqID = r.Header.Get("X-Trace-ID")
			}
			if reqID == "" {
				reqID = generateRequestID()
			}

			w.Header().Set("X-Request-ID", reqID)

			wrapped := &statusResponseWriter{
				ResponseWriter: w,
				statusCode:     0,
			}

			next.ServeHTTP(wrapped, r)

			if wrapped.statusCode == 0 {
				wrapped.statusCode = http.StatusOK
			}

			duration := time.Since(start)
			logger.Info("http request",
				"trace_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"remote_addr", r.RemoteAddr,
				"bytes", wrapped.written,
			)
		})
	}
}
