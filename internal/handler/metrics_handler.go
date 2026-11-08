package handler

import (
	"net/http"

	"github.com/daiko-dev/relayhook/internal/dispatcher"
	"github.com/daiko-dev/relayhook/internal/domain"
)

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadyz(store domain.Store, pool *dispatcher.WorkerPool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "store uninitialized")
			return
		}
		if err := store.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "store unavailable: "+err.Error())
			return
		}
		if pool != nil && !pool.IsRunning() {
			writeError(w, http.StatusServiceUnavailable, "worker pool not running")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
