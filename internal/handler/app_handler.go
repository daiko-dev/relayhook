package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

type createAppRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type createEndpointRequest struct {
	URL        string   `json:"url"`
	Secret     string   `json:"secret"`
	EventTypes []string `json:"event_types"`
	MaxRetries *int     `json:"max_retries"`
	IsActive   *bool    `json:"is_active"`
	AppID      string   `json:"app_id"`
}

func handleCreateApp(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createAppRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}

		appID := strings.TrimSpace(req.ID)
		if appID == "" {
			appID = randomID("app_")
		}

		app := &domain.App{
			ID:        appID,
			Name:      strings.TrimSpace(req.Name),
			CreatedAt: time.Now().UTC(),
		}

		if err := store.CreateApp(r.Context(), app); err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}

		writeJSON(w, http.StatusCreated, app)
	}
}

func handleListApps(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apps, err := store.ListApps(r.Context())
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		if apps == nil {
			apps = make([]*domain.App, 0)
		}
		writeJSON(w, http.StatusOK, apps)
	}
}

func handleGetApp(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if strings.TrimSpace(id) == "" {
			writeError(w, http.StatusBadRequest, "app id is required")
			return
		}
		app, err := store.GetApp(r.Context(), id)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, app)
	}
}

func generateSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

func handleCreateEndpoint(store domain.Store, fromPathAppID bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createEndpointRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}

		targetURL := strings.TrimSpace(req.URL)
		if targetURL == "" {
			writeError(w, http.StatusBadRequest, "url is required")
			return
		}
		parsedURL, err := url.ParseRequestURI(targetURL)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			writeError(w, http.StatusBadRequest, "valid http or https url is required")
			return
		}

		appID := ""
		if fromPathAppID {
			appID = strings.TrimSpace(r.PathValue("id"))
		} else {
			appID = strings.TrimSpace(req.AppID)
		}
		if appID == "" {
			appID = domain.DefaultAppID
		}

		if _, err := store.GetApp(r.Context(), appID); err != nil {
			writeError(w, http.StatusNotFound, "app not found")
			return
		}

		secret := strings.TrimSpace(req.Secret)
		if secret == "" {
			secret = generateSecret()
		}

		maxRetries := domain.DefaultMaxRetries
		if req.MaxRetries != nil {
			if *req.MaxRetries > 0 {
				maxRetries = *req.MaxRetries
			}
		}

		isActive := true
		if req.IsActive != nil {
			isActive = *req.IsActive
		}

		eventTypes := req.EventTypes
		if len(eventTypes) == 0 {
			eventTypes = []string{"*"}
		}

		ep := &domain.Endpoint{
			ID:         randomID("ep_"),
			AppID:      appID,
			URL:        targetURL,
			Secret:     secret,
			EventTypes: eventTypes,
			IsActive:   isActive,
			MaxRetries: maxRetries,
			CreatedAt:  time.Now().UTC(),
		}

		if err := store.CreateEndpoint(r.Context(), ep); err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}

		writeJSON(w, http.StatusCreated, ep)
	}
}

func handleListAppEndpoints(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := r.PathValue("id")
		endpoints, err := store.ListEndpoints(r.Context(), appID)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		if endpoints == nil {
			endpoints = make([]*domain.Endpoint, 0)
		}
		writeJSON(w, http.StatusOK, endpoints)
	}
}

func handleListEndpoints(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID := r.URL.Query().Get("app_id")
		endpoints, err := store.ListEndpoints(r.Context(), appID)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		if endpoints == nil {
			endpoints = make([]*domain.Endpoint, 0)
		}
		writeJSON(w, http.StatusOK, endpoints)
	}
}

func handleGetEndpoint(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ep, err := store.GetEndpoint(r.Context(), id)
		if err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, ep)
	}
}

func handleDeleteEndpoint(store domain.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := store.DeleteEndpoint(r.Context(), id); err != nil {
			code, msg := mapDomainError(err)
			writeError(w, code, msg)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	}
}
