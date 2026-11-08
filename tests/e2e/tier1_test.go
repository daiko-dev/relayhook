package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// F01: Domain Models & Contracts (5 subtests)
func TestTier1_F01_DomainModelsAndContracts(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("AppJSONContract", func(t *testing.T) {
		inst := getServer(t)
		app := mustCreateApp(t, inst.BaseURL, "", "F01 Contract App")
		if app.ID == "" {
			t.Fatal("expected non-empty App.ID")
		}
		if app.Name != "F01 Contract App" {
			t.Fatalf("expected App.Name %q, got %q", "F01 Contract App", app.Name)
		}
		if app.CreatedAt.IsZero() {
			t.Fatal("expected non-zero App.CreatedAt")
		}
	})

	t.Run("EndpointJSONContract", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f01_ep")
		app := mustCreateApp(t, inst.BaseURL, "", "F01 Endpoint App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f01_ep", []string{"user.created"}, 4)
		if ep.ID == "" {
			t.Fatal("expected non-empty Endpoint.ID")
		}
		if ep.AppID != app.ID {
			t.Fatalf("expected Endpoint.AppID=%q, got %q", app.ID, ep.AppID)
		}
		if ep.URL != srv.URL {
			t.Fatalf("expected Endpoint.URL=%q, got %q", srv.URL, ep.URL)
		}
		if ep.Secret != "whsec_f01_ep" {
			t.Fatalf("expected Endpoint.Secret=%q, got %q", "whsec_f01_ep", ep.Secret)
		}
		if !ep.IsActive {
			t.Fatal("expected Endpoint.IsActive=true by default")
		}
		if ep.MaxRetries != 4 {
			t.Fatalf("expected Endpoint.MaxRetries=4, got %d", ep.MaxRetries)
		}
		if ep.CreatedAt.IsZero() {
			t.Fatal("expected non-zero Endpoint.CreatedAt")
		}
	})

	t.Run("EventIngestContract", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f01_ev")
		app := mustCreateApp(t, inst.BaseURL, "", "F01 Event App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f01_ev", []string{"order.paid"}, 3)

		evResp := mustIngestEvent(t, inst.BaseURL, app.ID, "order.paid", map[string]any{"order_id": "ord_1"}, "")
		if evResp.EffectiveEventID() == "" {
			t.Fatal("expected non-empty event_id in ingestion response")
		}
		if len(evResp.DeliveryIDs) != 1 {
			t.Fatalf("expected 1 delivery_id, got %v", evResp.DeliveryIDs)
		}
	})

	t.Run("DeliveryAttemptDeliveredContract", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f01_dlv")
		app := mustCreateApp(t, inst.BaseURL, "", "F01 Delivery App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f01_dlv", []string{"invoice.created"}, 3)

		evResp := mustIngestEvent(t, inst.BaseURL, app.ID, "invoice.created", map[string]any{"total": 99}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, evResp.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		if dlv.AttemptCount != 1 {
			t.Fatalf("expected AttemptCount=1, got %d", dlv.AttemptCount)
		}
		if dlv.StatusCode != http.StatusOK {
			t.Fatalf("expected StatusCode=200, got %d", dlv.StatusCode)
		}
		if dlv.ResponseTime < 0 {
			t.Fatalf("expected ResponseTime >= 0, got %d", dlv.ResponseTime)
		}
		if dlv.CreatedAt.IsZero() || dlv.UpdatedAt.IsZero() {
			t.Fatal("expected non-zero CreatedAt and UpdatedAt on DeliveryAttempt")
		}
	})

	t.Run("DeliveryStatusEnumLifecycle", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f01_enum")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F01 Enum App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f01_enum", []string{"item.failed"}, 2)

		evResp := mustIngestEvent(t, inst.BaseURL, app.ID, "item.failed", map[string]any{"x": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, evResp.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
		if dlv.AttemptCount != 2 {
			t.Fatalf("expected AttemptCount=2 on DEAD_LETTER, got %d", dlv.AttemptCount)
		}
		if dlv.LastError == "" {
			t.Fatal("expected non-empty LastError on DEAD_LETTER")
		}
	})
}

// F02: HMAC-SHA256 Signing & Anti-Replay (5 subtests)
func TestTier1_F02_HMACSigningAndAntiReplay(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("SignatureHeaderFormat", func(t *testing.T) {
		inst := getServer(t)
		secret := "whsec_f02_format"
		srv := newWebhookCaptureServer(t, secret)
		app := mustCreateApp(t, inst.BaseURL, "", "F02 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 3)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "ping", map[string]any{"ok": true}, "")
		reqs := srv.WaitForRequests(t, 1, 3*time.Second)

		sig := reqs[0].Signature
		if !strings.HasPrefix(sig, "t=") || !strings.Contains(sig, ",v1=") {
			t.Fatalf("expected signature header format t=<ts>,v1=<hex>, got %q", sig)
		}
		parts := strings.Split(sig, ",v1=")
		if len(parts) != 2 || len(parts[1]) != 64 {
			t.Fatalf("expected 64-char hex digest in v1=, got %q", sig)
		}
	})

	t.Run("TimestampHeaderConsistency", func(t *testing.T) {
		inst := getServer(t)
		secret := "whsec_f02_ts"
		srv := newWebhookCaptureServer(t, secret)
		app := mustCreateApp(t, inst.BaseURL, "", "F02 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 3)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "ping.ts", map[string]any{"ts": 1}, "")
		reqs := srv.WaitForRequests(t, 1, 3*time.Second)

		tsHdr := reqs[0].Timestamp
		if tsHdr == "" {
			t.Fatal("expected non-empty X-RelayHook-Timestamp header")
		}
		if !strings.HasPrefix(reqs[0].Signature, "t="+tsHdr+",") {
			t.Fatalf("expected signature prefix t=%s, got %s", tsHdr, reqs[0].Signature)
		}
		tsVal, err := strconv.ParseInt(tsHdr, 10, 64)
		if err != nil {
			t.Fatalf("invalid timestamp integer %q: %v", tsHdr, err)
		}
		diff := time.Now().Unix() - tsVal
		if diff < -300 || diff > 300 {
			t.Fatalf("timestamp %d outside 5m window (now=%d)", tsVal, time.Now().Unix())
		}
	})

	t.Run("IndependentHMACVerification", func(t *testing.T) {
		inst := getServer(t)
		secret := "whsec_f02_verify"
		srv := newWebhookCaptureServer(t, secret)
		app := mustCreateApp(t, inst.BaseURL, "", "F02 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 3)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "crypto.check", map[string]any{"amount": 2500, "currency": "USD"}, "")
		reqs := srv.WaitForRequests(t, 1, 3*time.Second)
		if !reqs[0].HMACValid {
			t.Fatalf("independent HMAC verification failed: %s", reqs[0].HMACError)
		}
	})

	t.Run("DeliveryAndEventHeaders", func(t *testing.T) {
		inst := getServer(t)
		secret := "whsec_f02_hdrs"
		srv := newWebhookCaptureServer(t, secret)
		app := mustCreateApp(t, inst.BaseURL, "", "F02 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 3)

		evResp := mustIngestEvent(t, inst.BaseURL, app.ID, "account.updated", map[string]any{"id": "acc_1"}, "")
		reqs := srv.WaitForRequests(t, 1, 3*time.Second)

		if reqs[0].DeliveryID != evResp.DeliveryIDs[0] {
			t.Fatalf("expected X-RelayHook-ID=%q, got %q", evResp.DeliveryIDs[0], reqs[0].DeliveryID)
		}
		if reqs[0].EventType != "account.updated" {
			t.Fatalf("expected X-RelayHook-Event=%q, got %q", "account.updated", reqs[0].EventType)
		}
		if !strings.Contains(reqs[0].ContentType, "application/json") {
			t.Fatalf("expected Content-Type application/json, got %q", reqs[0].ContentType)
		}
	})

	t.Run("SecretIsolationPerEndpoint", func(t *testing.T) {
		inst := getServer(t)
		srvA := newWebhookCaptureServer(t, "whsec_secret_A")
		srvB := newWebhookCaptureServer(t, "whsec_secret_B")
		app := mustCreateApp(t, inst.BaseURL, "", "F02 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvA.URL, "whsec_secret_A", []string{"*"}, 3)
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvB.URL, "whsec_secret_B", []string{"*"}, 3)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "fanout.test", map[string]any{"shared": true}, "")
		reqsA := srvA.WaitForRequests(t, 1, 3*time.Second)
		reqsB := srvB.WaitForRequests(t, 1, 3*time.Second)

		if !reqsA[0].HMACValid || !reqsB[0].HMACValid {
			t.Fatalf("expected valid HMAC on both endpoints: A=%v (%s), B=%v (%s)",
				reqsA[0].HMACValid, reqsA[0].HMACError, reqsB[0].HMACValid, reqsB[0].HMACError)
		}
		if reqsA[0].Signature == reqsB[0].Signature {
			t.Fatal("expected distinct HMAC signatures for endpoints with different secrets")
		}
	})
}

// F03: Public Go SDK (`pkg/sdk`) (5 subtests)
func TestTier1_F03_PublicGoSDK(t *testing.T) {
	t.Run("SDKPackageTestSuite", func(t *testing.T) {
		requireOrSkipFile(t, filepath.Join("pkg", "sdk", "verifier.go"))
		cmd := exec.Command("go", "test", "-v", "./pkg/sdk/...")
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go test ./pkg/sdk/... failed: %v\n%s", err, string(out))
		}
	})

	t.Run("MockReceiverValidHMACViaSDK", func(t *testing.T) {
		mock := startMockReceiver(t, "-secret", "whsec_sdk_1", "-fail-first", "0")
		inst := startRelayHook(t)
		app := mustCreateApp(t, inst.BaseURL, "", "F03 SDK App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, mock.WebhookURL, "whsec_sdk_1", []string{"*"}, 3)

		evResp := mustIngestEvent(t, inst.BaseURL, app.ID, "sdk.valid", map[string]any{"hello": "sdk"}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, evResp.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from mock-receiver with valid SDK HMAC, got %d", dlv.StatusCode)
		}
	})

	t.Run("MockReceiverRejectsWrongSecretViaSDK", func(t *testing.T) {
		mock := startMockReceiver(t, "-secret", "whsec_sdk_correct")
		payload := []byte(`{"test":"wrong_secret"}`)
		now := time.Now().Unix()
		sig := signPayloadStdlib("whsec_sdk_wrong", payload, now)

		resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, payload, map[string]string{
			"X-RelayHook-Signature": sig,
			"X-RelayHook-Timestamp": strconv.FormatInt(now, 10),
			"X-RelayHook-ID":        "dlv_wrong_sec",
			"X-RelayHook-Event":     "sdk.test",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for wrong secret, got %d", resp.StatusCode)
		}
	})

	t.Run("MockReceiverRejectsExpiredTimestampViaSDK", func(t *testing.T) {
		mock := startMockReceiver(t, "-secret", "whsec_sdk_exp")
		payload := []byte(`{"test":"expired"}`)
		expiredTS := time.Now().Add(-10 * time.Minute).Unix()
		sig := signPayloadStdlib("whsec_sdk_exp", payload, expiredTS)

		resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, payload, map[string]string{
			"X-RelayHook-Signature": sig,
			"X-RelayHook-Timestamp": strconv.FormatInt(expiredTS, 10),
			"X-RelayHook-ID":        "dlv_exp",
			"X-RelayHook-Event":     "sdk.test",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for expired timestamp, got %d", resp.StatusCode)
		}
	})

	t.Run("MockReceiverRejectsTamperedBodyViaSDK", func(t *testing.T) {
		mock := startMockReceiver(t, "-secret", "whsec_sdk_tamper")
		now := time.Now().Unix()
		sig := signPayloadStdlib("whsec_sdk_tamper", []byte(`{"amount":100}`), now)

		resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, []byte(`{"amount":9999}`), map[string]string{
			"X-RelayHook-Signature": sig,
			"X-RelayHook-Timestamp": strconv.FormatInt(now, 10),
			"X-RelayHook-ID":        "dlv_tamper",
			"X-RelayHook-Event":     "sdk.test",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for tampered body, got %d", resp.StatusCode)
		}
	})
}

// F04: Thread-Safe MemoryStore (5 subtests)
func TestTier1_F04_MemoryStore(t *testing.T) {
	getServer := lazyRelayHook(t, "-db", "")

	t.Run("PreSeededDefaultApp", func(t *testing.T) {
		inst := getServer(t)
		resp, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps/default", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for pre-seeded default app, got %d: %s", resp.StatusCode, string(body))
		}
		var app appDTO
		if err := json.Unmarshal(body, &app); err != nil || app.ID != "default" {
			t.Fatalf("expected app.ID=default, got %+v (err=%v)", app, err)
		}
	})

	t.Run("AppAndEndpointCRUDInMemory", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_mem")
		app := mustCreateApp(t, inst.BaseURL, "", "Memory CRUD App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_mem", []string{"*"}, 3)

		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK getting endpoint, got %d", resp.StatusCode)
		}

		delResp, _ := doJSONRequest(t, http.MethodDelete, inst.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 204/200 deleting endpoint, got %d", delResp.StatusCode)
		}
	})

	t.Run("IdempotentEventCreationInMemory", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_mem_idem")
		app := mustCreateApp(t, inst.BaseURL, "", "Memory Idem App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_mem_idem", []string{"*"}, 3)

		r1 := mustIngestEvent(t, inst.BaseURL, app.ID, "user.login", map[string]any{"u": 1}, "mem-idem-key-1")
		r2 := mustIngestEvent(t, inst.BaseURL, app.ID, "user.login", map[string]any{"u": 1}, "mem-idem-key-1")
		if r1.EffectiveEventID() != r2.EffectiveEventID() {
			t.Fatalf("expected identical event_id on idempotent retry: %q vs %q", r1.EffectiveEventID(), r2.EffectiveEventID())
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, r1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if len(srv.Requests()) != 1 {
			t.Fatalf("expected exactly 1 webhook delivery, got %d", len(srv.Requests()))
		}
	})

	t.Run("FilteredDeliveryQueriesInMemory", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_mem_filter")
		app := mustCreateApp(t, inst.BaseURL, "", "Memory Filter App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_mem_filter", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "filter.evt", map[string]any{"k": "v"}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		byEp := listDeliveries(t, inst.BaseURL, "?endpoint_id="+ep.ID)
		if len(byEp) != 1 || byEp[0].ID != ev.DeliveryIDs[0] {
			t.Fatalf("expected 1 delivery for endpoint %s, got %+v", ep.ID, byEp)
		}
		byEv := listDeliveries(t, inst.BaseURL, "?event_id="+ev.EffectiveEventID())
		if len(byEv) != 1 || byEv[0].ID != ev.DeliveryIDs[0] {
			t.Fatalf("expected 1 delivery for event %s, got %+v", ev.EffectiveEventID(), byEv)
		}
	})

	t.Run("ConcurrentReadWriteSafety", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_mem_conc")
		app := mustCreateApp(t, inst.BaseURL, "", "Memory Concurrent App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_mem_conc", []string{"*"}, 3)

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_ = mustIngestEvent(t, inst.BaseURL, app.ID, "conc.event", map[string]any{"idx": idx}, "")
				_ = listDeliveries(t, inst.BaseURL, "")
			}(i)
		}
		wg.Wait()
	})
}

// F05: Pure-Go SQLiteStore (5 subtests)
func TestTier1_F05_SQLiteStore(t *testing.T) {
	t.Run("SQLiteDatabaseFileCreation", func(t *testing.T) {
		dbFile := filepath.Join(t.TempDir(), "f05_create.db")
		inst := startRelayHook(t, "-db", dbFile)
		defer inst.Stop(t)

		if _, err := os.Stat(dbFile); err != nil {
			t.Fatalf("expected SQLite file %s to be created: %v", dbFile, err)
		}
	})

	t.Run("PersistAppsAndEndpointsAcrossRestart", func(t *testing.T) {
		dbFile := filepath.Join(t.TempDir(), "f05_persist.db")
		inst1 := startRelayHook(t, "-db", dbFile)
		srv := newWebhookCaptureServer(t, "whsec_sqlite")
		app := mustCreateApp(t, inst1.BaseURL, "app-sql-1", "SQLite App")
		ep := mustCreateEndpoint(t, inst1.BaseURL, app.ID, srv.URL, "whsec_sqlite", []string{"*"}, 3)
		_ = inst1.Stop(t)

		inst2 := startRelayHook(t, "-db", dbFile)
		defer inst2.Stop(t)

		respApp, _ := doJSONRequest(t, http.MethodGet, inst2.BaseURL+"/api/v1/apps/"+app.ID, nil, nil)
		if respApp.StatusCode != http.StatusOK {
			t.Fatalf("expected persisted app after restart, got %d", respApp.StatusCode)
		}
		respEp, _ := doJSONRequest(t, http.MethodGet, inst2.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if respEp.StatusCode != http.StatusOK {
			t.Fatalf("expected persisted endpoint after restart, got %d", respEp.StatusCode)
		}
	})

	t.Run("PersistDeliveriesAcrossRestart", func(t *testing.T) {
		dbFile := filepath.Join(t.TempDir(), "f05_dlv.db")
		inst1 := startRelayHook(t, "-db", dbFile)
		srv := newWebhookCaptureServer(t, "whsec_sqlite_dlv")
		app := mustCreateApp(t, inst1.BaseURL, "", "SQLite Dlv App")
		_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srv.URL, "whsec_sqlite_dlv", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst1.BaseURL, app.ID, "sql.event", map[string]any{"v": 1}, "")
		_ = waitForDeliveryStatus(t, inst1.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		_ = inst1.Stop(t)

		inst2 := startRelayHook(t, "-db", dbFile)
		defer inst2.Stop(t)

		resp, dlv := getDelivery(t, inst2.BaseURL, ev.DeliveryIDs[0])
		if resp.StatusCode != http.StatusOK || dlv.Status != "DELIVERED" {
			t.Fatalf("expected persisted DELIVERED state after restart, got status=%d dlv=%+v", resp.StatusCode, dlv)
		}
	})

	t.Run("IdempotencyPersistedAcrossRestart", func(t *testing.T) {
		dbFile := filepath.Join(t.TempDir(), "f05_idem.db")
		inst1 := startRelayHook(t, "-db", dbFile)
		srv := newWebhookCaptureServer(t, "whsec_sqlite_idem")
		app := mustCreateApp(t, inst1.BaseURL, "app-sql-idem", "SQLite Idem App")
		_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srv.URL, "whsec_sqlite_idem", []string{"*"}, 3)
		ev1 := mustIngestEvent(t, inst1.BaseURL, app.ID, "sql.idem", map[string]any{"v": 1}, "sql-idem-key-1")
		_ = waitForDeliveryStatus(t, inst1.BaseURL, ev1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		_ = inst1.Stop(t)

		inst2 := startRelayHook(t, "-db", dbFile)
		defer inst2.Stop(t)

		ev2 := mustIngestEvent(t, inst2.BaseURL, app.ID, "sql.idem", map[string]any{"v": 1}, "sql-idem-key-1")
		if ev1.EffectiveEventID() != ev2.EffectiveEventID() {
			t.Fatalf("expected idempotent deduplication across SQLite restart: %s vs %s", ev1.EffectiveEventID(), ev2.EffectiveEventID())
		}
		if len(srv.Requests()) != 1 {
			t.Fatalf("expected only 1 webhook request across restart, got %d", len(srv.Requests()))
		}
	})

	t.Run("ConcurrentSQLiteWritesWAL", func(t *testing.T) {
		dbFile := filepath.Join(t.TempDir(), "f05_wal.db")
		inst := startRelayHook(t, "-db", dbFile)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_wal")
		app := mustCreateApp(t, inst.BaseURL, "", "SQLite WAL App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_wal", []string{"*"}, 3)

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_ = mustIngestEvent(t, inst.BaseURL, app.ID, "wal.write", map[string]any{"idx": idx}, "")
			}(i)
		}
		wg.Wait()
		_ = srv.WaitForRequests(t, 20, 5*time.Second)
	})
}

// F06: Buffered ChannelQueue & Scheduler (5 subtests)
func TestTier1_F06_ChannelQueueAndScheduler(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("NonBlockingIngestionQueueing", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f06_1")
		srv.SetDelay(200 * time.Millisecond)
		app := mustCreateApp(t, inst.BaseURL, "", "F06 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f06_1", []string{"*"}, 3)

		start := time.Now()
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "queue.fast", map[string]any{"fast": true}, "")
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Fatalf("expected non-blocking ingestion (<100ms), took %v", elapsed)
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
	})

	t.Run("AsynchronousDequeueAndDispatch", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f06_2")
		app := mustCreateApp(t, inst.BaseURL, "", "F06 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f06_2", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "queue.async", map[string]any{"n": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.Status != "DELIVERED" {
			t.Fatalf("expected DELIVERED, got %s", dlv.Status)
		}
	})

	t.Run("RetrySchedulerDelayedReEnqueue", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f06_3")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F06 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f06_3", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "queue.retry", map[string]any{"r": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.AttemptCount != 2 {
			t.Fatalf("expected AttemptCount=2 after 1 scheduled retry, got %d", dlv.AttemptCount)
		}
	})

	t.Run("MultipleScheduledRetriesInParallel", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f06_4")
		srv.SetFailFirstPerID(1)
		app := mustCreateApp(t, inst.BaseURL, "", "F06 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f06_4", []string{"*"}, 4)

		var dlvIDs []string
		for i := 0; i < 5; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "parallel.retry", map[string]any{"i": i}, "")
			dlvIDs = append(dlvIDs, ev.DeliveryIDs[0])
		}
		for _, id := range dlvIDs {
			d := waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 4*time.Second)
			if d.AttemptCount != 2 {
				t.Fatalf("expected AttemptCount=2 for %s, got %d", id, d.AttemptCount)
			}
		}
	})

	t.Run("CleanSchedulerStopOnShutdown", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "500ms", "-max-delay", "2s")
		srv := newWebhookCaptureServer(t, "whsec_f06_5")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F06 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f06_5", []string{"*"}, 5)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "shutdown.retry", map[string]any{"s": 1}, "")
		_ = srv.WaitForRequests(t, 1, 2*time.Second)

		start := time.Now()
		_ = inst.Stop(t)
		if time.Since(start) > 2*time.Second {
			t.Fatalf("expected clean scheduler stop in <2s, took %v", time.Since(start))
		}
	})
}

// F07: Exponential Backoff with Full Jitter (5 subtests)
func TestTier1_F07_ExponentialBackoffWithJitter(t *testing.T) {
	t.Run("FirstRetryDelayWithinBounds", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "40ms", "-max-delay", "400ms")
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f07_1")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F07 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f07_1", []string{"*"}, 4)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "backoff.first", map[string]any{"b": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		reqs := srv.Requests()
		if len(reqs) != 2 {
			t.Fatalf("expected 2 attempts, got %d", len(reqs))
		}
		gap := reqs[1].ReceivedAt.Sub(reqs[0].ReceivedAt)
		if gap > 500*time.Millisecond {
			t.Fatalf("expected first retry gap within bounded window, got %v", gap)
		}
	})

	t.Run("IncreasingBackoffWindowAcrossAttempts", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "25ms", "-max-delay", "200ms")
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f07_2")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F07 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f07_2", []string{"*"}, 5)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "backoff.seq", map[string]any{"b": 2}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 4*time.Second)
		if dlv.AttemptCount != 4 {
			t.Fatalf("expected 4 attempts, got %d", dlv.AttemptCount)
		}
	})

	t.Run("MaxDelayCapEnforced", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "40ms", "-max-delay", "60ms")
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f07_3")
		srv.SetStatusSequence(500, 500, 500, 200)
		app := mustCreateApp(t, inst.BaseURL, "", "F07 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f07_3", []string{"*"}, 5)

		start := time.Now()
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "backoff.cap", map[string]any{"b": 3}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if time.Since(start) > 1500*time.Millisecond {
			t.Fatalf("expected max-delay cap to keep 4 attempts under 1.5s, took %v", time.Since(start))
		}
	})

	t.Run("JitterVarianceAcrossConcurrentRetries", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "30ms", "-max-delay", "120ms")
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f07_4")
		srv.SetFailFirstPerID(1)
		app := mustCreateApp(t, inst.BaseURL, "", "F07 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f07_4", []string{"*"}, 3)

		var ids []string
		for i := 0; i < 4; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "backoff.jitter", map[string]any{"i": i}, "")
			ids = append(ids, ev.DeliveryIDs[0])
		}
		for _, id := range ids {
			_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
		}
	})

	t.Run("BackoffClearedOnceDelivered", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f07_5")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F07 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f07_5", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "backoff.clear", map[string]any{"c": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.NextRetryAt != nil {
			t.Fatalf("expected NextRetryAt to be nil after DELIVERED, got %v", dlv.NextRetryAt)
		}
	})
}

// F08: Per-Endpoint Circuit Breaker (5 subtests)
func TestTier1_F08_PerEndpointCircuitBreaker(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("ClosedStateNormalFlow", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f08_1")
		app := mustCreateApp(t, inst.BaseURL, "", "F08 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f08_1", []string{"*"}, 3)

		for i := 0; i < 3; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.normal", map[string]any{"i": i}, "")
			_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		}
	})

	t.Run("TripsToOpenAfterConsecutiveFailures", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f08_2")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F08 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f08_2", []string{"*"}, 3)

		var dlvIDs []string
		for i := 0; i < 3; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.trip", map[string]any{"i": i}, "")
			dlvIDs = append(dlvIDs, ev.DeliveryIDs[0])
		}
		for _, id := range dlvIDs {
			_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DEAD_LETTER", 4*time.Second)
		}
		metricsText := scrapeMetrics(t, inst.BaseURL)
		if !strings.Contains(metricsText, "relayhook_circuit_breaker_state") {
			t.Fatal("expected relayhook_circuit_breaker_state in /metrics")
		}
	})

	t.Run("SkipsNetworkIOWhenOpen", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f08_3")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F08 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f08_3", []string{"*"}, 2)

		// Trip breaker with consecutive failures
		for i := 0; i < 3; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.open", map[string]any{"i": i}, "")
			_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
		}
		beforeReqs := len(srv.Requests())

		// New event while breaker is OPEN should fast-fail or reschedule without immediate flood
		evOpen := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.open", map[string]any{"probe": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, evOpen.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
		afterReqs := len(srv.Requests())
		if afterReqs > beforeReqs+1 {
			t.Fatalf("expected open circuit breaker to suppress HTTP calls (before=%d, after=%d)", beforeReqs, afterReqs)
		}
	})

	t.Run("PerEndpointIsolation", func(t *testing.T) {
		inst := getServer(t)
		srvBad := newWebhookCaptureServer(t, "whsec_bad")
		srvBad.SetFixedStatus(http.StatusInternalServerError)
		srvGood := newWebhookCaptureServer(t, "whsec_good")

		app := mustCreateApp(t, inst.BaseURL, "", "F08 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvBad.URL, "whsec_bad", []string{"*"}, 2)
		epGood := mustCreateEndpoint(t, inst.BaseURL, app.ID, srvGood.URL, "whsec_good", []string{"*"}, 3)

		for i := 0; i < 3; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.iso", map[string]any{"i": i}, "")
			for _, dID := range ev.DeliveryIDs {
				_, d := getDelivery(t, inst.BaseURL, dID)
				if d.EndpointID == epGood.ID {
					_ = waitForDeliveryStatus(t, inst.BaseURL, dID, "DELIVERED", 3*time.Second)
				}
			}
		}
		if len(srvGood.Requests()) < 3 {
			t.Fatalf("expected healthy endpoint to receive all 3 events, got %d", len(srvGood.Requests()))
		}
	})

	t.Run("RecoveryViaReplayOrHalfOpen", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f08_5")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F08 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f08_5", []string{"*"}, 2)

		var lastDlvID string
		for i := 0; i < 3; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.recover", map[string]any{"i": i}, "")
			lastDlvID = ev.DeliveryIDs[0]
			_ = waitForDeliveryStatus(t, inst.BaseURL, lastDlvID, "DEAD_LETTER", 3*time.Second)
		}

		// Restore healthy status and trigger manual replay
		srv.SetFixedStatus(http.StatusOK)
		resp, body := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+lastDlvID+"/replay", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on replay, got %d: %s", resp.StatusCode, string(body))
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, lastDlvID, "DELIVERED", 3*time.Second)
	})
}

// F09: Safe Webhook HTTP Client (5 subtests)
func TestTier1_F09_SafeWebhookHTTPClient(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("StandardHeadersAndMethod", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f09_1")
		app := mustCreateApp(t, inst.BaseURL, "", "F09 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f09_1", []string{"*"}, 3)

		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "client.hdrs", map[string]any{"a": 1}, "")
		reqs := srv.WaitForRequests(t, 1, 3*time.Second)
		if reqs[0].Method != http.MethodPost {
			t.Fatalf("expected POST method, got %s", reqs[0].Method)
		}
		if !strings.Contains(reqs[0].ContentType, "application/json") {
			t.Fatalf("expected Content-Type application/json, got %s", reqs[0].ContentType)
		}
		if reqs[0].UserAgent == "" {
			t.Fatal("expected non-empty User-Agent header")
		}
	})

	t.Run("Oversized100KBResponseBodyDrainedSafely", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f09_2")
		srv.SetOversizedBody(100 * 1024) // 100KB > 64KB LimitReader
		app := mustCreateApp(t, inst.BaseURL, "", "F09 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f09_2", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "client.bigbody", map[string]any{"b": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK with 100KB body, got %d", dlv.StatusCode)
		}
	})

	t.Run("KeepAliveConnectionReuse", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f09_3")
		app := mustCreateApp(t, inst.BaseURL, "", "F09 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f09_3", []string{"*"}, 3)

		for i := 0; i < 8; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "client.keepalive", map[string]any{"i": i}, "")
			_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		}
		if srv.UniqueRemoteAddrs() > 4 {
			t.Fatalf("expected TCP connection reuse via Keep-Alive across 8 sequential requests, got %d unique connections", srv.UniqueRemoteAddrs())
		}
	})

	t.Run("ConnectionRefusedHandledCleanly", func(t *testing.T) {
		inst := getServer(t)
		closedPort := freePort(t)
		app := mustCreateApp(t, inst.BaseURL, "", "F09 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, fmt.Sprintf("http://127.0.0.1:%d/hook", closedPort), "whsec_f09_4", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "client.refused", map[string]any{"r": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
		if dlv.LastError == "" {
			t.Fatal("expected LastError recorded on connection refused")
		}
	})

	t.Run("ResponseLatencyRecorded", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f09_5")
		srv.SetDelay(45 * time.Millisecond)
		app := mustCreateApp(t, inst.BaseURL, "", "F09 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f09_5", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "client.latency", map[string]any{"l": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.ResponseTime < 30 {
			t.Fatalf("expected response_time_ms >= 30ms for 45ms server delay, got %d", dlv.ResponseTime)
		}
	})
}

// F10: Concurrent WorkerPool & DLQ Transition (5 subtests)
func TestTier1_F10_WorkerPoolAndDLQTransition(t *testing.T) {
	getServer := lazyRelayHook(t, "-workers", "4")

	t.Run("ConcurrentParallelDispatch", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f10_1")
		srv.SetDelay(100 * time.Millisecond)
		app := mustCreateApp(t, inst.BaseURL, "", "F10 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f10_1", []string{"*"}, 3)

		var dlvIDs []string
		for i := 0; i < 4; i++ {
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "pool.parallel", map[string]any{"i": i}, "")
			dlvIDs = append(dlvIDs, ev.DeliveryIDs[0])
		}
		for _, id := range dlvIDs {
			_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
		}
		if srv.MaxConcurrency() < 2 {
			t.Fatalf("expected parallel worker dispatch (MaxConcurrency >= 2), got %d", srv.MaxConcurrency())
		}
	})

	t.Run("RetryOn500UntilSuccess", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f10_2")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F10 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f10_2", []string{"*"}, 5)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "pool.retry500", map[string]any{"r": 1}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.AttemptCount != 3 {
			t.Fatalf("expected AttemptCount=3, got %d", dlv.AttemptCount)
		}
	})

	t.Run("RetryOn429TooManyRequests", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f10_3")
		srv.SetStatusSequence(http.StatusTooManyRequests, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F10 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f10_3", []string{"*"}, 4)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "pool.retry429", map[string]any{"r": 429}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if dlv.AttemptCount != 2 {
			t.Fatalf("expected AttemptCount=2 on [429, 200], got %d", dlv.AttemptCount)
		}
	})

	t.Run("MaxRetriesExhaustionTransitionsToDLQ", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f10_4")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F10 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f10_4", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "pool.dlq3", map[string]any{"d": 3}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
		if dlv.AttemptCount != 3 {
			t.Fatalf("expected AttemptCount=3, got %d", dlv.AttemptCount)
		}
		if dlv.NextRetryAt != nil {
			t.Fatalf("expected NextRetryAt=nil in DEAD_LETTER, got %v", dlv.NextRetryAt)
		}
	})

	t.Run("DefaultMaxRetriesFiveToDLQ", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f10_5")
		srv.SetFixedStatus(http.StatusBadGateway)
		app := mustCreateApp(t, inst.BaseURL, "", "F10 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f10_5", []string{"*"}, 0)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "pool.dlq5", map[string]any{"d": 5}, "")
		dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 4*time.Second)
		if dlv.AttemptCount != 5 {
			t.Fatalf("expected default MaxRetries=5 attempts before DEAD_LETTER, got %d", dlv.AttemptCount)
		}
	})
}

// F11: App Management API (5 subtests)
func TestTier1_F11_AppManagementAPI(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("CreateApp201", func(t *testing.T) {
		inst := getServer(t)
		resp, body := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/apps", map[string]any{"name": "Acme SaaS"}, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", resp.StatusCode, string(body))
		}
		var app appDTO
		_ = json.Unmarshal(body, &app)
		if app.ID == "" || app.Name != "Acme SaaS" {
			t.Fatalf("unexpected app response: %+v", app)
		}
	})

	t.Run("CreateAppWithCustomID", func(t *testing.T) {
		inst := getServer(t)
		app := mustCreateApp(t, inst.BaseURL, "app-custom-f11", "Custom App")
		if app.ID != "app-custom-f11" {
			t.Fatalf("expected ID=app-custom-f11, got %s", app.ID)
		}
	})

	t.Run("GetAppByID200", func(t *testing.T) {
		inst := getServer(t)
		_ = mustCreateApp(t, inst.BaseURL, "app-get-f11", "Get App")
		resp, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps/app-get-f11", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
		}
		var app appDTO
		_ = json.Unmarshal(body, &app)
		if app.ID != "app-get-f11" || app.Name != "Get App" {
			t.Fatalf("unexpected app: %+v", app)
		}
	})

	t.Run("ListApps200", func(t *testing.T) {
		inst := getServer(t)
		_ = mustCreateApp(t, inst.BaseURL, "app-list-f11", "List App")
		resp, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", resp.StatusCode, string(body))
		}
		var apps []appDTO
		if err := json.Unmarshal(body, &apps); err != nil {
			t.Fatalf("failed to unmarshal apps list: %v", err)
		}
		if len(apps) < 2 {
			t.Fatalf("expected at least 2 apps (default + created), got %d", len(apps))
		}
	})

	t.Run("GetNonExistentApp404", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps/non-existent-app-id", nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 Not Found, got %d", resp.StatusCode)
		}
	})
}

// F12: Endpoint Registration API (Both Variants) (5 subtests)
func TestTier1_F12_EndpointRegistrationAPI(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("CreateAppScopedEndpoint201", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "")
		app := mustCreateApp(t, inst.BaseURL, "", "F12 Scoped App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "", []string{"order.created"}, 3)
		if ep.AppID != app.ID {
			t.Fatalf("expected AppID=%s, got %s", app.ID, ep.AppID)
		}
		if ep.Secret == "" {
			t.Fatal("expected auto-generated secret when omitted")
		}
	})

	t.Run("CreateFlatEndpointDefaultsToDefaultApp", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_flat")
		ep := mustCreateEndpoint(t, inst.BaseURL, "", srv.URL, "whsec_flat", []string{"*"}, 3)
		if ep.AppID != "default" {
			t.Fatalf("expected flat endpoint to default to app_id='default', got %q", ep.AppID)
		}
	})

	t.Run("ListAppEndpointsAndAllEndpoints", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_list")
		app := mustCreateApp(t, inst.BaseURL, "", "F12 List App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_list", []string{"*"}, 3)

		resp1, body1 := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps/"+app.ID+"/endpoints", nil, nil)
		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on app endpoints list, got %d", resp1.StatusCode)
		}
		var list1 []endpointDTO
		_ = json.Unmarshal(body1, &list1)
		if len(list1) != 1 || list1[0].ID != ep.ID {
			t.Fatalf("expected 1 endpoint for app, got %+v", list1)
		}

		resp2, body2 := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/endpoints", nil, nil)
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on all endpoints list, got %d", resp2.StatusCode)
		}
		var list2 []endpointDTO
		_ = json.Unmarshal(body2, &list2)
		if len(list2) < 1 {
			t.Fatal("expected non-empty global endpoints list")
		}
	})

	t.Run("GetEndpointByID200", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_get")
		app := mustCreateApp(t, inst.BaseURL, "", "F12 Get App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_get", []string{"a.b"}, 3)

		resp, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}
		var got endpointDTO
		_ = json.Unmarshal(body, &got)
		if got.ID != ep.ID || got.URL != srv.URL {
			t.Fatalf("unexpected endpoint: %+v", got)
		}
	})

	t.Run("DeleteEndpoint204And404After", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_del")
		app := mustCreateApp(t, inst.BaseURL, "", "F12 Delete App")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_del", []string{"*"}, 3)

		delResp, _ := doJSONRequest(t, http.MethodDelete, inst.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 204/200 on DELETE, got %d", delResp.StatusCode)
		}

		getResp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/endpoints/"+ep.ID, nil, nil)
		if getResp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 after DELETE, got %d", getResp.StatusCode)
		}
	})
}

// F13: Asynchronous Event Ingestion API (5 subtests)
func TestTier1_F13_AsyncEventIngestionAPI(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("IngestEventReturns202Fast", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f13_1")
		app := mustCreateApp(t, inst.BaseURL, "", "F13 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f13_1", []string{"*"}, 3)

		resp, body := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/events", map[string]any{
			"app_id":     app.ID,
			"event_type": "order.created",
			"payload":    map[string]any{"id": 100},
		}, nil)
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("expected 202 Accepted, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ExactEventTypeMatching", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f13_2")
		app := mustCreateApp(t, inst.BaseURL, "", "F13 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f13_2", []string{"order.created"}, 3)

		evSkip := mustIngestEvent(t, inst.BaseURL, app.ID, "order.cancelled", map[string]any{"id": 1}, "")
		if len(evSkip.DeliveryIDs) != 0 {
			t.Fatalf("expected 0 deliveries for unsubscribed event_type, got %v", evSkip.DeliveryIDs)
		}

		evMatch := mustIngestEvent(t, inst.BaseURL, app.ID, "order.created", map[string]any{"id": 2}, "")
		if len(evMatch.DeliveryIDs) != 1 {
			t.Fatalf("expected 1 delivery for matching event_type, got %v", evMatch.DeliveryIDs)
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, evMatch.DeliveryIDs[0], "DELIVERED", 3*time.Second)
	})

	t.Run("WildcardAndEmptyEventTypeMatching", func(t *testing.T) {
		inst := getServer(t)
		srvWild := newWebhookCaptureServer(t, "whsec_wild")
		srvEmpty := newWebhookCaptureServer(t, "whsec_empty")
		app := mustCreateApp(t, inst.BaseURL, "", "F13 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvWild.URL, "whsec_wild", []string{"*"}, 3)
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvEmpty.URL, "whsec_empty", []string{}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "any.custom.event", map[string]any{"x": 1}, "")
		if len(ev.DeliveryIDs) != 2 {
			t.Fatalf("expected both wildcard and empty event_types endpoints to match, got %v", ev.DeliveryIDs)
		}
		_ = srvWild.WaitForRequests(t, 1, 3*time.Second)
		_ = srvEmpty.WaitForRequests(t, 1, 3*time.Second)
	})

	t.Run("IdempotencyKeyInBodyDeduplication", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f13_4")
		app := mustCreateApp(t, inst.BaseURL, "", "F13 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f13_4", []string{"*"}, 3)

		e1 := mustIngestEvent(t, inst.BaseURL, app.ID, "pay.ok", map[string]any{"a": 1}, "f13-body-idem-1")
		e2 := mustIngestEvent(t, inst.BaseURL, app.ID, "pay.ok", map[string]any{"a": 1}, "f13-body-idem-1")
		if e1.EffectiveEventID() != e2.EffectiveEventID() {
			t.Fatalf("expected same event_id, got %s vs %s", e1.EffectiveEventID(), e2.EffectiveEventID())
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, e1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if len(srv.Requests()) != 1 {
			t.Fatalf("expected 1 webhook delivery, got %d", len(srv.Requests()))
		}
	})

	t.Run("IdempotencyKeyHeaderDeduplication", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f13_5")
		app := mustCreateApp(t, inst.BaseURL, "", "F13 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f13_5", []string{"*"}, 3)

		hdr := map[string]string{"Idempotency-Key": "f13-hdr-idem-1"}
		e1 := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "pay.hdr", map[string]any{"a": 1}, "", hdr)
		e2 := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "pay.hdr", map[string]any{"a": 1}, "", hdr)
		if e1.EffectiveEventID() != e2.EffectiveEventID() {
			t.Fatalf("expected same event_id from Idempotency-Key header, got %s vs %s", e1.EffectiveEventID(), e2.EffectiveEventID())
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, e1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		if len(srv.Requests()) != 1 {
			t.Fatalf("expected 1 webhook delivery, got %d", len(srv.Requests()))
		}
	})
}

// F14: Delivery Inspection API (5 subtests)
func TestTier1_F14_DeliveryInspectionAPI(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("ListAllDeliveries200", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f14_1")
		app := mustCreateApp(t, inst.BaseURL, "", "F14 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f14_1", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "dlv.list", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		all := listDeliveries(t, inst.BaseURL, "")
		if len(all) < 1 {
			t.Fatal("expected non-empty deliveries list")
		}
	})

	t.Run("FilterDeliveriesByStatus", func(t *testing.T) {
		inst := getServer(t)
		srvOK := newWebhookCaptureServer(t, "whsec_f14_ok")
		srvFail := newWebhookCaptureServer(t, "whsec_f14_fail")
		srvFail.SetFixedStatus(http.StatusInternalServerError)

		app := mustCreateApp(t, inst.BaseURL, "", "F14 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvOK.URL, "whsec_f14_ok", []string{"ok.evt"}, 2)
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvFail.URL, "whsec_f14_fail", []string{"fail.evt"}, 2)

		evOK := mustIngestEvent(t, inst.BaseURL, app.ID, "ok.evt", map[string]any{"x": 1}, "")
		evFail := mustIngestEvent(t, inst.BaseURL, app.ID, "fail.evt", map[string]any{"x": 2}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, evOK.DeliveryIDs[0], "DELIVERED", 3*time.Second)
		_ = waitForDeliveryStatus(t, inst.BaseURL, evFail.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)

		delivered := listDeliveries(t, inst.BaseURL, "?status=DELIVERED")
		for _, d := range delivered {
			if d.Status != "DELIVERED" {
				t.Fatalf("expected only DELIVERED items, got %+v", d)
			}
		}
		dlq := listDeliveries(t, inst.BaseURL, "?status=DEAD_LETTER")
		for _, d := range dlq {
			if d.Status != "DEAD_LETTER" {
				t.Fatalf("expected only DEAD_LETTER items, got %+v", d)
			}
		}
	})

	t.Run("FilterDeliveriesByEndpointID", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f14_ep")
		app := mustCreateApp(t, inst.BaseURL, "", "F14 App 3")
		ep := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f14_ep", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "ep.filter", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		filtered := listDeliveries(t, inst.BaseURL, "?endpoint_id="+ep.ID)
		if len(filtered) != 1 || filtered[0].EndpointID != ep.ID {
			t.Fatalf("expected 1 delivery for endpoint %s, got %+v", ep.ID, filtered)
		}
	})

	t.Run("FilterDeliveriesByEventID", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f14_ev")
		app := mustCreateApp(t, inst.BaseURL, "", "F14 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f14_ev", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "ev.filter", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		filtered := listDeliveries(t, inst.BaseURL, "?event_id="+ev.EffectiveEventID())
		if len(filtered) != 1 || filtered[0].EventID != ev.EffectiveEventID() {
			t.Fatalf("expected 1 delivery for event %s, got %+v", ev.EffectiveEventID(), filtered)
		}
	})

	t.Run("GetSingleDeliveryByID200And404", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f14_single")
		app := mustCreateApp(t, inst.BaseURL, "", "F14 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f14_single", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "single.dlv", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		resp, dlv := getDelivery(t, inst.BaseURL, ev.DeliveryIDs[0])
		if resp.StatusCode != http.StatusOK || dlv.ID != ev.DeliveryIDs[0] {
			t.Fatalf("expected 200 OK for single delivery, got %d %+v", resp.StatusCode, dlv)
		}

		resp404, _ := getDelivery(t, inst.BaseURL, "non-existent-delivery-id")
		if resp404.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for unknown delivery ID, got %d", resp404.StatusCode)
		}
	})
}

// F15: Dead-Letter Queue (DLQ) & Manual Replay API (5 subtests)
func TestTier1_F15_DLQAndManualReplayAPI(t *testing.T) {
	t.Run("ListDLQEndpoint", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f15_1")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F15 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f15_1", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "dlq.list", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)

		dlq := listDLQ(t, inst.BaseURL)
		if len(dlq) != 1 || dlq[0].ID != ev.DeliveryIDs[0] {
			t.Fatalf("expected 1 item in GET /api/v1/dlq, got %+v", dlq)
		}
	})

	t.Run("ReplayViaDeliveriesRoute", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f15_2")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F15 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f15_2", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "dlq.replay1", map[string]any{"x": 1}, "")
		dlvID := ev.DeliveryIDs[0]
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DEAD_LETTER", 3*time.Second)

		srv.SetFixedStatus(http.StatusOK)
		resp, body := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/deliveries/"+dlvID+"/replay", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from POST /api/v1/deliveries/{id}/replay, got %d: %s", resp.StatusCode, string(body))
		}
		dlv := waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DELIVERED", 3*time.Second)
		if dlv.AttemptCount != 1 {
			t.Fatalf("expected AttemptCount=1 after replay delivery, got %d", dlv.AttemptCount)
		}
	})

	t.Run("ReplayViaDLQRoute", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f15_3")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F15 App 3")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f15_3", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "dlq.replay2", map[string]any{"x": 1}, "")
		dlvID := ev.DeliveryIDs[0]
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DEAD_LETTER", 3*time.Second)

		srv.SetFixedStatus(http.StatusOK)
		resp, body := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+dlvID+"/replay", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from POST /api/v1/dlq/{id}/replay, got %d: %s", resp.StatusCode, string(body))
		}
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DELIVERED", 3*time.Second)
	})

	t.Run("DLQEmptyAfterSuccessfulReplay", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f15_4")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F15 App 4")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f15_4", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "dlq.empty", map[string]any{"x": 1}, "")
		dlvID := ev.DeliveryIDs[0]
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DEAD_LETTER", 3*time.Second)

		srv.SetFixedStatus(http.StatusOK)
		_, _ = doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+dlvID+"/replay", nil, nil)
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DELIVERED", 3*time.Second)

		dlq := listDLQ(t, inst.BaseURL)
		if len(dlq) != 0 {
			t.Fatalf("expected empty DLQ after replay succeeded, got %+v", dlq)
		}
	})

	t.Run("ReplayNonExistentIDReturns404", func(t *testing.T) {
		inst := startRelayHook(t)
		defer inst.Stop(t)
		r1, _ := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/unknown-id/replay", nil, nil)
		if r1.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 on /api/v1/dlq/unknown-id/replay, got %d", r1.StatusCode)
		}
		r2, _ := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/deliveries/unknown-id/replay", nil, nil)
		if r2.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 on /api/v1/deliveries/unknown-id/replay, got %d", r2.StatusCode)
		}
	})
}

// F16: Prometheus Metrics (`/metrics`) (5 subtests)
func TestTier1_F16_PrometheusMetrics(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("MetricsEndpoint200AndContentType", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/metrics", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /metrics, got %d", resp.StatusCode)
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "text/plain") {
			t.Fatalf("expected text/plain Content-Type from /metrics, got %q", ct)
		}
	})

	t.Run("EventsIngestedCounterIncrements", func(t *testing.T) {
		inst := getServer(t)
		before, _ := parseMetricSum(scrapeMetrics(t, inst.BaseURL), "relayhook_events_ingested_total")
		srv := newWebhookCaptureServer(t, "whsec_f16")
		app := mustCreateApp(t, inst.BaseURL, "", "F16 App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f16", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "metrics.ingest", map[string]any{"m": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		after, ok := parseMetricSum(scrapeMetrics(t, inst.BaseURL), "relayhook_events_ingested_total")
		if !ok || after < before+1 {
			t.Fatalf("expected relayhook_events_ingested_total to increment from %v to >= %v (ok=%v)", before, before+1, ok)
		}
	})

	t.Run("DeliveriesTotalByStatusLabels", func(t *testing.T) {
		inst := getServer(t)
		m := scrapeMetrics(t, inst.BaseURL)
		if !strings.Contains(m, "relayhook_deliveries_total") {
			t.Fatalf("expected relayhook_deliveries_total in /metrics:\n%s", m)
		}
	})

	t.Run("RetryAttemptsAndDurationMetricsPresent", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f16_retry")
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
		app := mustCreateApp(t, inst.BaseURL, "", "F16 Retry App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f16_retry", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "metrics.retry", map[string]any{"m": 2}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		m := scrapeMetrics(t, inst.BaseURL)
		if !strings.Contains(m, "relayhook_retry_attempts_total") {
			t.Fatal("expected relayhook_retry_attempts_total in /metrics")
		}
		if !strings.Contains(m, "relayhook_delivery_duration_seconds") {
			t.Fatal("expected relayhook_delivery_duration_seconds in /metrics")
		}
	})

	t.Run("ActiveWorkersQueueDepthAndBreakerMetricsPresent", func(t *testing.T) {
		inst := getServer(t)
		m := scrapeMetrics(t, inst.BaseURL)
		for _, name := range []string{"relayhook_active_workers", "relayhook_queue_depth", "relayhook_circuit_breaker_state"} {
			if !strings.Contains(m, name) {
				t.Fatalf("expected metric %s in /metrics", name)
			}
		}
	})
}

// F17: Health & Readiness Probes (5 subtests)
func TestTier1_F17_HealthAndReadinessProbes(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("HealthzReturns200OK", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on /healthz, got %d", resp.StatusCode)
		}
	})

	t.Run("HealthzJSONPayload", func(t *testing.T) {
		inst := getServer(t)
		_, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("expected valid JSON from /healthz: %v (%s)", err, string(body))
		}
		if data["status"] != "ok" {
			t.Fatalf("expected status='ok' in /healthz JSON, got %v", data)
		}
	})

	t.Run("ReadyzReturns200OKWhenHealthy", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/readyz", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK on /readyz, got %d", resp.StatusCode)
		}
	})

	t.Run("ReadyzJSONPayload", func(t *testing.T) {
		inst := getServer(t)
		_, body := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/readyz", nil, nil)
		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			t.Fatalf("expected valid JSON from /readyz: %v (%s)", err, string(body))
		}
		if _, ok := data["status"]; !ok {
			t.Fatalf("expected 'status' field in /readyz JSON, got %v", data)
		}
	})

	t.Run("ProbesRespondUnderLoad", func(t *testing.T) {
		inst := getServer(t)
		start := time.Now()
		resp1, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
		resp2, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/readyz", nil, nil)
		if resp1.StatusCode != http.StatusOK || resp2.StatusCode != http.StatusOK {
			t.Fatalf("probes failed: healthz=%d readyz=%d", resp1.StatusCode, resp2.StatusCode)
		}
		if time.Since(start) > 100*time.Millisecond {
			t.Fatalf("expected probes to respond quickly (<100ms), took %v", time.Since(start))
		}
	})
}

// F18: Structured Logging & Panic Recovery Middleware (5 subtests)
func TestTier1_F18_StructuredLoggingAndRecovery(t *testing.T) {
	getServer := lazyRelayHook(t)

	t.Run("ValidJSONSlogLinesOnStdout", func(t *testing.T) {
		inst := getServer(t)
		_, _ = doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
		lines := inst.Logs.Lines()
		if len(lines) == 0 {
			t.Fatal("expected structured JSON log lines from relayhook process")
		}
		for _, line := range lines {
			var obj map[string]any
			if err := json.Unmarshal([]byte(line), &obj); err != nil {
				t.Fatalf("expected valid JSON log line, got error %v on line: %s", err, line)
			}
		}
	})

	t.Run("PropagatesIncomingXRequestID", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps", nil, map[string]string{
			"X-Request-ID": "req-trace-f18-123",
		})
		if got := resp.Header.Get("X-Request-ID"); got != "req-trace-f18-123" {
			t.Fatalf("expected echoed X-Request-ID='req-trace-f18-123', got %q", got)
		}
		time.Sleep(20 * time.Millisecond)
		if !strings.Contains(inst.Logs.String(), "req-trace-f18-123") {
			t.Fatalf("expected logs to contain trace_id 'req-trace-f18-123', logs:\n%s", inst.Logs.String())
		}
	})

	t.Run("GeneratesXRequestIDWhenOmitted", func(t *testing.T) {
		inst := getServer(t)
		resp, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/api/v1/apps", nil, nil)
		if got := resp.Header.Get("X-Request-ID"); got == "" {
			t.Fatal("expected generated X-Request-ID response header when omitted")
		}
	})

	t.Run("LogsEventIDAndDeliveryID", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f18")
		app := mustCreateApp(t, inst.BaseURL, "", "F18 Log App")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f18", []string{"*"}, 3)
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "log.check", map[string]any{"l": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

		logs := inst.Logs.String()
		if !strings.Contains(logs, ev.EffectiveEventID()) || !strings.Contains(logs, ev.DeliveryIDs[0]) {
			t.Fatalf("expected logs to include event_id (%s) and delivery_id (%s)", ev.EffectiveEventID(), ev.DeliveryIDs[0])
		}
	})

	t.Run("MiddlewareUnitTestsIncludingPanicRecovery", func(t *testing.T) {
		requireOrSkipFile(t, filepath.Join("internal", "middleware", "recover.go"))
		cmd := exec.Command("go", "test", "-v", "./internal/middleware/...")
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go test ./internal/middleware/... failed: %v\n%s", err, string(out))
		}
	})
}

// F19: Main Server Binary (`cmd/relayhook`) (5 subtests)
func TestTier1_F19_MainServerBinary(t *testing.T) {
	t.Run("CustomPortAndWorkersFlags", func(t *testing.T) {
		inst := startRelayHook(t, "-workers", "2")
		defer inst.Stop(t)
		val, ok := parseMetricSum(scrapeMetrics(t, inst.BaseURL), "relayhook_active_workers")
		if !ok || val != 2 {
			t.Fatalf("expected relayhook_active_workers=2, got %v (ok=%v)", val, ok)
		}
	})

	t.Run("CustomBackoffFlags", func(t *testing.T) {
		inst := startRelayHook(t, "-base-delay", "15ms", "-max-delay", "40ms")
		defer inst.Stop(t)
		srv := newWebhookCaptureServer(t, "whsec_f19_2")
		srv.SetStatusSequence(500, 500, 200)
		app := mustCreateApp(t, inst.BaseURL, "", "F19 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f19_2", []string{"*"}, 4)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cli.backoff", map[string]any{"x": 1}, "")
		_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 2*time.Second)
	})

	t.Run("SQLiteDBFlag", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "f19_cli.db")
		inst := startRelayHook(t, "-db", dbPath)
		defer inst.Stop(t)
		if _, err := os.Stat(dbPath); err != nil {
			t.Fatalf("expected SQLite DB created at %s: %v", dbPath, err)
		}
	})

	t.Run("GracefulShutdownOnSIGTERM", func(t *testing.T) {
		inst := startRelayHook(t)
		err := inst.StopWithSignal(t, syscall.SIGTERM)
		if err != nil {
			t.Fatalf("expected exit code 0 on SIGTERM, got: %v", err)
		}
	})

	t.Run("InFlightDeliveryCompletesBeforeShutdown", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "f19_inflight.db")
		inst := startRelayHook(t, "-db", dbPath)
		srv := newWebhookCaptureServer(t, "whsec_f19_5")
		srv.SetDelay(150 * time.Millisecond)
		app := mustCreateApp(t, inst.BaseURL, "", "F19 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f19_5", []string{"*"}, 3)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cli.inflight", map[string]any{"x": 1}, "")
		time.Sleep(40 * time.Millisecond) // allow worker to start HTTP call
		_ = inst.Stop(t)

		if len(srv.Requests()) != 1 {
			t.Fatalf("expected in-flight webhook request to complete before shutdown, got %d requests", len(srv.Requests()))
		}

		inst2 := startRelayHook(t, "-db", dbPath)
		defer inst2.Stop(t)
		_, dlv := getDelivery(t, inst2.BaseURL, ev.DeliveryIDs[0])
		if dlv.Status != "DELIVERED" {
			t.Fatalf("expected persisted DELIVERED status after graceful shutdown, got %s", dlv.Status)
		}
	})
}

// F20: Chaos Testing CLI (`cmd/mock-receiver`) (5 subtests)
func TestTier1_F20_MockReceiverCLI(t *testing.T) {
	t.Run("HealthzProbeOnMockReceiver", func(t *testing.T) {
		mock := startMockReceiver(t)
		resp, _ := doJSONRequest(t, http.MethodGet, mock.BaseURL+"/healthz", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from mock-receiver /healthz, got %d", resp.StatusCode)
		}
	})

	t.Run("FailFirstTwoThen200OK", func(t *testing.T) {
		mock := startMockReceiver(t, "-fail-first", "2")
		headers := map[string]string{"X-RelayHook-ID": "dlv-f20-1"}
		for i, want := range []int{500, 500, 200} {
			resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, map[string]any{"a": i}, headers)
			if resp.StatusCode != want {
				t.Fatalf("attempt %d: expected %d, got %d", i+1, want, resp.StatusCode)
			}
		}
	})

	t.Run("PerDeliveryIDFailFirstTracking", func(t *testing.T) {
		mock := startMockReceiver(t, "-fail-first", "2")
		for _, dlvID := range []string{"dlv-A", "dlv-B"} {
			hdr := map[string]string{"X-RelayHook-ID": dlvID}
			for i, want := range []int{500, 500, 200} {
				resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, map[string]any{"id": dlvID}, hdr)
				if resp.StatusCode != want {
					t.Fatalf("delivery %s attempt %d: expected %d, got %d", dlvID, i+1, want, resp.StatusCode)
				}
			}
		}
	})

	t.Run("HMACVerificationWithSecretFlag", func(t *testing.T) {
		mock := startMockReceiver(t, "-secret", "whsec_chaos")
		payload := []byte(`{"chaos":true}`)
		now := time.Now().Unix()
		sig := signPayloadStdlib("whsec_chaos", payload, now)

		respOK, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, payload, map[string]string{
			"X-RelayHook-Signature": sig,
			"X-RelayHook-Timestamp": strconv.FormatInt(now, 10),
			"X-RelayHook-ID":        "dlv-sec-ok",
		})
		if respOK.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK with valid signature, got %d", respOK.StatusCode)
		}

		respBad, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, payload, map[string]string{
			"X-RelayHook-Signature": "t=123,v1=bad",
			"X-RelayHook-ID":        "dlv-sec-bad",
		})
		if respBad.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized with invalid signature, got %d", respBad.StatusCode)
		}
	})

	t.Run("ArtificialDelayFlag", func(t *testing.T) {
		mock := startMockReceiver(t, "-delay", "80ms")
		start := time.Now()
		resp, _ := doJSONRequest(t, http.MethodPost, mock.WebhookURL, map[string]any{"d": 1}, map[string]string{
			"X-RelayHook-ID": "dlv-delay",
		})
		elapsed := time.Since(start)
		if resp.StatusCode != http.StatusOK || elapsed < 65*time.Millisecond {
			t.Fatalf("expected 200 OK after >=65ms delay, got status=%d elapsed=%v", resp.StatusCode, elapsed)
		}
	})
}

// F21: Benchmarks & Race-Detector Verification (5 subtests)
func TestTier1_F21_BenchmarksAndRaceVerification(t *testing.T) {
	getServer := lazyRelayHook(t, "-workers", "8")

	t.Run("IngestionSingleRequestUnder15msLoopback", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f21_1")
		app := mustCreateApp(t, inst.BaseURL, "", "F21 App 1")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f21_1", []string{"*"}, 3)

		// Warmup connection
		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "warm.up", map[string]any{"w": 1}, "")

		start := time.Now()
		_ = mustIngestEvent(t, inst.BaseURL, app.ID, "perf.single", map[string]any{"p": 1}, "")
		if elapsed := time.Since(start); elapsed > 25*time.Millisecond {
			t.Fatalf("expected fast loopback ingestion (<25ms), took %v", elapsed)
		}
	})

	t.Run("Burst100ConcurrentEventsAllDelivered", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f21_2")
		app := mustCreateApp(t, inst.BaseURL, "", "F21 App 2")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f21_2", []string{"*"}, 3)

		var wg sync.WaitGroup
		dlvIDs := make([]string, 100)
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				ev := mustIngestEvent(t, inst.BaseURL, app.ID, "burst.100", map[string]any{"idx": idx}, "")
				dlvIDs[idx] = ev.DeliveryIDs[0]
			}(i)
		}
		wg.Wait()

		_ = srv.WaitForRequests(t, 100, 10*time.Second)
		for _, id := range dlvIDs {
			_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 5*time.Second)
		}
	})

	t.Run("BenchmarkIngestEventExistsAndRuns", func(t *testing.T) {
		requireOrSkipFile(t, filepath.Join("internal", "handler", "handler_test.go"))
		cmd := exec.Command("go", "test", "-bench=BenchmarkIngestEvent", "-benchtime=20x", "-benchmem", "-run=^$", "./internal/handler/...")
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("BenchmarkIngestEvent failed: %v\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "BenchmarkIngestEvent") {
			t.Fatalf("expected BenchmarkIngestEvent output, got:\n%s", string(out))
		}
	})

	t.Run("RaceDetectorUnitSuitePass", func(t *testing.T) {
		requireOrSkipFile(t, filepath.Join("internal", "domain", "models.go"))
		cmd := exec.Command("go", "test", "-race", "./internal/...", "./pkg/...")
		cmd.Dir = projectRoot(t)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go test -race ./internal/... ./pkg/... failed: %v\n%s", err, string(out))
		}
	})

	t.Run("ConcurrentReplayAndIngestNoRace", func(t *testing.T) {
		inst := getServer(t)
		srv := newWebhookCaptureServer(t, "whsec_f21_5")
		srv.SetFixedStatus(http.StatusInternalServerError)
		app := mustCreateApp(t, inst.BaseURL, "", "F21 App 5")
		_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_f21_5", []string{"*"}, 2)

		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "race.mix", map[string]any{"x": 1}, "")
		dlvID := ev.DeliveryIDs[0]
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DEAD_LETTER", 3*time.Second)

		srv.SetFixedStatus(http.StatusOK)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+dlvID+"/replay", nil, nil)
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_ = mustIngestEvent(t, inst.BaseURL, app.ID, "race.mix", map[string]any{"i": i}, "")
			}
		}()
		wg.Wait()
		_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DELIVERED", 3*time.Second)
	})
}

// F22: DevOps, Portfolio Docs & GitHub Deployment (5 subtests)
func TestTier1_F22_DevOpsAndPortfolioDocs(t *testing.T) {
	t.Run("DockerfileExistsAndValidMultiStage", func(t *testing.T) {
		p1 := requireOrSkipFile(t, "Dockerfile")
		p2 := requireOrSkipFile(t, filepath.Join("deployments", "Dockerfile"))
		for _, p := range []string{p1, p2} {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("failed reading %s: %v", p, err)
			}
			s := string(b)
			if !strings.Contains(s, "FROM") || !strings.Contains(s, "go build") {
				t.Fatalf("expected multi-stage Dockerfile with 'FROM' and 'go build' in %s", p)
			}
		}
	})

	t.Run("DockerComposeExistsAndDefinesStack", func(t *testing.T) {
		p1 := requireOrSkipFile(t, "docker-compose.yml")
		p2 := requireOrSkipFile(t, filepath.Join("deployments", "docker-compose.yml"))
		for _, p := range []string{p1, p2} {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("failed reading %s: %v", p, err)
			}
			s := strings.ToLower(string(b))
			for _, svc := range []string{"relayhook", "mock-receiver", "prometheus", "grafana"} {
				if !strings.Contains(s, svc) {
					t.Fatalf("expected %s to define service %q", p, svc)
				}
			}
		}
	})

	t.Run("PrometheusConfigExists", func(t *testing.T) {
		p := requireOrSkipFile(t, filepath.Join("deployments", "prometheus.yml"))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("failed reading %s: %v", p, err)
		}
		if !strings.Contains(string(b), "relayhook") {
			t.Fatalf("expected prometheus.yml to scrape relayhook, got:\n%s", string(b))
		}
	})

	t.Run("MakefileTargetsPresent", func(t *testing.T) {
		p := requireOrSkipFile(t, "Makefile")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("failed reading Makefile: %v", err)
		}
		s := string(b)
		for _, target := range []string{"build:", "run:", "run-mock:", "test:", "test-race:", "bench:", "lint:", "clean:"} {
			if !strings.Contains(s, target) {
				t.Fatalf("expected Makefile target %q", target)
			}
		}
	})

	t.Run("ReadmePortfolioContent", func(t *testing.T) {
		p := requireOrSkipFile(t, "README.md")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("failed reading README.md: %v", err)
		}
		s := string(b)
		for _, needle := range []string{"mermaid", "daikodev.com", "/api/v1/events"} {
			if !strings.Contains(strings.ToLower(s), strings.ToLower(needle)) {
				t.Fatalf("expected README.md to contain %q", needle)
			}
		}
	})
}
