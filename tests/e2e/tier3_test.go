package e2e_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// C01: Multi-App Isolation + Event Filtering + Async Ingestion + Delivery Inspection
func TestTier3_C01_MultiAppIsolation_EventFiltering_AsyncIngestion(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	appAlpha := mustCreateApp(t, inst.BaseURL, "app-alpha", "Alpha Tenant")
	appBeta := mustCreateApp(t, inst.BaseURL, "app-beta", "Beta Tenant")

	epAExact := newWebhookCaptureServer(t, "whsec_a_exact")
	epAWild := newWebhookCaptureServer(t, "whsec_a_wild")
	epAOther := newWebhookCaptureServer(t, "whsec_a_other")
	epBWild := newWebhookCaptureServer(t, "whsec_b_wild")
	epDefault := newWebhookCaptureServer(t, "whsec_def")

	_ = mustCreateEndpoint(t, inst.BaseURL, appAlpha.ID, epAExact.URL, "whsec_a_exact", []string{"order.created"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appAlpha.ID, epAWild.URL, "whsec_a_wild", []string{"*"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appAlpha.ID, epAOther.URL, "whsec_a_other", []string{"order.cancelled"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appBeta.ID, epBWild.URL, "whsec_b_wild", []string{"*"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, "", epDefault.URL, "whsec_def", []string{"*"}, 3)

	ev := mustIngestEvent(t, inst.BaseURL, appAlpha.ID, "order.created", map[string]any{"order_id": "ord_c01"}, "")
	if len(ev.DeliveryIDs) != 2 {
		t.Fatalf("expected 2 deliveries queued for app-alpha order.created, got %v", ev.DeliveryIDs)
	}

	for _, id := range ev.DeliveryIDs {
		_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
	}

	if len(epAExact.Requests()) != 1 || len(epAWild.Requests()) != 1 {
		t.Fatalf("expected 1 call each on epAExact (%d) and epAWild (%d)", len(epAExact.Requests()), len(epAWild.Requests()))
	}
	if len(epAOther.Requests()) != 0 || len(epBWild.Requests()) != 0 || len(epDefault.Requests()) != 0 {
		t.Fatalf("expected 0 calls on non-matching/other-tenant endpoints, got other=%d beta=%d default=%d",
			len(epAOther.Requests()), len(epBWild.Requests()), len(epDefault.Requests()))
	}

	dlvs := listDeliveries(t, inst.BaseURL, "?event_id="+ev.EffectiveEventID())
	if len(dlvs) != 2 {
		t.Fatalf("expected 2 deliveries in inspection query, got %d", len(dlvs))
	}
}

// C02: Idempotency (Body & Header) + Multi-Endpoint Fanout + Cross-App Scoping
func TestTier3_C02_Idempotency_MultiEndpointFanout_DeliveryInspection(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	appMain := mustCreateApp(t, inst.BaseURL, "app-c02-main", "Main App")
	appSecond := mustCreateApp(t, inst.BaseURL, "app-c02-second", "Second App")

	srv1 := newWebhookCaptureServer(t, "whsec_1")
	srv2 := newWebhookCaptureServer(t, "whsec_2")
	srv3 := newWebhookCaptureServer(t, "whsec_3")
	srvSecond := newWebhookCaptureServer(t, "whsec_sec")

	_ = mustCreateEndpoint(t, inst.BaseURL, appMain.ID, srv1.URL, "whsec_1", []string{"invoice.paid"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appMain.ID, srv2.URL, "whsec_2", []string{"invoice.paid"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appMain.ID, srv3.URL, "whsec_3", []string{"invoice.paid"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, appSecond.ID, srvSecond.URL, "whsec_sec", []string{"invoice.paid"}, 3)

	// 5 concurrent requests with body idempotency_key
	bodyEvIDs := make([]string, 5)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ev := mustIngestEvent(t, inst.BaseURL, appMain.ID, "invoice.paid", map[string]any{"inv": 1}, "idem-body-001")
			bodyEvIDs[idx] = ev.EffectiveEventID()
		}(i)
	}
	wg.Wait()
	for i := 1; i < 5; i++ {
		if bodyEvIDs[i] != bodyEvIDs[0] {
			t.Fatalf("expected identical event_id for body idempotency key: %s vs %s", bodyEvIDs[0], bodyEvIDs[i])
		}
	}

	// 5 concurrent requests with header Idempotency-Key
	hdrEvIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ev := mustIngestEventWithHeaders(t, inst.BaseURL, appMain.ID, "invoice.paid", map[string]any{"inv": 2}, "", map[string]string{
				"Idempotency-Key": "idem-hdr-002",
			})
			hdrEvIDs[idx] = ev.EffectiveEventID()
		}(i)
	}
	wg.Wait()
	for i := 1; i < 5; i++ {
		if hdrEvIDs[i] != hdrEvIDs[0] {
			t.Fatalf("expected identical event_id for header idempotency key: %s vs %s", hdrEvIDs[0], hdrEvIDs[i])
		}
	}

	for _, s := range []*webhookCaptureServer{srv1, srv2, srv3} {
		_ = s.WaitForRequests(t, 2, 3*time.Second)
	}
	time.Sleep(80 * time.Millisecond)
	for idx, s := range []*webhookCaptureServer{srv1, srv2, srv3} {
		if len(s.Requests()) != 2 {
			t.Fatalf("endpoint %d: expected exactly 2 requests total, got %d", idx+1, len(s.Requests()))
		}
	}

	// Same idempotency_key on a different app creates a distinct event
	evSecond := mustIngestEvent(t, inst.BaseURL, appSecond.ID, "invoice.paid", map[string]any{"inv": 1}, "idem-body-001")
	if evSecond.EffectiveEventID() == bodyEvIDs[0] {
		t.Fatal("expected idempotency_key to be scoped per app")
	}
	_ = srvSecond.WaitForRequests(t, 1, 3*time.Second)
}

// C03: Transient 500s + Exponential Backoff + Eventual DELIVERED + HMAC Verification on Every Attempt
func TestTier3_C03_Transient500_ExponentialBackoff_EventualDelivered_HMAC(t *testing.T) {
	inst := startRelayHook(t, "-base-delay", "30ms", "-max-delay", "200ms")
	defer inst.Stop(t)

	secret := "whsec_c3_secret"
	srv := newWebhookCaptureServer(t, secret)
	srv.SetStatusSequence(http.StatusInternalServerError, http.StatusInternalServerError, http.StatusOK)

	app := mustCreateApp(t, inst.BaseURL, "", "C03 App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 5)

	ev := mustIngestEvent(t, inst.BaseURL, app.ID, "payment.retry", map[string]any{"amount": 750}, "")
	dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 4*time.Second)

	if dlv.AttemptCount != 3 || dlv.StatusCode != http.StatusOK || dlv.LastError != "" || dlv.NextRetryAt != nil {
		t.Fatalf("unexpected final delivery state: %+v", dlv)
	}

	reqs := srv.Requests()
	if len(reqs) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(reqs))
	}
	for i, r := range reqs {
		if !r.HMACValid {
			t.Fatalf("attempt %d: invalid HMAC signature: %s", i+1, r.HMACError)
		}
		if r.DeliveryID != dlv.ID || r.EventType != "payment.retry" {
			t.Fatalf("attempt %d: header mismatch: %+v", i+1, r)
		}
	}
}

// C04: Persistent 502 + MaxRetries Exhaustion + Automatic DLQ Transition
func TestTier3_C04_Persistent500_MaxRetriesExhaustion_DLQTransition(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	srv := newWebhookCaptureServer(t, "whsec_c4")
	srv.SetFixedStatus(http.StatusBadGateway)

	app := mustCreateApp(t, inst.BaseURL, "", "C04 App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_c4", []string{"*"}, 3)

	ev := mustIngestEvent(t, inst.BaseURL, app.ID, "order.failed", map[string]any{"id": 404}, "")
	dlv := waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DEAD_LETTER", 4*time.Second)

	if dlv.AttemptCount != 3 || dlv.StatusCode != http.StatusBadGateway || dlv.NextRetryAt != nil || dlv.LastError == "" {
		t.Fatalf("unexpected DEAD_LETTER state: %+v", dlv)
	}

	time.Sleep(80 * time.Millisecond)
	if len(srv.Requests()) != 3 {
		t.Fatalf("expected no further retries after max_retries=3, got %d requests", len(srv.Requests()))
	}

	dlq := listDLQ(t, inst.BaseURL)
	if len(dlq) != 1 || dlq[0].ID != dlv.ID {
		t.Fatalf("expected delivery in GET /api/v1/dlq, got %+v", dlq)
	}
}

// C05: DLQ Manual Replay via Both Routes + Downstream Recovery
func TestTier3_C05_DLQManualReplay_BothRoutes_DownstreamRecovery(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	srv := newWebhookCaptureServer(t, "whsec_c5")
	srv.SetFixedStatus(http.StatusInternalServerError)

	app := mustCreateApp(t, inst.BaseURL, "", "C05 App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_c5", []string{"*"}, 2)

	ev1 := mustIngestEvent(t, inst.BaseURL, app.ID, "replay.one", map[string]any{"n": 1}, "")
	ev2 := mustIngestEvent(t, inst.BaseURL, app.ID, "replay.two", map[string]any{"n": 2}, "")
	d1 := ev1.DeliveryIDs[0]
	d2 := ev2.DeliveryIDs[0]

	_ = waitForDeliveryStatus(t, inst.BaseURL, d1, "DEAD_LETTER", 3*time.Second)
	_ = waitForDeliveryStatus(t, inst.BaseURL, d2, "DEAD_LETTER", 3*time.Second)

	if len(listDLQ(t, inst.BaseURL)) != 2 {
		t.Fatalf("expected 2 items in DLQ before replay")
	}

	srv.SetFixedStatus(http.StatusOK)

	r1, _ := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/deliveries/"+d1+"/replay", nil, nil)
	r2, _ := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+d2+"/replay", nil, nil)
	if r1.StatusCode != http.StatusOK || r2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on both replay routes, got %d and %d", r1.StatusCode, r2.StatusCode)
	}

	_ = waitForDeliveryStatus(t, inst.BaseURL, d1, "DELIVERED", 3*time.Second)
	_ = waitForDeliveryStatus(t, inst.BaseURL, d2, "DELIVERED", 3*time.Second)

	if len(listDLQ(t, inst.BaseURL)) != 0 {
		t.Fatal("expected DLQ empty after both replays succeeded")
	}
}

// C06: Circuit Breaker Lifecycle + Fast-Fail + Prometheus Gauge + Recovery
func TestTier3_C06_CircuitBreakerLifecycle_FastFail_PrometheusGauge(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	srv := newWebhookCaptureServer(t, "whsec_c6")
	srv.SetFixedStatus(http.StatusInternalServerError)

	app := mustCreateApp(t, inst.BaseURL, "", "C06 App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_c6", []string{"*"}, 3)

	var lastID string
	for i := 0; i < 3; i++ {
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "cb.event", map[string]any{"i": i}, "")
		lastID = ev.DeliveryIDs[0]
		_ = waitForDeliveryStatus(t, inst.BaseURL, lastID, "DEAD_LETTER", 3*time.Second)
	}

	m := scrapeMetrics(t, inst.BaseURL)
	if !strings.Contains(m, "relayhook_circuit_breaker_state") {
		t.Fatal("expected relayhook_circuit_breaker_state in /metrics")
	}

	// Recover via replay
	srv.SetFixedStatus(http.StatusOK)
	_, _ = doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+lastID+"/replay", nil, nil)
	_ = waitForDeliveryStatus(t, inst.BaseURL, lastID, "DELIVERED", 3*time.Second)
}

// C07: SQLite Persistence + Process Restart + DLQ Replay + Idempotency Preservation
func TestTier3_C07_SQLitePersistence_ProcessRestart_StatePreservation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "c07.db")
	inst1 := startRelayHook(t, "-db", dbPath)

	srvOK := newWebhookCaptureServer(t, "whsec_c7_ok")
	srvFail := newWebhookCaptureServer(t, "whsec_c7_fail")
	srvFail.SetFixedStatus(http.StatusInternalServerError)

	app := mustCreateApp(t, inst1.BaseURL, "app-c07", "C07 SQLite App")
	_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srvOK.URL, "whsec_c7_ok", []string{"ev.ok"}, 2)
	_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srvFail.URL, "whsec_c7_fail", []string{"ev.fail"}, 2)

	ev1 := mustIngestEvent(t, inst1.BaseURL, app.ID, "ev.ok", map[string]any{"v": 1}, "c07-idem-1")
	ev2 := mustIngestEvent(t, inst1.BaseURL, app.ID, "ev.fail", map[string]any{"v": 2}, "c07-idem-2")

	_ = waitForDeliveryStatus(t, inst1.BaseURL, ev1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
	_ = waitForDeliveryStatus(t, inst1.BaseURL, ev2.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)
	_ = inst1.Stop(t)

	// Restart instance #2 with same SQLite DB
	inst2 := startRelayHook(t, "-db", dbPath)
	defer inst2.Stop(t)

	_, d1 := getDelivery(t, inst2.BaseURL, ev1.DeliveryIDs[0])
	_, d2 := getDelivery(t, inst2.BaseURL, ev2.DeliveryIDs[0])
	if d1.Status != "DELIVERED" || d2.Status != "DEAD_LETTER" {
		t.Fatalf("expected persisted statuses DELIVERED and DEAD_LETTER, got %s and %s", d1.Status, d2.Status)
	}

	// Replay dead-lettered delivery #2 on Instance #2 after downstream recovers
	srvFail.SetFixedStatus(http.StatusOK)
	resp, _ := doJSONRequest(t, http.MethodPost, inst2.BaseURL+"/api/v1/dlq/"+ev2.DeliveryIDs[0]+"/replay", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK replaying persisted DLQ item, got %d", resp.StatusCode)
	}
	_ = waitForDeliveryStatus(t, inst2.BaseURL, ev2.DeliveryIDs[0], "DELIVERED", 3*time.Second)

	// Re-sending idempotency key from Instance #1 is still deduplicated on Instance #2
	ev1Dup := mustIngestEvent(t, inst2.BaseURL, app.ID, "ev.ok", map[string]any{"v": 1}, "c07-idem-1")
	if ev1Dup.EffectiveEventID() != ev1.EffectiveEventID() {
		t.Fatalf("expected idempotency deduplication across restart, got %s vs %s", ev1.EffectiveEventID(), ev1Dup.EffectiveEventID())
	}
}

// C08: Request Tracing (X-Request-ID) + Structured JSON Logs + Health/Ready Probes
func TestTier3_C08_RequestTracing_StructuredJSONLogs_HealthReadyProbes(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	srv := newWebhookCaptureServer(t, "whsec_c8")
	traceHdr := map[string]string{"X-Request-ID": "trace-custom-c08-999"}

	rApp, appBody := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/apps", map[string]any{"name": "C08 App"}, traceHdr)
	if rApp.Header.Get("X-Request-ID") != "trace-custom-c08-999" {
		t.Fatalf("expected echoed X-Request-ID, got %q", rApp.Header.Get("X-Request-ID"))
	}
	var app appDTO
	_ = json.Unmarshal(appBody, &app)

	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, "whsec_c8", []string{"*"}, 3)
	ev := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "trace.evt", map[string]any{"t": 1}, "", traceHdr)
	_ = waitForDeliveryStatus(t, inst.BaseURL, ev.DeliveryIDs[0], "DELIVERED", 3*time.Second)

	rHealth, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
	rReady, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/readyz", nil, nil)
	if rHealth.StatusCode != http.StatusOK || rReady.StatusCode != http.StatusOK {
		t.Fatalf("probes failed: health=%d ready=%d", rHealth.StatusCode, rReady.StatusCode)
	}
	if rHealth.Header.Get("X-Request-ID") == "" {
		t.Fatal("expected generated X-Request-ID on /healthz")
	}

	logs := inst.Logs.String()
	if !strings.Contains(logs, "trace-custom-c08-999") {
		t.Fatal("expected trace-custom-c08-999 in structured JSON logs")
	}
	for _, line := range inst.Logs.Lines() {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("invalid JSON log line: %v (%s)", err, line)
		}
	}
}

// C09: High Concurrency Burst + Oversized 128KB Response Body + Prometheus Metrics
func TestTier3_C09_HighConcurrencyBurst_WorkerPool_PrometheusMetrics(t *testing.T) {
	inst := startRelayHook(t, "-workers", "8")
	defer inst.Stop(t)

	srvNormal := newWebhookCaptureServer(t, "whsec_c9_norm")
	srvBig := newWebhookCaptureServer(t, "whsec_c9_big")
	srvBig.SetOversizedBody(128 * 1024)

	app := mustCreateApp(t, inst.BaseURL, "", "C09 Burst App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvNormal.URL, "whsec_c9_norm", []string{"*"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvBig.URL, "whsec_c9_big", []string{"*"}, 3)

	const eventsCount = 60
	var wg sync.WaitGroup
	allDeliveries := make([][]string, eventsCount)
	for i := 0; i < eventsCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ev := mustIngestEvent(t, inst.BaseURL, app.ID, "burst.c09", map[string]any{"idx": idx}, "")
			allDeliveries[idx] = ev.DeliveryIDs
		}(i)
	}
	wg.Wait()

	for i := 0; i < eventsCount; i++ {
		for _, id := range allDeliveries[i] {
			_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 8*time.Second)
		}
	}

	m := scrapeMetrics(t, inst.BaseURL)
	ingested, ok1 := parseMetricSum(m, "relayhook_events_ingested_total")
	delivered, ok2 := parseMetricSum(m, "relayhook_deliveries_total")
	if !ok1 || ingested < eventsCount || !ok2 || delivered < eventsCount*2 {
		t.Fatalf("expected metrics ingested>=%d (got %v) and deliveries>=%d (got %v)", eventsCount, ingested, eventsCount*2, delivered)
	}
}

// C10: Endpoint Deletion + Subsequent Ingestion + Historical Deliveries Preservation
func TestTier3_C10_EndpointDeletion_SubsequentIngestion_HistoricalDeliveries(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	srv1 := newWebhookCaptureServer(t, "whsec_c10_1")
	srv2 := newWebhookCaptureServer(t, "whsec_c10_2")

	app := mustCreateApp(t, inst.BaseURL, "app-c10", "C10 App")
	ep1 := mustCreateEndpoint(t, inst.BaseURL, app.ID, srv1.URL, "whsec_c10_1", []string{"*"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv2.URL, "whsec_c10_2", []string{"*"}, 3)

	evBefore := mustIngestEvent(t, inst.BaseURL, app.ID, "before.delete", map[string]any{"step": 1}, "")
	if len(evBefore.DeliveryIDs) != 2 {
		t.Fatalf("expected 2 deliveries before delete, got %v", evBefore.DeliveryIDs)
	}
	for _, id := range evBefore.DeliveryIDs {
		_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
	}

	delResp, _ := doJSONRequest(t, http.MethodDelete, inst.BaseURL+"/api/v1/endpoints/"+ep1.ID, nil, nil)
	if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 204/200 deleting ep1, got %d", delResp.StatusCode)
	}

	evAfter := mustIngestEvent(t, inst.BaseURL, app.ID, "after.delete", map[string]any{"step": 2}, "")
	if len(evAfter.DeliveryIDs) != 1 {
		t.Fatalf("expected 1 delivery after deleting ep1, got %v", evAfter.DeliveryIDs)
	}
	_ = waitForDeliveryStatus(t, inst.BaseURL, evAfter.DeliveryIDs[0], "DELIVERED", 3*time.Second)

	if len(srv1.Requests()) != 1 {
		t.Fatalf("expected deleted ep1 to receive 0 new calls (total 1), got %d", len(srv1.Requests()))
	}

	hist := listDeliveries(t, inst.BaseURL, "?endpoint_id="+ep1.ID)
	if len(hist) != 1 || hist[0].Status != "DELIVERED" {
		t.Fatalf("expected historical delivery for deleted ep1 preserved, got %+v", hist)
	}
}

// C11: Mock-Receiver Subprocess CLI (-fail-first 2 -secret) + RelayHook Subprocess Integration
func TestTier3_C11_MockReceiverCLI_Subprocess_FailFirstAndSecretIntegration(t *testing.T) {
	mock := startMockReceiver(t, "-fail-first", "2", "-secret", "whsec_cli_e2e")
	inst := startRelayHook(t, "-base-delay", "25ms", "-max-delay", "80ms")
	defer inst.Stop(t)

	appValid := mustCreateApp(t, inst.BaseURL, "", "C11 Valid Secret App")
	appWrong := mustCreateApp(t, inst.BaseURL, "", "C11 Wrong Secret App")

	_ = mustCreateEndpoint(t, inst.BaseURL, appValid.ID, mock.WebhookURL, "whsec_cli_e2e", []string{"*"}, 5)
	_ = mustCreateEndpoint(t, inst.BaseURL, appWrong.ID, mock.WebhookURL, "whsec_wrong", []string{"*"}, 2)

	evValid := mustIngestEvent(t, inst.BaseURL, appValid.ID, "cli.valid", map[string]any{"ok": true}, "")
	dlvValid := waitForDeliveryStatus(t, inst.BaseURL, evValid.DeliveryIDs[0], "DELIVERED", 4*time.Second)
	if dlvValid.AttemptCount != 3 || dlvValid.StatusCode != http.StatusOK {
		t.Fatalf("expected 3 attempts (2x 500 + 1x 200) on valid secret endpoint, got %+v", dlvValid)
	}

	evWrong := mustIngestEvent(t, inst.BaseURL, appWrong.ID, "cli.wrong", map[string]any{"ok": false}, "")
	dlvWrong := waitForDeliveryStatus(t, inst.BaseURL, evWrong.DeliveryIDs[0], "DEAD_LETTER", 4*time.Second)
	if dlvWrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 status_code from mock-receiver on wrong secret, got %d", dlvWrong.StatusCode)
	}
}

// C12: SDK Header Contract Across Retries and Manual Replays
func TestTier3_C12_SDKHeaderContract_AcrossRetriesAndManualReplays(t *testing.T) {
	inst := startRelayHook(t, "-base-delay", "30ms", "-max-delay", "80ms")
	defer inst.Stop(t)

	secret := "whsec_c12_contract"
	srv := newWebhookCaptureServer(t, secret)
	srv.SetFixedStatus(http.StatusInternalServerError)

	app := mustCreateApp(t, inst.BaseURL, "", "C12 App")
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srv.URL, secret, []string{"*"}, 2)

	ev := mustIngestEvent(t, inst.BaseURL, app.ID, "contract.check", map[string]any{"v": 42}, "")
	dlvID := ev.DeliveryIDs[0]
	_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DEAD_LETTER", 3*time.Second)

	// Switch to [500, 200] and replay
	srv.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
	_, _ = doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+dlvID+"/replay", nil, nil)
	_ = waitForDeliveryStatus(t, inst.BaseURL, dlvID, "DELIVERED", 3*time.Second)

	reqs := srv.Requests()
	if len(reqs) != 4 {
		t.Fatalf("expected 4 total attempts (2 initial + 2 on replay), got %d", len(reqs))
	}
	for i, r := range reqs {
		if !r.HMACValid {
			t.Fatalf("attempt %d: invalid HMAC: %s", i+1, r.HMACError)
		}
		if r.DeliveryID != dlvID {
			t.Fatalf("attempt %d: X-RelayHook-ID changed from %s to %s", i+1, dlvID, r.DeliveryID)
		}
		if r.EventType != "contract.check" {
			t.Fatalf("attempt %d: unexpected X-RelayHook-Event %s", i+1, r.EventType)
		}
	}
}
