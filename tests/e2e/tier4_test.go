package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// S01: Stripe Billing Webhook Fanout (Healthy, Flaky mock-receiver, Outage -> DLQ, Unsubscribed) & Operator Replay
func TestTier4_S01_StripeBillingWebhookFanoutAndDLQRecovery(t *testing.T) {
	mockCRM := startMockReceiver(t, "-fail-first", "2", "-secret", "whsec_crm_s01")
	inst := startRelayHook(t, "-workers", "6", "-base-delay", "20ms", "-max-delay", "80ms")
	defer inst.Stop(t)

	app := mustCreateApp(t, inst.BaseURL, "stripe-billing-prod", "Stripe Billing Production")

	srvAccounting := newWebhookCaptureServer(t, "whsec_acc_s01")
	srvAnalytics := newWebhookCaptureServer(t, "whsec_ana_s01")
	srvAnalytics.SetFixedStatus(http.StatusServiceUnavailable)
	srvChurn := newWebhookCaptureServer(t, "whsec_churn_s01")

	epAcc := mustCreateEndpoint(t, inst.BaseURL, app.ID, srvAccounting.URL, "whsec_acc_s01", []string{"invoice.payment_succeeded"}, 3)
	epCRM := mustCreateEndpoint(t, inst.BaseURL, app.ID, mockCRM.WebhookURL, "whsec_crm_s01", []string{"*"}, 5)
	epAna := mustCreateEndpoint(t, inst.BaseURL, app.ID, srvAnalytics.URL, "whsec_ana_s01", []string{"invoice.payment_succeeded"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvChurn.URL, "whsec_churn_s01", []string{"customer.subscription.deleted"}, 3)

	invoicePayload := map[string]any{
		"invoice_id": "inv_01HXYZ",
		"amount_usd": 49900,
		"plan":       "enterprise_annual",
	}
	hdr := map[string]string{"Idempotency-Key": "inv_01HXYZ"}

	ev1 := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "invoice.payment_succeeded", invoicePayload, "", hdr)
	ev2 := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "invoice.payment_succeeded", invoicePayload, "", hdr)
	if ev1.EffectiveEventID() != ev2.EffectiveEventID() {
		t.Fatalf("expected upstream producer retry deduplication: %s vs %s", ev1.EffectiveEventID(), ev2.EffectiveEventID())
	}
	if len(ev1.DeliveryIDs) != 3 {
		t.Fatalf("expected 3 deliveries (Accounting, CRM, Analytics; Churn skipped), got %v", ev1.DeliveryIDs)
	}

	var dlvAccID, dlvCRMID, dlvAnaID string
	for _, id := range ev1.DeliveryIDs {
		_, d := getDelivery(t, inst.BaseURL, id)
		switch d.EndpointID {
		case epAcc.ID:
			dlvAccID = id
		case epCRM.ID:
			dlvCRMID = id
		case epAna.ID:
			dlvAnaID = id
		}
	}

	dAcc := waitForDeliveryStatus(t, inst.BaseURL, dlvAccID, "DELIVERED", 4*time.Second)
	dCRM := waitForDeliveryStatus(t, inst.BaseURL, dlvCRMID, "DELIVERED", 4*time.Second)
	dAna := waitForDeliveryStatus(t, inst.BaseURL, dlvAnaID, "DEAD_LETTER", 4*time.Second)

	if dAcc.AttemptCount != 1 {
		t.Fatalf("expected Accounting attempt_count=1, got %d", dAcc.AttemptCount)
	}
	if dCRM.AttemptCount != 3 {
		t.Fatalf("expected CRM attempt_count=3 (after -fail-first 2), got %d", dCRM.AttemptCount)
	}
	if dAna.AttemptCount != 3 || dAna.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected Analytics DEAD_LETTER with 3 attempts and 503, got %+v", dAna)
	}
	if len(srvChurn.Requests()) != 0 {
		t.Fatalf("expected Churn service to receive 0 calls, got %d", len(srvChurn.Requests()))
	}

	// Operator inspects DLQ, restores Analytics Warehouse, and replays
	dlq := listDLQ(t, inst.BaseURL)
	if len(dlq) != 1 || dlq[0].ID != dlvAnaID {
		t.Fatalf("expected 1 DLQ item (%s), got %+v", dlvAnaID, dlq)
	}

	srvAnalytics.SetFixedStatus(http.StatusOK)
	replayResp, _ := doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+dlvAnaID+"/replay", nil, nil)
	if replayResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on DLQ replay, got %d", replayResp.StatusCode)
	}
	_ = waitForDeliveryStatus(t, inst.BaseURL, dlvAnaID, "DELIVERED", 4*time.Second)

	if len(listDLQ(t, inst.BaseURL)) != 0 {
		t.Fatal("expected DLQ empty after Analytics recovery and replay")
	}
}

// S02: Multi-Tenant SaaS Onboarding, Zero-Downtime Secret/Endpoint Rotation & Decommissioning
func TestTier4_S02_MultiTenantSaaSOnboarding_SecretRotationAndDecommissioning(t *testing.T) {
	inst := startRelayHook(t)
	defer inst.Stop(t)

	acme := mustCreateApp(t, inst.BaseURL, "tenant-acme", "Acme Corp")
	globex := mustCreateApp(t, inst.BaseURL, "tenant-globex", "Globex Inc")

	srvAcmeV1 := newWebhookCaptureServer(t, "whsec_acme_v1")
	srvAcmeV2 := newWebhookCaptureServer(t, "whsec_acme_v2")
	srvGlobex := newWebhookCaptureServer(t, "whsec_globex_1")

	epAcmeV1 := mustCreateEndpoint(t, inst.BaseURL, acme.ID, srvAcmeV1.URL, "whsec_acme_v1", []string{"user.signup"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, globex.ID, srvGlobex.URL, "whsec_globex_1", []string{"user.signup"}, 3)

	// Phase 1: Initial tenant traffic isolation
	evA1 := mustIngestEvent(t, inst.BaseURL, acme.ID, "user.signup", map[string]any{"tenant": "acme", "phase": 1}, "")
	evG1 := mustIngestEvent(t, inst.BaseURL, globex.ID, "user.signup", map[string]any{"tenant": "globex", "phase": 1}, "")
	_ = waitForDeliveryStatus(t, inst.BaseURL, evA1.DeliveryIDs[0], "DELIVERED", 3*time.Second)
	_ = waitForDeliveryStatus(t, inst.BaseURL, evG1.DeliveryIDs[0], "DELIVERED", 3*time.Second)

	if !srvAcmeV1.Requests()[0].HMACValid || !srvGlobex.Requests()[0].HMACValid {
		t.Fatal("expected valid tenant-isolated HMAC signatures")
	}

	// Phase 2: Zero-downtime rotation window (both v1 and v2 active for Acme)
	_ = mustCreateEndpoint(t, inst.BaseURL, acme.ID, srvAcmeV2.URL, "whsec_acme_v2", []string{"user.signup"}, 3)
	evA2 := mustIngestEvent(t, inst.BaseURL, acme.ID, "user.signup", map[string]any{"tenant": "acme", "phase": 2}, "")
	if len(evA2.DeliveryIDs) != 2 {
		t.Fatalf("expected dual delivery during rotation window, got %v", evA2.DeliveryIDs)
	}
	for _, id := range evA2.DeliveryIDs {
		_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
	}

	// Phase 3: Decommission v1 endpoint
	delResp, _ := doJSONRequest(t, http.MethodDelete, inst.BaseURL+"/api/v1/endpoints/"+epAcmeV1.ID, nil, nil)
	if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 204/200 deleting epAcmeV1, got %d", delResp.StatusCode)
	}

	evA3 := mustIngestEvent(t, inst.BaseURL, acme.ID, "user.signup", map[string]any{"tenant": "acme", "phase": 3}, "")
	if len(evA3.DeliveryIDs) != 1 {
		t.Fatalf("expected 1 delivery (v2 only) after decommissioning v1, got %v", evA3.DeliveryIDs)
	}
	_ = waitForDeliveryStatus(t, inst.BaseURL, evA3.DeliveryIDs[0], "DELIVERED", 3*time.Second)

	if len(srvAcmeV1.Requests()) != 2 || len(srvAcmeV2.Requests()) != 2 {
		t.Fatalf("expected 2 calls on v1 (phases 1,2) and 2 calls on v2 (phases 2,3), got v1=%d v2=%d",
			len(srvAcmeV1.Requests()), len(srvAcmeV2.Requests()))
	}

	// Compliance audit: v1 historical deliveries remain queryable
	v1History := listDeliveries(t, inst.BaseURL, "?endpoint_id="+epAcmeV1.ID)
	if len(v1History) != 2 {
		t.Fatalf("expected 2 historical deliveries preserved for epAcmeV1, got %d", len(v1History))
	}
}

// S03: E-Commerce Order Lifecycle (`order.created` -> `order.paid` -> `order.shipped`) Under Retry Storm
func TestTier4_S03_EcommerceOrderLifecycle_IdempotencyUnderNetworkStorm(t *testing.T) {
	inst := startRelayHook(t, "-workers", "8")
	defer inst.Stop(t)

	app := mustCreateApp(t, inst.BaseURL, "shop-core", "E-Commerce Core")

	srvWarehouse := newWebhookCaptureServer(t, "whsec_wh")
	srvEmail := newWebhookCaptureServer(t, "whsec_em")
	srvFraud := newWebhookCaptureServer(t, "whsec_fr")

	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvWarehouse.URL, "whsec_wh", []string{"order.paid", "order.shipped"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvEmail.URL, "whsec_em", []string{"*"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvFraud.URL, "whsec_fr", []string{"order.created"}, 3)

	stages := []struct {
		eventType string
		idemKey   string
	}{
		{"order.created", "ord-100-created"},
		{"order.paid", "ord-100-paid"},
		{"order.shipped", "ord-100-shipped"},
	}

	for _, st := range stages {
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(evType, key string) {
				defer wg.Done()
				_ = mustIngestEvent(t, inst.BaseURL, app.ID, evType, map[string]any{"order_id": "ord-100"}, key)
			}(st.eventType, st.idemKey)
		}
		wg.Wait()
	}

	_ = srvWarehouse.WaitForRequests(t, 2, 4*time.Second)
	_ = srvEmail.WaitForRequests(t, 3, 4*time.Second)
	_ = srvFraud.WaitForRequests(t, 1, 4*time.Second)

	time.Sleep(100 * time.Millisecond)
	if len(srvWarehouse.Requests()) != 2 || len(srvEmail.Requests()) != 3 || len(srvFraud.Requests()) != 1 {
		t.Fatalf("unexpected delivery counts: warehouse=%d (want 2), email=%d (want 3), fraud=%d (want 1)",
			len(srvWarehouse.Requests()), len(srvEmail.Requests()), len(srvFraud.Requests()))
	}

	allDeliveries := listDeliveries(t, inst.BaseURL, "")
	if len(allDeliveries) != 6 {
		t.Fatalf("expected exactly 6 total deliveries across 30 storm requests, got %d", len(allDeliveries))
	}
}

// S04: Downstream Outage, Noisy Neighbor Isolation via Per-Endpoint Circuit Breaker & Auto-Recovery
func TestTier4_S04_DownstreamOutage_CircuitBreakerProtectionAndAutoRecovery(t *testing.T) {
	inst := startRelayHook(t, "-workers", "6", "-base-delay", "20ms", "-max-delay", "60ms")
	defer inst.Stop(t)

	app := mustCreateApp(t, inst.BaseURL, "saas-noisy-neighbor", "Noisy Neighbor Test")

	srvHealthy := newWebhookCaptureServer(t, "whsec_healthy")
	srvOutage := newWebhookCaptureServer(t, "whsec_outage")
	srvOutage.SetFixedStatus(http.StatusInternalServerError)

	epHealthy := mustCreateEndpoint(t, inst.BaseURL, app.ID, srvHealthy.URL, "whsec_healthy", []string{"*"}, 3)
	epOutage := mustCreateEndpoint(t, inst.BaseURL, app.ID, srvOutage.URL, "whsec_outage", []string{"*"}, 2)

	// Trip epOutage circuit breaker
	for i := 0; i < 3; i++ {
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "outage.warmup", map[string]any{"i": i}, "")
		for _, id := range ev.DeliveryIDs {
			_, d := getDelivery(t, inst.BaseURL, id)
			if d.EndpointID == epOutage.ID {
				_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DEAD_LETTER", 3*time.Second)
			} else {
				_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
			}
		}
	}

	// Send 15 events fanning out to both healthy and outage endpoints
	var healthyIDs []string
	var lastOutageID string
	for i := 0; i < 15; i++ {
		ev := mustIngestEvent(t, inst.BaseURL, app.ID, "fanout.storm", map[string]any{"i": i}, "")
		for _, id := range ev.DeliveryIDs {
			_, d := getDelivery(t, inst.BaseURL, id)
			if d.EndpointID == epHealthy.ID {
				healthyIDs = append(healthyIDs, id)
			} else {
				lastOutageID = id
			}
		}
	}

	for _, id := range healthyIDs {
		_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 4*time.Second)
	}
	_ = waitForDeliveryStatus(t, inst.BaseURL, lastOutageID, "DEAD_LETTER", 4*time.Second)

	// Recover srvOutage and replay
	srvOutage.SetFixedStatus(http.StatusOK)
	_, _ = doJSONRequest(t, http.MethodPost, inst.BaseURL+"/api/v1/dlq/"+lastOutageID+"/replay", nil, nil)
	_ = waitForDeliveryStatus(t, inst.BaseURL, lastOutageID, "DELIVERED", 3*time.Second)
}

// S05: SQLite Disaster Recovery — Process Restart & Operator DLQ Batch Replay
func TestTier4_S05_SQLiteDisasterRecovery_ProcessRestartAndDLQReplay(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "s05_disaster.db")
	inst1 := startRelayHook(t, "-db", dbPath, "-workers", "4")

	app := mustCreateApp(t, inst1.BaseURL, "fintech-ledger", "Fintech Ledger")

	srvLedger := newWebhookCaptureServer(t, "whsec_ledger")
	srvLedger.SetFixedStatus(http.StatusInternalServerError)
	srvAudit := newWebhookCaptureServer(t, "whsec_audit")

	_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srvLedger.URL, "whsec_ledger", []string{"ledger.entry"}, 2)
	_ = mustCreateEndpoint(t, inst1.BaseURL, app.ID, srvAudit.URL, "whsec_audit", []string{"audit.log"}, 3)

	var ledgerDlvIDs, auditDlvIDs []string
	for i := 0; i < 5; i++ {
		evL := mustIngestEvent(t, inst1.BaseURL, app.ID, "ledger.entry", map[string]any{"seq": i}, "")
		ledgerDlvIDs = append(ledgerDlvIDs, evL.DeliveryIDs[0])

		evA := mustIngestEvent(t, inst1.BaseURL, app.ID, "audit.log", map[string]any{"seq": i}, "")
		auditDlvIDs = append(auditDlvIDs, evA.DeliveryIDs[0])
	}

	for _, id := range auditDlvIDs {
		_ = waitForDeliveryStatus(t, inst1.BaseURL, id, "DELIVERED", 3*time.Second)
	}
	for _, id := range ledgerDlvIDs {
		_ = waitForDeliveryStatus(t, inst1.BaseURL, id, "DEAD_LETTER", 3*time.Second)
	}

	// Gracefully stop process #1
	if err := inst1.Stop(t); err != nil {
		t.Fatalf("clean stop of inst1 failed: %v", err)
	}

	// Start process #2 on same SQLite DB
	inst2 := startRelayHook(t, "-db", dbPath, "-workers", "4")
	defer inst2.Stop(t)

	dlq := listDLQ(t, inst2.BaseURL)
	if len(dlq) != 5 {
		t.Fatalf("expected 5 persisted DEAD_LETTER items after restart, got %d", len(dlq))
	}

	// Bring ledger online and replay all 5 items from DLQ
	srvLedger.SetFixedStatus(http.StatusOK)
	for _, item := range dlq {
		resp, _ := doJSONRequest(t, http.MethodPost, inst2.BaseURL+"/api/v1/dlq/"+item.ID+"/replay", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("failed replaying %s: %d", item.ID, resp.StatusCode)
		}
	}

	for _, id := range ledgerDlvIDs {
		_ = waitForDeliveryStatus(t, inst2.BaseURL, id, "DELIVERED", 4*time.Second)
	}

	if len(listDLQ(t, inst2.BaseURL)) != 0 {
		t.Fatal("expected DLQ empty after replaying all 5 ledger deliveries")
	}
}

// S06: Full Observability SLA Audit — End-to-End Correlation of X-Request-ID, JSON slog, Probes & Prometheus Metrics
func TestTier4_S06_FullObservabilitySLAAudit_MetricsLogsAndProbes(t *testing.T) {
	inst := startRelayHook(t, "-workers", "4")
	defer inst.Stop(t)

	// Pre-traffic probe checks
	rH, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/healthz", nil, nil)
	rR, _ := doJSONRequest(t, http.MethodGet, inst.BaseURL+"/readyz", nil, nil)
	if rH.StatusCode != http.StatusOK || rR.StatusCode != http.StatusOK {
		t.Fatalf("initial probe failure: healthz=%d readyz=%d", rH.StatusCode, rR.StatusCode)
	}

	app := mustCreateApp(t, inst.BaseURL, "sre-audit-app", "SRE Observability App")

	srvFast := newWebhookCaptureServer(t, "whsec_fast")
	srvFlaky := newWebhookCaptureServer(t, "whsec_flaky")
	srvFlaky.SetStatusSequence(http.StatusInternalServerError, http.StatusOK)
	srvDead := newWebhookCaptureServer(t, "whsec_dead")
	srvDead.SetFixedStatus(http.StatusInternalServerError)

	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvFast.URL, "whsec_fast", []string{"evt.fast"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvFlaky.URL, "whsec_flaky", []string{"evt.flaky"}, 3)
	_ = mustCreateEndpoint(t, inst.BaseURL, app.ID, srvDead.URL, "whsec_dead", []string{"evt.dead"}, 2)

	var fastIDs []string
	for i := 1; i <= 8; i++ {
		traceID := fmt.Sprintf("sre-audit-req-%d", i)
		ev := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "evt.fast", map[string]any{"n": i}, "", map[string]string{
			"X-Request-ID": traceID,
		})
		fastIDs = append(fastIDs, ev.DeliveryIDs[0])
	}

	evFlaky := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "evt.flaky", map[string]any{"n": 9}, "", map[string]string{
		"X-Request-ID": "sre-audit-req-9",
	})
	evDead := mustIngestEventWithHeaders(t, inst.BaseURL, app.ID, "evt.dead", map[string]any{"n": 10}, "", map[string]string{
		"X-Request-ID": "sre-audit-req-10",
	})

	for _, id := range fastIDs {
		_ = waitForDeliveryStatus(t, inst.BaseURL, id, "DELIVERED", 3*time.Second)
	}
	_ = waitForDeliveryStatus(t, inst.BaseURL, evFlaky.DeliveryIDs[0], "DELIVERED", 3*time.Second)
	_ = waitForDeliveryStatus(t, inst.BaseURL, evDead.DeliveryIDs[0], "DEAD_LETTER", 3*time.Second)

	metrics := scrapeMetrics(t, inst.BaseURL)
	ingested, ok1 := parseMetricSum(metrics, "relayhook_events_ingested_total")
	deliveries, ok2 := parseMetricSum(metrics, "relayhook_deliveries_total")
	retries, ok3 := parseMetricSum(metrics, "relayhook_retry_attempts_total")
	workers, ok4 := parseMetricSum(metrics, "relayhook_active_workers")

	if !ok1 || ingested < 10 {
		t.Fatalf("expected relayhook_events_ingested_total >= 10, got %v", ingested)
	}
	if !ok2 || deliveries < 10 {
		t.Fatalf("expected relayhook_deliveries_total >= 10, got %v", deliveries)
	}
	if !ok3 || retries < 2 {
		t.Fatalf("expected relayhook_retry_attempts_total >= 2, got %v", retries)
	}
	if !ok4 || workers != 4 {
		t.Fatalf("expected relayhook_active_workers == 4, got %v", workers)
	}

	logText := inst.Logs.String()
	for i := 1; i <= 10; i++ {
		traceID := fmt.Sprintf("sre-audit-req-%d", i)
		if !strings.Contains(logText, traceID) {
			t.Fatalf("expected JSON logs to contain trace_id %q", traceID)
		}
	}
	for _, line := range inst.Logs.Lines() {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON log entry: %v (%s)", err, line)
		}
	}
}
