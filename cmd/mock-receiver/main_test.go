package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/pkg/sdk"
)

func TestMockReceiver_HealthzAndReadyz(t *testing.T) {
	mr := NewMockReceiver("", 0, 0, 0, 200, nil)
	handler := mr.Handler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /healthz, got %d", rr.Code)
	}

	reqRdy := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rrRdy := httptest.NewRecorder()
	handler.ServeHTTP(rrRdy, reqRdy)

	if rrRdy.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /readyz, got %d", rrRdy.Code)
	}
}

func TestMockReceiver_HMACVerificationAndFailFirst(t *testing.T) {
	secret := "whsec_test_mock"
	mr := NewMockReceiver(secret, 2, 0, 0, 200, nil)
	handler := mr.Handler()

	payload := []byte(`{"event":"order.created","id":"ord_123"}`)
	now := time.Now().Unix()
	sig := sdk.SignPayload(secret, payload, now)

	// Attempt 1 -> 500
	req1 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-RelayHook-Signature", sig)
	req1.Header.Set("X-RelayHook-ID", "dlv_test_1")
	req1.Header.Set("X-RelayHook-Event", "order.created")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusInternalServerError {
		t.Fatalf("attempt 1: expected 500, got %d", rr1.Code)
	}

	// Attempt 2 -> 500
	req2 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-RelayHook-Signature", sig)
	req2.Header.Set("X-RelayHook-ID", "dlv_test_1")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusInternalServerError {
		t.Fatalf("attempt 2: expected 500, got %d", rr2.Code)
	}

	// Attempt 3 -> 200 OK
	req3 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-RelayHook-Signature", sig)
	req3.Header.Set("X-RelayHook-ID", "dlv_test_1")
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("attempt 3: expected 200, got %d", rr3.Code)
	}

	// Invalid signature -> 401
	reqBad := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("X-RelayHook-Signature", "t=123,v1=badbadbad")
	reqBad.Header.Set("X-RelayHook-ID", "dlv_test_bad")
	rrBad := httptest.NewRecorder()
	handler.ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for bad HMAC, got %d", rrBad.Code)
	}
}
