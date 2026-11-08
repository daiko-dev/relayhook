package sdk

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/security"
)

func TestSDK_ParityWithInternalSecurity(t *testing.T) {
	secret := "whsec_sdk_parity"
	payload := []byte(`{"id":"evt_123","type":"invoice.paid"}`)
	ts := time.Now().Unix()

	if got, want := ComputeHMAC(secret, payload, ts), security.ComputeHMAC(secret, payload, ts); got != want {
		t.Fatalf("ComputeHMAC mismatch: got %q, want %q", got, want)
	}
	if got, want := SignPayload(secret, payload, ts), security.SignPayload(secret, payload, ts); got != want {
		t.Fatalf("SignPayload mismatch: got %q, want %q", got, want)
	}

	sig := SignPayload(secret, payload, ts)
	if !VerifySignature(secret, sig, payload, DefaultTolerance) {
		t.Fatalf("expected VerifySignature to return true")
	}
	if VerifySignature("wrong", sig, payload, DefaultTolerance) {
		t.Fatalf("expected VerifySignature with wrong secret to return false")
	}
}

func TestSDK_VerifyHeaders(t *testing.T) {
	secret := "whsec_headers_sdk"
	payload := []byte(`{"user":"alice"}`)
	now := time.Now()
	ts := now.Unix()
	tsStr := strconv.FormatInt(ts, 10)
	sig := SignPayload(secret, payload, ts)
	rawHex := ComputeHMAC(secret, payload, ts)

	if err := VerifyHeaders(secret, sig, "", payload, DefaultTolerance); err != nil {
		t.Fatalf("expected nil error for combined header, got %v", err)
	}
	if err := VerifyHeaders(secret, sig, tsStr, payload, DefaultTolerance); err != nil {
		t.Fatalf("expected nil error for combined header + matching tsHeader, got %v", err)
	}
	if err := VerifyHeaders(secret, rawHex, tsStr, payload, DefaultTolerance); err != nil {
		t.Fatalf("expected nil error for split rawHex + tsHeader, got %v", err)
	}
	if err := VerifyHeaders(secret, "v1="+rawHex, tsStr, payload, DefaultTolerance); err != nil {
		t.Fatalf("expected nil error for split v1= + tsHeader, got %v", err)
	}

	if err := VerifyHeaders(secret, "", tsStr, payload, DefaultTolerance); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
	if err := VerifyHeaders(secret, "malformed", "", payload, DefaultTolerance); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat, got %v", err)
	}
	if err := VerifyHeaders(secret, "v1=", tsStr, payload, DefaultTolerance); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat for empty v1=, got %v", err)
	}
	if err := VerifyHeaders(secret, "t=bad,v1="+rawHex, "", payload, DefaultTolerance); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat for non-int timestamp, got %v", err)
	}
	if err := VerifyHeaders(secret, "t="+tsStr+",v1=not_hex!", "", payload, DefaultTolerance); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat for non-hex v1, got %v", err)
	}
	if err := VerifyHeaders(secret, sig, "not_an_int", payload, DefaultTolerance); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat for bad tsHeader, got %v", err)
	}

	expiredTsStr := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	if err := VerifyHeaders(secret, sig, expiredTsStr, payload, DefaultTolerance); !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired for expired tsHeader, got %v", err)
	}
	if err := VerifyHeaders(secret, sig, strconv.FormatInt(ts-5, 10), payload, DefaultTolerance); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch for mismatched tsHeader, got %v", err)
	}
}

func TestVerifier_VerifyRequest(t *testing.T) {
	secret := "whsec_req_verifier"
	payload := []byte(`{"order_id":"ord_999"}`)
	fixedNow := time.Unix(1700000000, 0)

	v := NewVerifier(secret, 0) // defaults to DefaultTolerance
	v.now = func() time.Time { return fixedNow }

	// 1. Valid request & readable restored body
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set(SignatureHeader, SignPayload(secret, payload, fixedNow.Unix()))
	req.Header.Set(TimestampHeader, strconv.FormatInt(fixedNow.Unix(), 10))
	req.Header.Set(EventIDHeader, "del_1")
	req.Header.Set(EventTypeHeader, "order.created")

	body, err := v.VerifyRequest(req)
	if err != nil {
		t.Fatalf("VerifyRequest failed: %v", err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body mismatch: got %q, want %q", body, payload)
	}

	restoredBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading restored r.Body failed: %v", err)
	}
	if !bytes.Equal(restoredBody, payload) {
		t.Fatalf("restored r.Body mismatch: got %q, want %q", restoredBody, payload)
	}

	// 2. Missing signature header
	reqMissing := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	if _, err := v.VerifyRequest(reqMissing); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}

	// 3. Expired timestamp
	reqExpired := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	oldTs := fixedNow.Add(-10 * time.Minute).Unix()
	reqExpired.Header.Set(SignatureHeader, SignPayload(secret, payload, oldTs))
	if _, err := v.VerifyRequest(reqExpired); !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired, got %v", err)
	}

	// 4. Tampered body
	reqTampered := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{"order_id":"tampered"}`)))
	reqTampered.Header.Set(SignatureHeader, SignPayload(secret, payload, fixedNow.Unix()))
	if _, err := v.VerifyRequest(reqTampered); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("expected ErrSignatureMismatch, got %v", err)
	}

	// 5. Malformed header & nil request
	reqMalformed := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	reqMalformed.Header.Set(SignatureHeader, "invalid_format")
	if _, err := v.VerifyRequest(reqMalformed); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat, got %v", err)
	}
	if _, err := v.VerifyRequest(nil); !errors.Is(err, ErrInvalidHeaderFormat) {
		t.Fatalf("expected ErrInvalidHeaderFormat for nil request, got %v", err)
	}
}
