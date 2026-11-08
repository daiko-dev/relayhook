package security

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

func TestComputeHMACAndSignPayload_DeterministicVector(t *testing.T) {
	secret := "whsec_test_secret_123"
	payload := []byte(`{"event":"payment.succeeded","amount":4999}`)
	ts := int64(1700000000)

	// HMAC-SHA256("whsec_test_secret_123", "1700000000.{\"event\":\"payment.succeeded\",\"amount\":4999}")
	expectedHex := "75857743488f38affda21536838bab035842e0d92091f9ee4de119b8b0090249"
	gotHex := ComputeHMAC(secret, payload, ts)
	if gotHex != expectedHex {
		t.Fatalf("ComputeHMAC mismatch: got %q, want %q", gotHex, expectedHex)
	}

	expectedHeader := fmt.Sprintf("t=%d,v1=%s", ts, expectedHex)
	gotHeader := SignPayload(secret, payload, ts)
	if gotHeader != expectedHeader {
		t.Fatalf("SignPayload mismatch: got %q, want %q", gotHeader, expectedHeader)
	}
}

func TestVerifySignature_RoundTripAndTampering(t *testing.T) {
	secret := "whsec_live_abc"
	payload := []byte(`{"id":"evt_1","data":{"ok":true}}`)
	now := time.Now()
	header := SignPayload(secret, payload, now.Unix())

	if !VerifySignature(secret, header, payload, HeaderTolerance) {
		t.Fatalf("expected valid signature to verify")
	}

	// Tampered payload (1 byte changed)
	tampered := []byte(`{"id":"evt_2","data":{"ok":true}}`)
	if VerifySignature(secret, header, tampered, HeaderTolerance) {
		t.Fatalf("expected tampered payload to fail verification")
	}

	// Wrong secret
	if VerifySignature("wrong_secret", header, payload, HeaderTolerance) {
		t.Fatalf("expected wrong secret to fail verification")
	}
}

func TestVerifySignatureAt_TimestampTolerance(t *testing.T) {
	secret := "whsec_time_test"
	payload := []byte(`{"status":"ok"}`)
	baseTime := time.Unix(1700000000, 0)

	// Past expired timestamp (now - 10m with 5m tolerance)
	oldHeader := SignPayload(secret, payload, baseTime.Add(-10*time.Minute).Unix())
	err := VerifySignatureAt(secret, oldHeader, payload, baseTime, HeaderTolerance)
	if !errors.Is(err, domain.ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired for old timestamp, got %v", err)
	}
	if VerifySignature(secret, oldHeader, payload, HeaderTolerance) {
		t.Fatalf("expected VerifySignature to return false for old timestamp")
	}

	// Future expired timestamp (now + 10m with 5m tolerance)
	futureHeader := SignPayload(secret, payload, baseTime.Add(10*time.Minute).Unix())
	err = VerifySignatureAt(secret, futureHeader, payload, baseTime, HeaderTolerance)
	if !errors.Is(err, domain.ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired for future timestamp, got %v", err)
	}

	// Zero tolerance disables timestamp check
	if !VerifySignature(secret, oldHeader, payload, 0) {
		t.Fatalf("expected VerifySignature with tolerance=0 to accept old timestamp")
	}
}

func TestVerifySignature_MalformedHeaders(t *testing.T) {
	secret := "whsec_malformed"
	payload := []byte(`{}`)
	now := time.Now()

	cases := []string{
		"",
		"   ",
		"invalid",
		"t=1700000000",
		"v1=abcdef123456",
		"t=,v1=abcdef",
		"t=1700000000,v1=",
		"t=notanint,v1=abcdef123456",
		fmt.Sprintf("t=%d,v1=not_valid_hex!", now.Unix()),
		fmt.Sprintf("t=%d,v1=deadbeef", now.Unix()),
	}

	for _, tc := range cases {
		err := VerifySignatureAt(secret, tc, payload, now, HeaderTolerance)
		if !errors.Is(err, domain.ErrInvalidSignature) {
			t.Errorf("header %q: expected ErrInvalidSignature, got %v", tc, err)
		}
	}
}

func TestVerifyHeaders_CombinedAndSplitFormats(t *testing.T) {
	secret := "whsec_headers"
	payload := []byte(`{"hello":"world"}`)
	now := time.Now()
	ts := now.Unix()
	tsStr := strconv.FormatInt(ts, 10)
	rawHex := ComputeHMAC(secret, payload, ts)
	combined := SignPayload(secret, payload, ts)

	// 1. Combined sigHeader with empty tsHeader
	if err := VerifyHeaders(secret, combined, "", payload, HeaderTolerance); err != nil {
		t.Fatalf("combined header with empty tsHeader failed: %v", err)
	}

	// 2. Combined sigHeader with matching tsHeader
	if err := VerifyHeaders(secret, combined, tsStr, payload, HeaderTolerance); err != nil {
		t.Fatalf("combined header with matching tsHeader failed: %v", err)
	}

	// 3. Raw hex sigHeader + tsHeader
	if err := VerifyHeaders(secret, rawHex, tsStr, payload, HeaderTolerance); err != nil {
		t.Fatalf("raw hex sigHeader + tsHeader failed: %v", err)
	}

	// 4. v1=<hex> sigHeader + tsHeader
	if err := VerifyHeaders(secret, "v1="+rawHex, tsStr, payload, HeaderTolerance); err != nil {
		t.Fatalf("v1=<hex> sigHeader + tsHeader failed: %v", err)
	}

	// 5. Combined sigHeader with mismatched valid tsHeader -> ErrInvalidSignature
	otherTsStr := strconv.FormatInt(ts-10, 10)
	if err := VerifyHeadersAt(secret, combined, otherTsStr, payload, now, HeaderTolerance); !errors.Is(err, domain.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for mismatched tsHeader, got %v", err)
	}

	// 6. Combined sigHeader with expired tsHeader -> ErrTimestampExpired
	expiredTsStr := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	if err := VerifyHeadersAt(secret, combined, expiredTsStr, payload, now, HeaderTolerance); !errors.Is(err, domain.ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired for expired tsHeader, got %v", err)
	}

	// 7. Combined sigHeader with non-integer tsHeader -> ErrInvalidSignature
	if err := VerifyHeadersAt(secret, combined, "bad-ts", payload, now, HeaderTolerance); !errors.Is(err, domain.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for bad tsHeader, got %v", err)
	}

	// 8. Missing sigHeader or missing tsHeader on raw hex
	if err := VerifyHeaders(secret, "", tsStr, payload, HeaderTolerance); !errors.Is(err, domain.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for empty sigHeader, got %v", err)
	}
	if err := VerifyHeaders(secret, rawHex, "", payload, HeaderTolerance); !errors.Is(err, domain.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for rawHex without tsHeader, got %v", err)
	}
	if err := VerifyHeaders(secret, "v1=", tsStr, payload, HeaderTolerance); !errors.Is(err, domain.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for empty v1=, got %v", err)
	}
}
