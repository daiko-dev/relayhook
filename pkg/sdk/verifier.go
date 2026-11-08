package sdk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTolerance = 5 * time.Minute
	SignatureHeader  = "X-RelayHook-Signature"
	TimestampHeader  = "X-RelayHook-Timestamp"
	EventIDHeader    = "X-RelayHook-ID"
	EventTypeHeader  = "X-RelayHook-Event"
)

var (
	ErrMissingSignature    = errors.New("missing webhook signature")
	ErrInvalidHeaderFormat = errors.New("invalid signature header format")
	ErrTimestampExpired    = errors.New("webhook timestamp expired")
	ErrSignatureMismatch   = errors.New("webhook signature mismatch")
)

func ComputeHMAC(secret string, payload []byte, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	msg := fmt.Sprintf("%d.%s", timestamp, payload)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func SignPayload(secret string, payload []byte, timestamp int64) string {
	return fmt.Sprintf("t=%d,v1=%s", timestamp, ComputeHMAC(secret, payload, timestamp))
}

func VerifySignature(secret, header string, payload []byte, tolerance time.Duration) bool {
	return verifySignatureAt(secret, header, payload, time.Now(), tolerance) == nil
}

func VerifyHeaders(secret, sigHeader, tsHeader string, payload []byte, tolerance time.Duration) error {
	return verifyHeadersAt(secret, sigHeader, tsHeader, payload, time.Now(), tolerance)
}

func verifyHeadersAt(secret, sigHeader, tsHeader string, payload []byte, now time.Time, tolerance time.Duration) error {
	sigHeader = strings.TrimSpace(sigHeader)
	tsHeader = strings.TrimSpace(tsHeader)
	if sigHeader == "" {
		return ErrMissingSignature
	}

	if tsStr, _, ok := parseSignatureHeader(sigHeader); ok {
		if tsHeader != "" && tsHeader != tsStr {
			hdrTs, err := strconv.ParseInt(tsHeader, 10, 64)
			if err != nil {
				return ErrInvalidHeaderFormat
			}
			if tolerance > 0 {
				diff := now.Sub(time.Unix(hdrTs, 0))
				if diff > tolerance || diff < -tolerance {
					return ErrTimestampExpired
				}
			}
			return ErrSignatureMismatch
		}
		return verifySignatureAt(secret, sigHeader, payload, now, tolerance)
	}

	if tsHeader == "" {
		return ErrInvalidHeaderFormat
	}
	rawHex := strings.TrimPrefix(sigHeader, "v1=")
	if rawHex == "" || strings.Contains(rawHex, "=") {
		return ErrInvalidHeaderFormat
	}
	combined := fmt.Sprintf("t=%s,v1=%s", tsHeader, rawHex)
	return verifySignatureAt(secret, combined, payload, now, tolerance)
}

func verifySignatureAt(secret, header string, payload []byte, now time.Time, tolerance time.Duration) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return ErrMissingSignature
	}
	tsStr, sigHex, ok := parseSignatureHeader(header)
	if !ok {
		return ErrInvalidHeaderFormat
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return ErrInvalidHeaderFormat
	}

	if tolerance > 0 {
		diff := now.Sub(time.Unix(ts, 0))
		if diff > tolerance || diff < -tolerance {
			return ErrTimestampExpired
		}
	}

	providedMAC, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidHeaderFormat
	}

	expectedHex := ComputeHMAC(secret, payload, ts)
	expectedMAC, _ := hex.DecodeString(expectedHex)

	if !hmac.Equal(providedMAC, expectedMAC) {
		return ErrSignatureMismatch
	}
	return nil
}

func parseSignatureHeader(header string) (tsStr string, sigHex string, ok bool) {
	parts := strings.Split(header, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", "", false
		}
		switch kv[0] {
		case "t":
			tsStr = kv[1]
		case "v1":
			sigHex = kv[1]
		}
	}
	if tsStr == "" || sigHex == "" {
		return "", "", false
	}
	return tsStr, sigHex, true
}

type Verifier struct {
	secret    string
	tolerance time.Duration
	now       func() time.Time
}

func NewVerifier(secret string, tolerance time.Duration) *Verifier {
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	return &Verifier{
		secret:    secret,
		tolerance: tolerance,
		now:       time.Now,
	}
}

func (v *Verifier) VerifyRequest(r *http.Request) ([]byte, error) {
	if r == nil {
		return nil, ErrInvalidHeaderFormat
	}
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	sigHeader := r.Header.Get(SignatureHeader)
	tsHeader := r.Header.Get(TimestampHeader)
	nowFn := time.Now
	if v.now != nil {
		nowFn = v.now
	}
	if err := verifyHeadersAt(v.secret, sigHeader, tsHeader, body, nowFn(), v.tolerance); err != nil {
		return nil, err
	}
	return body, nil
}
