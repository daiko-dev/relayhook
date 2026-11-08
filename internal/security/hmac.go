package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daiko-dev/relayhook/internal/domain"
)

const HeaderTolerance = 5 * time.Minute

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
	return VerifySignatureAt(secret, header, payload, time.Now(), tolerance) == nil
}

func VerifySignatureAt(secret, header string, payload []byte, now time.Time, tolerance time.Duration) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return domain.ErrInvalidSignature
	}
	tsStr, sigHex, ok := parseSignatureHeader(header)
	if !ok {
		return domain.ErrInvalidSignature
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return domain.ErrInvalidSignature
	}

	if tolerance > 0 {
		diff := now.Sub(time.Unix(ts, 0))
		if diff > tolerance || diff < -tolerance {
			return domain.ErrTimestampExpired
		}
	}

	providedMAC, err := hex.DecodeString(sigHex)
	if err != nil {
		return domain.ErrInvalidSignature
	}

	expectedHex := ComputeHMAC(secret, payload, ts)
	expectedMAC, _ := hex.DecodeString(expectedHex)

	if !hmac.Equal(providedMAC, expectedMAC) {
		return domain.ErrInvalidSignature
	}
	return nil
}

func VerifyHeaders(secret, sigHeader, tsHeader string, payload []byte, tolerance time.Duration) error {
	return VerifyHeadersAt(secret, sigHeader, tsHeader, payload, time.Now(), tolerance)
}

func VerifyHeadersAt(secret, sigHeader, tsHeader string, payload []byte, now time.Time, tolerance time.Duration) error {
	sigHeader = strings.TrimSpace(sigHeader)
	tsHeader = strings.TrimSpace(tsHeader)
	if sigHeader == "" {
		return domain.ErrInvalidSignature
	}

	if tsStr, _, ok := parseSignatureHeader(sigHeader); ok {
		if tsHeader != "" && tsHeader != tsStr {
			hdrTs, err := strconv.ParseInt(tsHeader, 10, 64)
			if err != nil {
				return domain.ErrInvalidSignature
			}
			if tolerance > 0 {
				diff := now.Sub(time.Unix(hdrTs, 0))
				if diff > tolerance || diff < -tolerance {
					return domain.ErrTimestampExpired
				}
			}
			return domain.ErrInvalidSignature
		}
		return VerifySignatureAt(secret, sigHeader, payload, now, tolerance)
	}

	if tsHeader == "" {
		return domain.ErrInvalidSignature
	}
	rawHex := strings.TrimPrefix(sigHeader, "v1=")
	if rawHex == "" || strings.Contains(rawHex, "=") {
		return domain.ErrInvalidSignature
	}
	combined := fmt.Sprintf("t=%s,v1=%s", tsHeader, rawHex)
	return VerifySignatureAt(secret, combined, payload, now, tolerance)
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
