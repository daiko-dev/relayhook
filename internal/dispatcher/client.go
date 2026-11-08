package dispatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/daiko-dev/relayhook/internal/security"
)

const (
	DefaultClientTimeout = 5 * time.Second
	MaxResponseBodyBytes = 64 * 1024
	DefaultUserAgent     = "RelayHook/1.0"
)

type DeliveryRequest struct {
	DeliveryID string
	EventID    string
	EventType  string
	URL        string
	Secret     string
	Payload    []byte
	Timestamp  int64
}

type DeliveryResult struct {
	StatusCode   int
	ResponseTime int64
	ResponseBody []byte
	Err          error
}

type WebhookClient struct {
	httpClient *http.Client
	maxBody    int64
	userAgent  string
}

func NewWebhookClient(timeout time.Duration) *WebhookClient {
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}
	return &WebhookClient{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		maxBody:   MaxResponseBodyBytes,
		userAgent: DefaultUserAgent,
	}
}

func (c *WebhookClient) Send(ctx context.Context, req DeliveryRequest) DeliveryResult {
	start := time.Now()

	ts := req.Timestamp
	if ts <= 0 {
		ts = start.Unix()
	}
	payload := req.Payload
	if payload == nil {
		payload = []byte("{}")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.URL, bytes.NewReader(payload))
	if err != nil {
		return DeliveryResult{
			ResponseTime: time.Since(start).Milliseconds(),
			Err:          fmt.Errorf("create request: %w", err),
		}
	}

	sigHeader := security.SignPayload(req.Secret, payload, ts)
	tsHeader := strconv.FormatInt(ts, 10)

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", c.userAgent)
	httpReq.Header.Set("X-RelayHook-ID", req.DeliveryID)
	httpReq.Header.Set("X-RelayHook-Event", req.EventType)
	httpReq.Header.Set("X-RelayHook-Timestamp", tsHeader)
	httpReq.Header.Set("X-RelayHook-Signature", sigHeader)

	resp, err := c.httpClient.Do(httpReq)
	elapsedMs := time.Since(start).Milliseconds()
	if err != nil {
		return DeliveryResult{
			ResponseTime: elapsedMs,
			Err:          err,
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	limited := io.LimitReader(resp.Body, c.maxBody)
	bodyBytes, readErr := io.ReadAll(limited)
	if readErr != nil {
		return DeliveryResult{
			StatusCode:   resp.StatusCode,
			ResponseTime: elapsedMs,
			ResponseBody: bodyBytes,
			Err:          readErr,
		}
	}

	return DeliveryResult{
		StatusCode:   resp.StatusCode,
		ResponseTime: elapsedMs,
		ResponseBody: bodyBytes,
		Err:          nil,
	}
}

func (c *WebhookClient) CloseIdleConnections() {
	if c != nil && c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}
