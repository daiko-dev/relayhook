package e2e_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var (
	sharedBinDirOnce sync.Once
	sharedBinDir     string
	sharedBinDirErr  error

	buildRelayHookMu   sync.Mutex
	relayHookBinBuilt  bool
	relayHookBinPath   string
	buildRelayHookErr  error

	buildMockMu       sync.Mutex
	mockBinBuilt      bool
	mockBinPath       string
	buildMockErr      error
)

func getSharedBinDir(t *testing.T) string {
	t.Helper()
	sharedBinDirOnce.Do(func() {
		sharedBinDir, sharedBinDirErr = os.MkdirTemp("", "relayhook-e2e-bins-*")
	})
	if sharedBinDirErr != nil {
		t.Fatalf("failed to create shared temp bin dir: %v", sharedBinDirErr)
	}
	return sharedBinDir
}

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine caller file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func requireOrSkipFile(t *testing.T, relPath string) string {
	t.Helper()
	root := projectRoot(t)
	full := filepath.Join(root, relPath)
	if _, err := os.Stat(full); err != nil {
		if os.Getenv("RELAYHOOK_REQUIRE_E2E") == "1" {
			t.Fatalf("RELAYHOOK_REQUIRE_E2E=1: required file %s does not exist: %v", full, err)
		}
		t.Skipf("%s not yet built; set RELAYHOOK_REQUIRE_E2E=1 to enforce", relPath)
	}
	return full
}

func ensureRelayHookBinary(t *testing.T) string {
	t.Helper()
	root := projectRoot(t)
	mainFile := filepath.Join(root, "cmd", "relayhook", "main.go")
	if _, err := os.Stat(mainFile); err != nil {
		if os.Getenv("RELAYHOOK_REQUIRE_E2E") == "1" {
			t.Fatalf("RELAYHOOK_REQUIRE_E2E=1: cmd/relayhook/main.go does not exist: %v", err)
		}
		t.Skipf("cmd/relayhook/main.go not yet built; set RELAYHOOK_REQUIRE_E2E=1 to enforce")
	}

	buildRelayHookMu.Lock()
	defer buildRelayHookMu.Unlock()
	if !relayHookBinBuilt {
		binDir := getSharedBinDir(t)
		out := filepath.Join(binDir, "relayhook")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/relayhook")
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		if err != nil {
			buildRelayHookErr = fmt.Errorf("go build ./cmd/relayhook failed: %w\n%s", err, string(output))
		} else {
			relayHookBinPath = out
		}
		relayHookBinBuilt = true
	}
	if buildRelayHookErr != nil {
		t.Fatalf("%v", buildRelayHookErr)
	}
	return relayHookBinPath
}

func ensureMockReceiverBinary(t *testing.T) string {
	t.Helper()
	root := projectRoot(t)
	mainFile := filepath.Join(root, "cmd", "mock-receiver", "main.go")
	if _, err := os.Stat(mainFile); err != nil {
		if os.Getenv("RELAYHOOK_REQUIRE_E2E") == "1" {
			t.Fatalf("RELAYHOOK_REQUIRE_E2E=1: cmd/mock-receiver/main.go does not exist: %v", err)
		}
		t.Skipf("cmd/mock-receiver/main.go not yet built; set RELAYHOOK_REQUIRE_E2E=1 to enforce")
	}

	buildMockMu.Lock()
	defer buildMockMu.Unlock()
	if !mockBinBuilt {
		binDir := getSharedBinDir(t)
		out := filepath.Join(binDir, "mock-receiver")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/mock-receiver")
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		if err != nil {
			buildMockErr = fmt.Errorf("go build ./cmd/mock-receiver failed: %w\n%s", err, string(output))
		} else {
			mockBinPath = out
		}
		mockBinBuilt = true
	}
	if buildMockErr != nil {
		t.Fatalf("%v", buildMockErr)
	}
	return mockBinPath
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuffer) Lines() []string {
	raw := strings.TrimSpace(s.String())
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

type relayHookInstance struct {
	BaseURL  string
	Port     int
	Cmd      *exec.Cmd
	Logs     *safeBuffer
	DBPath   string
	doneCh   chan error
	stopOnce sync.Once
	exitErr  error
}

func (inst *relayHookInstance) Stop(t *testing.T) error {
	t.Helper()
	inst.stopOnce.Do(func() {
		if inst.Cmd == nil || inst.Cmd.Process == nil {
			return
		}
		_ = inst.Cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-inst.doneCh:
			inst.exitErr = err
		case <-time.After(5 * time.Second):
			_ = inst.Cmd.Process.Kill()
			inst.exitErr = <-inst.doneCh
		}
	})
	return inst.exitErr
}

func (inst *relayHookInstance) StopWithSignal(t *testing.T, sig os.Signal) error {
	t.Helper()
	inst.stopOnce.Do(func() {
		if inst.Cmd == nil || inst.Cmd.Process == nil {
			return
		}
		_ = inst.Cmd.Process.Signal(sig)
		select {
		case err := <-inst.doneCh:
			inst.exitErr = err
		case <-time.After(5 * time.Second):
			_ = inst.Cmd.Process.Kill()
			inst.exitErr = <-inst.doneCh
		}
	})
	return inst.exitErr
}

func mergeFlags(defaults map[string]string, order []string, extraArgs []string) []string {
	merged := make(map[string]string, len(defaults))
	keyOrder := make([]string, 0, len(order)+len(extraArgs))
	seen := make(map[string]bool)
	for _, k := range order {
		merged[k] = defaults[k]
		keyOrder = append(keyOrder, k)
		seen[k] = true
	}

	var positional []string
	for i := 0; i < len(extraArgs); i++ {
		arg := extraArgs[i]
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				k, v := parts[0], parts[1]
				merged[k] = v
				if !seen[k] {
					keyOrder = append(keyOrder, k)
					seen[k] = true
				}
			} else if i+1 < len(extraArgs) && !strings.HasPrefix(extraArgs[i+1], "-") {
				k := arg
				v := extraArgs[i+1]
				i++
				merged[k] = v
				if !seen[k] {
					keyOrder = append(keyOrder, k)
					seen[k] = true
				}
			} else {
				positional = append(positional, arg)
			}
		} else {
			positional = append(positional, arg)
		}
	}

	var finalArgs []string
	for _, k := range keyOrder {
		v := merged[k]
		if v == "" && k == "-db" {
			continue
		}
		finalArgs = append(finalArgs, k, v)
	}
	finalArgs = append(finalArgs, positional...)
	return finalArgs
}

func startRelayHook(t *testing.T, extraArgs ...string) *relayHookInstance {
	t.Helper()
	binPath := ensureRelayHookBinary(t)
	port := freePort(t)

	defaults := map[string]string{
		"-port":       strconv.Itoa(port),
		"-workers":    "4",
		"-base-delay": "20ms",
		"-max-delay":  "100ms",
	}
	order := []string{"-port", "-workers", "-base-delay", "-max-delay"}
	args := mergeFlags(defaults, order, extraArgs)

	var dbPath string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-db" {
			dbPath = args[i+1]
		}
		if args[i] == "-port" {
			if p, err := strconv.Atoi(args[i+1]); err == nil {
				port = p
			}
		}
	}

	logs := &safeBuffer{}
	cmd := exec.Command(binPath, args...)
	cmd.Dir = projectRoot(t)
	cmd.Stdout = logs
	cmd.Stderr = logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start relayhook binary: %v", err)
	}

	inst := &relayHookInstance{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Port:    port,
		Cmd:     cmd,
		Logs:    logs,
		DBPath:  dbPath,
		doneCh:  make(chan error, 1),
	}

	go func() {
		inst.doneCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		_ = inst.Stop(t)
	})

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-inst.doneCh:
			t.Fatalf("relayhook exited prematurely (%v). Logs:\n%s", err, inst.Logs.String())
		default:
		}

		resp1, err1 := client.Get(inst.BaseURL + "/healthz")
		if err1 == nil {
			_ = resp1.Body.Close()
		}
		resp2, err2 := client.Get(inst.BaseURL + "/readyz")
		if err2 == nil {
			_ = resp2.Body.Close()
		}
		if err1 == nil && resp1.StatusCode == http.StatusOK && err2 == nil && resp2.StatusCode == http.StatusOK {
			return inst
		}
		time.Sleep(15 * time.Millisecond)
	}

	t.Fatalf("relayhook did not become ready within 5s on %s. Logs:\n%s", inst.BaseURL, inst.Logs.String())
	return nil
}

// lazyRelayHook defers starting relayhook until the first subtest actually invokes it,
// ensuring subtests are always registered and cleanly skipped when pre-M3.
func lazyRelayHook(parentT *testing.T, extraArgs ...string) func(subT *testing.T) *relayHookInstance {
	var once sync.Once
	var inst *relayHookInstance
	return func(subT *testing.T) *relayHookInstance {
		subT.Helper()
		_ = ensureRelayHookBinary(subT)
		once.Do(func() {
			inst = startRelayHook(parentT, extraArgs...)
		})
		return inst
	}
}

type mockReceiverInstance struct {
	BaseURL    string
	WebhookURL string
	Port       int
	Cmd        *exec.Cmd
	Logs       *safeBuffer
	doneCh     chan error
	stopOnce   sync.Once
}

func (m *mockReceiverInstance) Stop(t *testing.T) {
	t.Helper()
	m.stopOnce.Do(func() {
		if m.Cmd == nil || m.Cmd.Process == nil {
			return
		}
		_ = m.Cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-m.doneCh:
		case <-time.After(3 * time.Second):
			_ = m.Cmd.Process.Kill()
			<-m.doneCh
		}
	})
}

func startMockReceiver(t *testing.T, extraArgs ...string) *mockReceiverInstance {
	t.Helper()
	binPath := ensureMockReceiverBinary(t)
	port := freePort(t)

	defaults := map[string]string{
		"-port": strconv.Itoa(port),
	}
	order := []string{"-port"}
	args := mergeFlags(defaults, order, extraArgs)

	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-port" {
			if p, err := strconv.Atoi(args[i+1]); err == nil {
				port = p
			}
		}
	}

	logs := &safeBuffer{}
	cmd := exec.Command(binPath, args...)
	cmd.Dir = projectRoot(t)
	cmd.Stdout = logs
	cmd.Stderr = logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start mock-receiver binary: %v", err)
	}

	inst := &mockReceiverInstance{
		BaseURL:    fmt.Sprintf("http://127.0.0.1:%d", port),
		WebhookURL: fmt.Sprintf("http://127.0.0.1:%d/webhook", port),
		Port:       port,
		Cmd:        cmd,
		Logs:       logs,
		doneCh:     make(chan error, 1),
	}

	go func() {
		inst.doneCh <- cmd.Wait()
	}()

	t.Cleanup(func() {
		inst.Stop(t)
	})

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-inst.doneCh:
			t.Fatalf("mock-receiver exited prematurely (%v). Logs:\n%s", err, inst.Logs.String())
		default:
		}
		resp, err := client.Get(inst.BaseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return inst
			}
		}
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return inst
		}
		time.Sleep(15 * time.Millisecond)
	}

	t.Fatalf("mock-receiver did not start within 5s on %s. Logs:\n%s", inst.BaseURL, inst.Logs.String())
	return nil
}

// --- Independent Standard Library HMAC-SHA256 Signing & Verification ---

func signPayloadStdlib(secret string, payload []byte, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", timestamp, string(payload))))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", timestamp, sig)
}

func computeHMACStdlib(secret string, payload []byte, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", timestamp, string(payload))))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyHMACStdlib(secret, sigHeader, tsHeader string, payload []byte, tolerance time.Duration) error {
	if secret == "" {
		return errors.New("empty secret")
	}
	if sigHeader == "" {
		return errors.New("missing signature header")
	}

	var tsStr, v1Hex string
	if strings.Contains(sigHeader, ",") || strings.HasPrefix(sigHeader, "t=") {
		parts := strings.Split(sigHeader, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "t=") {
				tsStr = strings.TrimPrefix(p, "t=")
			} else if strings.HasPrefix(p, "v1=") {
				v1Hex = strings.TrimPrefix(p, "v1=")
			}
		}
	} else {
		v1Hex = strings.TrimPrefix(strings.TrimSpace(sigHeader), "v1=")
		tsStr = strings.TrimSpace(tsHeader)
	}

	if tsStr == "" || v1Hex == "" {
		return errors.New("malformed signature header: missing t or v1")
	}

	if tsHeader != "" && tsHeader != tsStr {
		return fmt.Errorf("timestamp header mismatch: sig t=%s vs header=%s", tsStr, tsHeader)
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp integer: %w", err)
	}

	if tolerance > 0 {
		now := time.Now().Unix()
		diff := now - ts
		if diff < 0 {
			diff = -diff
		}
		if diff > int64(tolerance.Seconds()) {
			return fmt.Errorf("timestamp expired or in future: diff=%ds > tolerance=%ds", diff, int64(tolerance.Seconds()))
		}
	}

	actualBytes, err := hex.DecodeString(v1Hex)
	if err != nil || len(actualBytes) != sha256.Size {
		return errors.New("invalid hex signature")
	}

	expectedHex := computeHMACStdlib(secret, payload, ts)
	expectedBytes, _ := hex.DecodeString(expectedHex)

	if !hmac.Equal(actualBytes, expectedBytes) {
		return errors.New("hmac signature mismatch")
	}
	return nil
}

// --- Opaque-Box Webhook Capture Server ---

type capturedWebhook struct {
	Method      string
	Path        string
	Headers     http.Header
	Body        []byte
	Signature   string
	Timestamp   string
	DeliveryID  string
	EventType   string
	ContentType string
	UserAgent   string
	RemoteAddr  string
	ReceivedAt  time.Time
	HMACValid   bool
	HMACError   string
}

type webhookCaptureServer struct {
	Server *httptest.Server
	URL    string
	Secret string

	mu             sync.Mutex
	requests       []capturedWebhook
	globalSeq      []int
	seqIdx         int
	perDeliveryCnt map[string]int
	failFirstPerID int
	fixedStatus    int
	responseDelay  time.Duration
	responseBody   []byte
	dropConn       bool
	inFlight       int32
	maxInFlight    int32
	remoteAddrs    map[string]int
}

func newWebhookCaptureServer(t *testing.T, secret string) *webhookCaptureServer {
	t.Helper()
	w := &webhookCaptureServer{
		Secret:         secret,
		fixedStatus:    http.StatusOK,
		perDeliveryCnt: make(map[string]int),
		remoteAddrs:    make(map[string]int),
	}

	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&w.inFlight, 1)
		for {
			prevMax := atomic.LoadInt32(&w.maxInFlight)
			if cur <= prevMax || atomic.CompareAndSwapInt32(&w.maxInFlight, prevMax, cur) {
				break
			}
		}
		defer atomic.AddInt32(&w.inFlight, -1)

		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		sig := r.Header.Get("X-RelayHook-Signature")
		ts := r.Header.Get("X-RelayHook-Timestamp")
		dlvID := r.Header.Get("X-RelayHook-ID")
		evType := r.Header.Get("X-RelayHook-Event")

		w.mu.Lock()
		secretToUse := w.Secret
		delay := w.responseDelay
		drop := w.dropConn
		respBody := w.responseBody
		w.remoteAddrs[r.RemoteAddr]++

		status := w.fixedStatus
		if w.failFirstPerID > 0 && dlvID != "" {
			cnt := w.perDeliveryCnt[dlvID]
			w.perDeliveryCnt[dlvID] = cnt + 1
			if cnt < w.failFirstPerID {
				status = http.StatusInternalServerError
			} else {
				status = http.StatusOK
			}
		} else if len(w.globalSeq) > 0 {
			if w.seqIdx < len(w.globalSeq) {
				status = w.globalSeq[w.seqIdx]
				w.seqIdx++
			} else {
				status = w.globalSeq[len(w.globalSeq)-1]
			}
		}

		hmacValid := true
		hmacErrStr := ""
		if secretToUse != "" {
			if err := verifyHMACStdlib(secretToUse, sig, ts, bodyBytes, 5*time.Minute); err != nil {
				hmacValid = false
				hmacErrStr = err.Error()
			}
		}

		clonedHeaders := r.Header.Clone()
		w.requests = append(w.requests, capturedWebhook{
			Method:      r.Method,
			Path:        r.URL.Path,
			Headers:     clonedHeaders,
			Body:        bodyBytes,
			Signature:   sig,
			Timestamp:   ts,
			DeliveryID:  dlvID,
			EventType:   evType,
			ContentType: r.Header.Get("Content-Type"),
			UserAgent:   r.Header.Get("User-Agent"),
			RemoteAddr:  r.RemoteAddr,
			ReceivedAt:  time.Now(),
			HMACValid:   hmacValid,
			HMACError:   hmacErrStr,
		})
		w.mu.Unlock()

		if drop {
			if hj, ok := rw.(http.Hijacker); ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
					return
				}
			}
		}

		if delay > 0 {
			time.Sleep(delay)
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		if len(respBody) > 0 {
			_, _ = rw.Write(respBody)
		} else {
			_, _ = rw.Write([]byte(`{"received":true}`))
		}
	}))

	w.URL = w.Server.URL
	t.Cleanup(func() {
		w.Server.Close()
	})
	return w
}

func (w *webhookCaptureServer) SetStatusSequence(codes ...int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.globalSeq = append([]int(nil), codes...)
	w.seqIdx = 0
}

func (w *webhookCaptureServer) SetFailFirstPerID(k int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failFirstPerID = k
}

func (w *webhookCaptureServer) SetFixedStatus(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.globalSeq = nil
	w.failFirstPerID = 0
	w.fixedStatus = code
}

func (w *webhookCaptureServer) SetDelay(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.responseDelay = d
}

func (w *webhookCaptureServer) SetOversizedBody(sizeBytes int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.responseBody = bytes.Repeat([]byte("X"), sizeBytes)
}

func (w *webhookCaptureServer) SetDropConnection(drop bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dropConn = drop
}

func (w *webhookCaptureServer) SetSecret(secret string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Secret = secret
}

func (w *webhookCaptureServer) Requests() []capturedWebhook {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]capturedWebhook, len(w.requests))
	copy(out, w.requests)
	return out
}

func (w *webhookCaptureServer) ResetRequests() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.requests = nil
}

func (w *webhookCaptureServer) MaxConcurrency() int {
	return int(atomic.LoadInt32(&w.maxInFlight))
}

func (w *webhookCaptureServer) UniqueRemoteAddrs() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.remoteAddrs)
}

func (w *webhookCaptureServer) WaitForRequests(t *testing.T, count int, timeout time.Duration) []capturedWebhook {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reqs := w.Requests()
		if len(reqs) >= count {
			return reqs
		}
		time.Sleep(10 * time.Millisecond)
	}
	reqs := w.Requests()
	t.Fatalf("timed out waiting for %d webhook requests (got %d)", count, len(reqs))
	return nil
}

// --- Wire DTOs & HTTP Helpers ---

type appDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type endpointDTO struct {
	ID         string    `json:"id"`
	AppID      string    `json:"app_id"`
	URL        string    `json:"url"`
	Secret     string    `json:"secret"`
	EventTypes []string  `json:"event_types"`
	IsActive   bool      `json:"is_active"`
	MaxRetries int       `json:"max_retries"`
	CreatedAt  time.Time `json:"created_at"`
}

type eventIngestRespDTO struct {
	EventID          string   `json:"event_id"`
	ID               string   `json:"id"`
	Status           string   `json:"status"`
	DeliveriesQueued int      `json:"deliveries_queued"`
	DeliveryIDs      []string `json:"delivery_ids"`
}

func (e eventIngestRespDTO) EffectiveEventID() string {
	if e.EventID != "" {
		return e.EventID
	}
	return e.ID
}

type deliveryDTO struct {
	ID           string     `json:"id"`
	EventID      string     `json:"event_id"`
	EndpointID   string     `json:"endpoint_id"`
	Status       string     `json:"status"`
	AttemptCount int        `json:"attempt_count"`
	MaxRetries   int        `json:"max_retries"`
	StatusCode   int        `json:"status_code"`
	ResponseTime int64      `json:"response_time_ms"`
	LastError    string     `json:"last_error"`
	NextRetryAt  *time.Time `json:"next_retry_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func doJSONRequest(t *testing.T, method, url string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		case []byte:
			bodyReader = bytes.NewReader(v)
		default:
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("failed to marshal request body: %v", err)
			}
			bodyReader = bytes.NewReader(b)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		t.Fatalf("failed to create request %s %s: %v", method, url, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s failed: %v", method, url, err)
	}
	respBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("failed reading response body from %s %s: %v", method, url, err)
	}
	return resp, respBytes
}

func mustCreateApp(t *testing.T, baseURL, id, name string) appDTO {
	t.Helper()
	payload := map[string]any{"name": name}
	if id != "" {
		payload["id"] = id
	}
	resp, body := doJSONRequest(t, http.MethodPost, baseURL+"/api/v1/apps", payload, nil)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 201 Created from POST /api/v1/apps, got %d: %s", resp.StatusCode, string(body))
	}
	var app appDTO
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatalf("failed to unmarshal App response: %v (body=%s)", err, string(body))
	}
	return app
}

func mustCreateEndpoint(t *testing.T, baseURL, appID, targetURL, secret string, eventTypes []string, maxRetries int) endpointDTO {
	t.Helper()
	payload := map[string]any{
		"url":         targetURL,
		"event_types": eventTypes,
	}
	if secret != "" {
		payload["secret"] = secret
	}
	if maxRetries > 0 {
		payload["max_retries"] = maxRetries
	}

	var route string
	if appID != "" {
		route = fmt.Sprintf("%s/api/v1/apps/%s/endpoints", baseURL, appID)
	} else {
		route = baseURL + "/api/v1/endpoints"
	}

	resp, body := doJSONRequest(t, http.MethodPost, route, payload, nil)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 201 Created from POST %s, got %d: %s", route, resp.StatusCode, string(body))
	}
	var ep endpointDTO
	if err := json.Unmarshal(body, &ep); err != nil {
		t.Fatalf("failed to unmarshal Endpoint response: %v (body=%s)", err, string(body))
	}
	return ep
}

func mustIngestEvent(t *testing.T, baseURL, appID, eventType string, payload any, idempotencyKey string) eventIngestRespDTO {
	t.Helper()
	return mustIngestEventWithHeaders(t, baseURL, appID, eventType, payload, idempotencyKey, nil)
}

func mustIngestEventWithHeaders(t *testing.T, baseURL, appID, eventType string, payload any, idempotencyKey string, headers map[string]string) eventIngestRespDTO {
	t.Helper()
	reqBody := map[string]any{
		"event_type": eventType,
		"payload":    payload,
	}
	if appID != "" {
		reqBody["app_id"] = appID
	}
	if idempotencyKey != "" {
		reqBody["idempotency_key"] = idempotencyKey
	}

	resp, body := doJSONRequest(t, http.MethodPost, baseURL+"/api/v1/events", reqBody, headers)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 202/200 from POST /api/v1/events, got %d: %s", resp.StatusCode, string(body))
	}
	var out eventIngestRespDTO
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("failed to unmarshal event ingest response: %v (body=%s)", err, string(body))
	}
	if out.EventID == "" && out.ID != "" {
		out.EventID = out.ID
	}
	if len(out.DeliveryIDs) == 0 && out.EventID != "" {
		dlvs := listDeliveries(t, baseURL, "?event_id="+out.EventID)
		for _, d := range dlvs {
			out.DeliveryIDs = append(out.DeliveryIDs, d.ID)
		}
		if out.DeliveriesQueued == 0 {
			out.DeliveriesQueued = len(out.DeliveryIDs)
		}
	}
	return out
}

func getDelivery(t *testing.T, baseURL, deliveryID string) (*http.Response, deliveryDTO) {
	t.Helper()
	resp, body := doJSONRequest(t, http.MethodGet, baseURL+"/api/v1/deliveries/"+deliveryID, nil, nil)
	var d deliveryDTO
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatalf("failed to unmarshal delivery: %v (body=%s)", err, string(body))
		}
	}
	return resp, d
}

func listDeliveries(t *testing.T, baseURL, query string) []deliveryDTO {
	t.Helper()
	resp, body := doJSONRequest(t, http.MethodGet, baseURL+"/api/v1/deliveries"+query, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/deliveries%s, got %d: %s", query, resp.StatusCode, string(body))
	}
	var list []deliveryDTO
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("failed to unmarshal deliveries list: %v (body=%s)", err, string(body))
	}
	return list
}

func listDLQ(t *testing.T, baseURL string) []deliveryDTO {
	t.Helper()
	resp, body := doJSONRequest(t, http.MethodGet, baseURL+"/api/v1/dlq", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/dlq, got %d: %s", resp.StatusCode, string(body))
	}
	var list []deliveryDTO
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("failed to unmarshal dlq list: %v (body=%s)", err, string(body))
	}
	return list
}

func waitForDeliveryStatus(t *testing.T, baseURL, deliveryID, expectedStatus string, timeout time.Duration) deliveryDTO {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last deliveryDTO
	for time.Now().Before(deadline) {
		resp, d := getDelivery(t, baseURL, deliveryID)
		if resp.StatusCode == http.StatusOK {
			last = d
			if d.Status == expectedStatus {
				return d
			}
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for delivery %s to reach status %q (last status=%q, attempts=%d, err=%q)",
		deliveryID, expectedStatus, last.Status, last.AttemptCount, last.LastError)
	return last
}

func scrapeMetrics(t *testing.T, baseURL string) string {
	t.Helper()
	resp, body := doJSONRequest(t, http.MethodGet, baseURL+"/metrics", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /metrics, got %d: %s", resp.StatusCode, string(body))
	}
	return string(body)
}

// parseMetricSum sums all values for lines beginning with metricName (ignoring comments).
func parseMetricSum(metricsText, metricName string) (float64, bool) {
	lines := strings.Split(metricsText, "\n")
	var sum float64
	var found bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, metricName) {
			rest := line[len(metricName):]
			if len(rest) > 0 && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '{' {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if val, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
					sum += val
					found = true
				}
			}
		}
	}
	return sum, found
}

// --- Harness Self-Check Test (Always Executes Even Pre-M3) ---

func TestHarnessSelfCheck(t *testing.T) {
	t.Run("SignAndVerifyValidHMACStdlib", func(t *testing.T) {
		secret := "whsec_harness_self_check"
		payload := []byte(`{"event":"invoice.paid","amount":4900}`)
		now := time.Now().Unix()

		sigHeader := signPayloadStdlib(secret, payload, now)
		tsHeader := strconv.FormatInt(now, 10)
		if err := verifyHMACStdlib(secret, sigHeader, tsHeader, payload, 5*time.Minute); err != nil {
			t.Fatalf("expected valid HMAC verification, got error: %v", err)
		}
	})

	t.Run("RejectExpiredAndFutureTimestamps", func(t *testing.T) {
		secret := "whsec_harness_self_check"
		payload := []byte(`{"event":"test"}`)

		expiredTS := time.Now().Add(-10 * time.Minute).Unix()
		expiredSig := signPayloadStdlib(secret, payload, expiredTS)
		if err := verifyHMACStdlib(secret, expiredSig, strconv.FormatInt(expiredTS, 10), payload, 5*time.Minute); err == nil {
			t.Fatal("expected expired timestamp to be rejected")
		}

		futureTS := time.Now().Add(10 * time.Minute).Unix()
		futureSig := signPayloadStdlib(secret, payload, futureTS)
		if err := verifyHMACStdlib(secret, futureSig, strconv.FormatInt(futureTS, 10), payload, 5*time.Minute); err == nil {
			t.Fatal("expected future timestamp to be rejected")
		}
	})

	t.Run("RejectTamperedBodyAndSingleBitFlipAndMalformedHeader", func(t *testing.T) {
		secret := "whsec_harness_self_check"
		payload := []byte(`{"amount":100}`)
		now := time.Now().Unix()
		tsStr := strconv.FormatInt(now, 10)
		sigHeader := signPayloadStdlib(secret, payload, now)

		// Tampered body
		if err := verifyHMACStdlib(secret, sigHeader, tsStr, []byte(`{"amount":999}`), 5*time.Minute); err == nil {
			t.Fatal("expected tampered body to fail verification")
		}

		// 1-bit / 1-nibble flipped hex
		lastChar := sigHeader[len(sigHeader)-1]
		flippedChar := byte('0')
		if lastChar == '0' {
			flippedChar = '1'
		}
		flippedSig := sigHeader[:len(sigHeader)-1] + string(flippedChar)
		if err := verifyHMACStdlib(secret, flippedSig, tsStr, payload, 5*time.Minute); err == nil {
			t.Fatal("expected single-nibble flipped signature to fail verification")
		}

		// Malformed headers
		for _, bad := range []string{"", "t=abc,v1=deadbeef", "v1=only", "t=1700000000,v1=zzz"} {
			if err := verifyHMACStdlib(secret, bad, "", payload, 5*time.Minute); err == nil {
				t.Fatalf("expected malformed header %q to fail verification", bad)
			}
		}
	})

	t.Run("WebhookCaptureServerSequence500_500_200AndHMACCapture", func(t *testing.T) {
		secret := "whsec_capture_test"
		srv := newWebhookCaptureServer(t, secret)
		srv.SetStatusSequence(http.StatusInternalServerError, http.StatusInternalServerError, http.StatusOK)

		payload := []byte(`{"id":"evt_123"}`)
		now := time.Now().Unix()
		sig := signPayloadStdlib(secret, payload, now)
		headers := map[string]string{
			"X-RelayHook-Signature": sig,
			"X-RelayHook-Timestamp": strconv.FormatInt(now, 10),
			"X-RelayHook-ID":        "dlv_test_1",
			"X-RelayHook-Event":     "order.created",
		}

		expectedCodes := []int{500, 500, 200}
		for i, wantCode := range expectedCodes {
			resp, _ := doJSONRequest(t, http.MethodPost, srv.URL, payload, headers)
			if resp.StatusCode != wantCode {
				t.Fatalf("attempt %d: expected status %d, got %d", i+1, wantCode, resp.StatusCode)
			}
		}

		captured := srv.WaitForRequests(t, 3, time.Second)
		for i, c := range captured {
			if !c.HMACValid {
				t.Fatalf("attempt %d: expected HMACValid=true, got false (%s)", i+1, c.HMACError)
			}
			if c.DeliveryID != "dlv_test_1" || c.EventType != "order.created" {
				t.Fatalf("attempt %d: unexpected captured metadata: %+v", i+1, c)
			}
		}
	})
}
