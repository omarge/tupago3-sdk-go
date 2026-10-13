package rest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/omarge/tupago3-sdk-go/auth"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/stretchr/testify/require"
)

// errSimulatedWriteFailure models a write failure on a reused keep-alive connection.
var errSimulatedWriteFailure = errors.New("simulated write failure on reused connection")

// failWriteConn fails the FIRST write that contains marker (exactly once, globally per
// test), returning (0, err). This reproduces the pre-write connection failure that net/http
// treats as retryable for a replayable request. After the first failure, all writes succeed
// so any net/http retry actually reaches the server (proving a transparent replay occurred).
type failWriteConn struct {
	net.Conn
	buf        []byte
	failed     bool
	failedOnce *int32
	marker     string
}

func (c *failWriteConn) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	// Only fail the first write whose accumulated bytes contain the financial-create
	// marker; the CompareAndSwap must run AFTER the marker check so it does not fire on
	// a preceding header-only write and disable the real failure.
	if !c.failed && bytes.Contains(c.buf, []byte(c.marker)) && atomic.CompareAndSwapInt32(c.failedOnce, 0, 1) {
		c.failed = true
		return 0, errSimulatedWriteFailure
	}
	return c.Conn.Write(p)
}

// recordRT is a RoundTripper that captures the outbound request (including body and
// GetBody) and returns a stub 200 so the SDK parse path runs.
type recordRT struct {
	mu       sync.Mutex
	lastReq  *http.Request
	lastBody []byte
	respBody string
}

func (r *recordRT) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.mu.Lock()
	r.lastReq = req
	r.lastBody = body
	r.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(r.respBody)),
		Request:    req,
	}, nil
}

// P0-HTTP-07 (structural, C2): CreateTelefonico must also be non-replayable.
func TestREST_CreateTelefonico_RequestGetBodyNil_Structural(t *testing.T) {
	tr, err := NewTransport(&Options{
		BaseURL:     "http://127.0.0.1:8080",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	rt := &recordRT{respBody: `{"mensaje":"x"}`}
	tr.hc.Transport = rt

	_, cerr := tr.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-tel-structural",
	})
	require.NoError(t, cerr)

	rt.mu.Lock()
	req := rt.lastReq
	rt.mu.Unlock()
	require.NotNil(t, req)
	require.Equal(t, http.MethodPost, req.Method)
	require.NotNil(t, req.Body)
	require.Greater(t, req.ContentLength, int64(0))
	require.Equal(t, "idem-tel-structural", req.Header.Get("Idempotency-Key"), "Idempotency-Key must remain present and verbatim")
	require.Nil(t, req.GetBody, "financial create must not be replayable: req.GetBody must be nil")
}

// P0-HTTP-07 (structural): a financial CREATE request must NOT be replayable by net/http.
// bytes.NewReader + http.NewRequestWithContext auto-populates req.GetBody; we must null it.
func TestREST_CreateQr_RequestGetBodyNil_Structural(t *testing.T) {
	tr, err := NewTransport(&Options{
		BaseURL:     "http://127.0.0.1:8080",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	rt := &recordRT{respBody: `{"mensaje":"x"}`}
	tr.hc.Transport = rt

	_, cerr := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-structural",
	})
	require.NoError(t, cerr)

	rt.mu.Lock()
	req := rt.lastReq
	rt.mu.Unlock()
	require.NotNil(t, req)
	require.Equal(t, http.MethodPost, req.Method)
	require.NotNil(t, req.Body)
	require.Greater(t, req.ContentLength, int64(0))
	require.Equal(t, "idem-structural", req.Header.Get("Idempotency-Key"), "Idempotency-Key must remain present and verbatim")
	require.Nil(t, req.GetBody, "financial create must not be replayable: req.GetBody must be nil")
}

// P0-HTTP-07 (control): reads that carry a body MUST keep GetBody populated so SDK
// read retries keep working. (A body-less GET has GetBody==nil naturally; we use a
// POST read with a body, GetQrStatus, to prove the fix only nulls GetBody for creates.)
func TestREST_Read_RequestGetBodyPopulated(t *testing.T) {
	tr, err := NewTransport(&Options{
		BaseURL:     "http://127.0.0.1:8080",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	rt := &recordRT{respBody: `{"id":1,"claveInstitucion":"BCM","nombreCorto":"x"}`}
	tr.hc.Transport = rt

	_, err = tr.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "x", IdCuenta: 1})
	require.NoError(t, err)

	rt.mu.Lock()
	req := rt.lastReq
	rt.mu.Unlock()
	require.NotNil(t, req)
	require.Empty(t, req.Header.Get("Idempotency-Key"), "reads must not carry an Idempotency-Key header")
	require.NotNil(t, req.GetBody, "reads with a body must remain replayable for SDK bounded read retry")
}

// P0-HTTP-07 (adversarial): on a reused keep-alive connection, a write failure of the
// financial create must NOT cause net/http to transparently replay the POST beneath our
// no-retry policy. This test FAILS against candidate 8931210 (GetBody populated + Idempotency-Key
// header => net/http replays) and PASSES once req.GetBody is nulled for creates.
func TestREST_CreateQr_NoNativeReplay_ReusedConn(t *testing.T) {
	var failedOnce int32
	var createReceives int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isCreate := r.Method == http.MethodPost && strings.Contains(r.URL.Path, "msjpagoqrusuario")
		if isCreate {
			atomic.AddInt32(&createReceives, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if isCreate {
			_, _ = w.Write([]byte(`{"mensaje":"replayed"}`))
		} else {
			_, _ = w.Write([]byte(`{"id":1,"claveInstitucion":"BCM","nombreCorto":"x"}`))
		}
	}))
	defer srv.Close()

	tr, err := NewTransport(&Options{
		BaseURL:     srv.URL,
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)

	transport := tr.hc.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, derr := net.Dial(network, addr)
		if derr != nil {
			return nil, derr
		}
		return &failWriteConn{Conn: c, failedOnce: &failedOnce, marker: "msjpagoqrusuario"}, nil
	}

	// Warm-up a keep-alive connection so the financial create genuinely reuses it.
	_, werr := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, werr)

	_, cerr := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-replay",
	})

	// After the fix: the SDK issues exactly ONE create attempt; net/http must NOT
	// transparently replay it beneath our no-retry policy. The single attempt's write
	// failed and is NOT resent, so the server receives the create ZERO times and the
	// SDK surfaces an error rather than a hidden success.
	require.Error(t, cerr, "single failed create attempt must surface an error, not a hidden success")
	require.Equal(t, int32(0), atomic.LoadInt32(&createReceives),
		"FIXED: net/http must NOT transparently replay the financial create on a reused connection")
}
