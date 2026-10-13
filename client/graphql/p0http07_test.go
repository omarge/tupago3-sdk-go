package graphql

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

var errSimulatedWriteFailureGQL = errors.New("simulated write failure on reused connection")

type failWriteConnGQL struct {
	net.Conn
	buf        []byte
	failed     bool
	failedOnce *int32
	marker     string
}

func (c *failWriteConnGQL) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	// Only fail the first write whose accumulated bytes contain the financial-create
	// marker; the CompareAndSwap must run AFTER the marker check so it does not fire on
	// a preceding header-only write and disable the real failure.
	if !c.failed && bytes.Contains(c.buf, []byte(c.marker)) && atomic.CompareAndSwapInt32(c.failedOnce, 0, 1) {
		c.failed = true
		return 0, errSimulatedWriteFailureGQL
	}
	return c.Conn.Write(p)
}

type recordRTGQL struct {
	mu       sync.Mutex
	lastReq  *http.Request
	lastBody []byte
	respBody string
}

func (r *recordRTGQL) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
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

// P0-HTTP-07 (structural): a GraphQL financial CREATE must not be replayable by net/http.
// The idempotency travels in the GraphQL variables (not the HTTP Idempotency-Key header),
// so it was not replayable by default; we additionally null GetBody for defense in depth.
func TestGraphQL_CreateQr_RequestGetBodyNil_Structural(t *testing.T) {
	tr, err := NewTransport(&Options{
		BaseURL:     "http://127.0.0.1:8080",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	rt := &recordRTGQL{respBody: `{"data":{"createPagoQr":"x"}}`}
	tr.hc.Transport = rt

	_, cerr := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-structural",
	})
	require.NoError(t, cerr)

	rt.mu.Lock()
	req := rt.lastReq
	body := rt.lastBody
	rt.mu.Unlock()
	require.NotNil(t, req)
	require.Equal(t, http.MethodPost, req.Method)
	require.NotNil(t, req.Body)
	require.Greater(t, req.ContentLength, int64(0))
	require.Empty(t, req.Header.Get("Idempotency-Key"),
		"GraphQL carries idempotency in variables, never the HTTP Idempotency-Key header")
	require.Nil(t, req.GetBody, "financial create must not be replayable: req.GetBody must be nil")
	require.Contains(t, string(body), "idem-structural", "GraphQL idempotency variable must remain present in payload")
}

// P0-HTTP-07 (control): GraphQL reads MUST keep GetBody populated so SDK read retries work.
func TestGraphQL_Read_RequestGetBodyPopulated(t *testing.T) {
	tr, err := NewTransport(&Options{
		BaseURL:     "http://127.0.0.1:8080",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider("tok"),
	})
	require.NoError(t, err)
	rt := &recordRTGQL{respBody: `{"data":{"catalogoInstitucion":{"id":1,"claveInstitucion":"BCM","nombreCorto":"x"}}}`}
	tr.hc.Transport = rt

	_, err = tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)

	rt.mu.Lock()
	req := rt.lastReq
	rt.mu.Unlock()
	require.NotNil(t, req)
	require.NotNil(t, req.GetBody, "reads must remain replayable for SDK bounded read retry")
}

// P0-HTTP-07 (adversarial): on a reused keep-alive connection, a write failure of the
// GraphQL financial create must NOT cause net/http to transparently replay the POST. This
// test FAILS against candidate 8931210 and PASSES once req.GetBody is nulled for creates.
func TestGraphQL_CreateQr_NoNativeReplay_ReusedConn(t *testing.T) {
	var failedOnce int32
	var createReceives int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		isCreate := r.Method == http.MethodPost && bytes.Contains(body, []byte("createPagoQr"))
		if isCreate {
			atomic.AddInt32(&createReceives, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if isCreate {
			_, _ = w.Write([]byte(`{"data":{"createPagoQr":"replayed"}}`))
		} else {
			_, _ = w.Write([]byte(`{"data":{"catalogoInstitucion":{"id":1,"claveInstitucion":"BCM","nombreCorto":"x"}}}`))
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
		return &failWriteConnGQL{Conn: c, failedOnce: &failedOnce, marker: "createPagoQr"}, nil
	}

	// Warm-up a keep-alive connection so the financial create genuinely reuses it.
	_, werr := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, werr)

	_, cerr := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idem-replay",
	})

	// After the fix: the SDK issues exactly ONE create attempt; net/http must NOT
	// transparently replay it. The single attempt's write failed and is NOT resent.
	require.Error(t, cerr, "single failed create attempt must surface an error, not a hidden success")
	require.Equal(t, int32(0), atomic.LoadInt32(&createReceives),
		"FIXED: net/http must NOT transparently replay the GraphQL financial create on a reused connection")
}
