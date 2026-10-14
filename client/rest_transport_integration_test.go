package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// fakeRESTBackend implements the backend3 REST routes used by the SDK adapter.
type fakeRESTBackend struct {
	calls      map[string]*int32
	qrTries    *int32 // for transient-then-success on QR status
	lastIdem   string
	lastAuth   string
	lastQRBody []byte
}

func newFakeREST() *fakeRESTBackend {
	return &fakeRESTBackend{calls: map[string]*int32{}, qrTries: new(int32)}
}

func (b *fakeRESTBackend) count(path string) int {
	c, ok := b.calls[path]
	if !ok {
		return 0
	}
	return int(atomic.LoadInt32(c))
}

func (b *fakeRESTBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path
	if c, ok := b.calls[key]; ok {
		atomic.AddInt32(c, 1)
	} else {
		b.calls[key] = new(int32)
		atomic.StoreInt32(b.calls[key], 1)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(key, "/msjpagoqrusuario"):
		b.lastIdem = r.Header.Get("Idempotency-Key")
		b.lastAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		b.lastQRBody = body
		_, _ = w.Write([]byte(`{"mensaje":{"qr":"https://pay.tupago/qr/abc"},"emisor":"B","banco":"BCM"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(key, "/msjpagotelefonicousuario"):
		_, _ = w.Write([]byte(`{"ref":"TEL-123"}`))
	case r.Method == http.MethodPost && strings.HasSuffix(key, "/estatusmsjqr"):
		if atomic.AddInt32(b.qrTries, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"status":"ACTIVE","idc":"IDC1"}]`))
	case r.Method == http.MethodPost && strings.HasSuffix(key, "/estatusmsjcobrotelefonico"):
		_, _ = w.Write([]byte(`{"status":"PAID"}`))
	case r.Method == http.MethodGet && strings.HasPrefix(key, "/api/clientes/"):
		_, _ = w.Write([]byte(`{"id":9223372036854775807,"nombre":"Demo","claveInstitucion":"BCM","key":"k1"}`))
	case r.Method == http.MethodGet && strings.HasPrefix(key, "/api/catalogo-institucions/clave/"):
		_, _ = w.Write([]byte(`{"id":7,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newRESTClient(t *testing.T, b *fakeRESTBackend) *client.PaymentClient {
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Insecure:    true, // loopback plaintext permitted
		Transport:   "rest",
		Credentials: auth.StaticTokenProvider("tok"),
		REST:        &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRESTClient_C1_C2_Create(t *testing.T) {
	b := newFakeREST()
	c := newRESTClient(t, b)
	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 9223372036854775807, Monto: 10, IdempotencyKey: "idem-qr"})
	require.NoError(t, err)
	require.Equal(t, `{"qr":"https://pay.tupago/qr/abc"}`, qr.Json)
	require.Equal(t, 1, b.count("/api/payments/msjpagoqrusuario"), "create is exactly one attempt")
	require.Equal(t, "idem-qr", b.lastIdem, "idempotency key preserved verbatim")
	require.Equal(t, "Bearer tok", b.lastAuth, "bearer token propagated")
	var rb map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b.lastQRBody, &rb))
	require.Equal(t, "9223372036854775807", strings.TrimSpace(string(rb["idCuenta"])), "int64 idCuenta exact on wire")

	tel, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-tel"})
	require.NoError(t, err)
	require.Equal(t, `{"ref":"TEL-123"}`, tel.Json)
	require.Equal(t, 1, b.count("/api/payments/msjpagotelefonicousuario"))
}

func TestRESTClient_C3_C4_Status(t *testing.T) {
	b := newFakeREST()
	c := newRESTClient(t, b)
	qr, err := c.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 42})
	require.NoError(t, err)
	require.Equal(t, `[{"status":"ACTIVE","idc":"IDC1"}]`, qr.Json)
	tel, err := c.GetTelefonicoStatus(context.Background(), &v1.GetStatusRequest{Idc: "COBRO1", IdCuenta: 7})
	require.NoError(t, err)
	require.Equal(t, `{"status":"PAID"}`, tel.Json)
}

func TestRESTClient_C5_C6_Reference_Int64(t *testing.T) {
	b := newFakeREST()
	c := newRESTClient(t, b)
	perfil, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 99})
	require.NoError(t, err)
	require.Equal(t, int64(9223372036854775807), perfil.Cliente.Id, "int64 exact")
	require.Equal(t, "BCM", perfil.CatalogoInstitucion.ClaveInstitucion)

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, "BCM", cat.ClaveInstitucion)
	require.Equal(t, "Banco", cat.NombreCorto)
}

func TestRESTClient_ReadRetry_ExactAttempts(t *testing.T) {
	b := newFakeREST()
	c := newRESTClient(t, b)
	resp, err := c.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "X"})
	require.NoError(t, err)
	require.Equal(t, `[{"status":"ACTIVE","idc":"IDC1"}]`, resp.Json)
	require.Equal(t, 2, b.count("/api/payments/estatusmsjqr"), "transient 503 then 200 => exactly 2 attempts")
}

func TestRESTClient_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "rest",
		Credentials: auth.StaticTokenProvider("tok"), REST: &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
}

func TestRESTClient_Create_NetworkAmbiguity_UnknownOutcome(t *testing.T) {
	// Server accepts but never responds; client deadline -> UnknownOutcome.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "rest",
		Credentials: auth.StaticTokenProvider("tok"), REST: &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.CreateQr(ctx, &v1.CreateQrRequest{IdCuenta: 1, Monto: 1, IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, errors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, errors.IsRequestNotSent(err))
}

func TestRESTClient_Create_PendingReconciliation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"PENDING"}`))
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "rest",
		Credentials: auth.StaticTokenProvider("tok"), REST: &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 1, IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, errors.IsPendingReconciliation(err))
	require.False(t, errors.IsRetryable(err))
}

func TestRESTClient_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "rest",
		Credentials: auth.StaticTokenProvider("tok"), REST: &client.RESTOptions{BaseURL: srv.URL},
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, errors.HasGRPCCode(err, codes.Unauthenticated))
}
