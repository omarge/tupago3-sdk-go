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

// fakeGraphQLBackend implements the backend3 GraphQL endpoint used by the SDK
// adapter. It speaks the GraphQL-over-HTTP wire format ({"data":...}/{"errors":...}).
type fakeGraphQLBackend struct {
	calls    int32
	lastAuth string
	lastOp   string
}

func (b *fakeGraphQLBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&b.calls, 1)
	b.lastAuth = r.Header.Get("Authorization")
	body, _ := io.ReadAll(r.Body)
	var req struct {
		OperationName string `json:"operationName"`
	}
	_ = json.Unmarshal(body, &req)
	b.lastOp = req.OperationName

	w.Header().Set("Content-Type", "application/json")
	switch req.OperationName {
	case "createPagoQr":
		_, _ = w.Write([]byte(`{"data":{"createPagoQr":{"qr":"https://pay.tupago/qr/abc"},"emisor":"B"}}`))
	case "createPagoTelefonico":
		_, _ = w.Write([]byte(`{"data":{"createPagoTelefonico":{"ref":"TEL-123"}}}`))
	case "pagoQrEstatusByCuenta":
		_, _ = w.Write([]byte(`{"data":{"pagoQrEstatusByCuenta":[{"status":"ACTIVE","idc":"IDC1"}]}}`))
	case "pagoTelefonicoEstatusByCuenta":
		_, _ = w.Write([]byte(`{"data":{"pagoTelefonicoEstatusByCuenta":{"status":"PAID"}}}`))
	case "cliente":
		_, _ = w.Write([]byte(`{"data":{"cliente":{"cliente":{"id":"9223372036854775807","nombre":"Demo","claveInstitucion":"BCM","key":"k1"},"catalogoInstitucion":{"id":"7","claveInstitucion":"BCM","nombreCorto":"Banco"}}}}`))
	case "catalogoInstitucion":
		_, _ = w.Write([]byte(`{"data":{"catalogoInstitucion":{"id":"7","claveInstitucion":"BCM","nombreCorto":"Banco"}}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"message":"NOT_FOUND","extensions":{"code":"NOT_FOUND","classification":"not_found"}}]}`))
	}
}

func newGraphQLClient(t *testing.T, b *fakeGraphQLBackend) *client.PaymentClient {
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      srv.URL,
		Insecure:    true, // loopback plaintext permitted
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: srv.URL},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestGraphQLClient_C1_C2_Create(t *testing.T) {
	b := &fakeGraphQLBackend{}
	c := newGraphQLClient(t, b)

	qr, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 9223372036854775807, Monto: 10, IdempotencyKey: "idem-qr"})
	require.NoError(t, err)
	require.Equal(t, `{"qr":"https://pay.tupago/qr/abc"}`, qr.Json)
	require.Equal(t, 1, int(b.calls), "create is exactly one attempt")
	require.Equal(t, "Bearer tok", b.lastAuth, "bearer token propagated")

	tel, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{Key: "k", Monto: 5, NumeroCelular: "5512345678", IdempotencyKey: "idem-tel"})
	require.NoError(t, err)
	require.Equal(t, `{"ref":"TEL-123"}`, tel.Json)
}

func TestGraphQLClient_C3_C4_Status(t *testing.T) {
	b := &fakeGraphQLBackend{}
	c := newGraphQLClient(t, b)
	qr, err := c.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 42})
	require.NoError(t, err)
	require.Equal(t, `[{"status":"ACTIVE","idc":"IDC1"}]`, qr.Json)
	tel, err := c.GetTelefonicoStatus(context.Background(), &v1.GetStatusRequest{Idc: "COBRO1", IdCuenta: 7})
	require.NoError(t, err)
	require.Equal(t, `{"status":"PAID"}`, tel.Json)
}

func TestGraphQLClient_C5_C6_Reference_Int64(t *testing.T) {
	b := &fakeGraphQLBackend{}
	c := newGraphQLClient(t, b)
	perfil, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 99})
	require.NoError(t, err)
	require.Equal(t, int64(9223372036854775807), perfil.Cliente.Id, "int64 exact")
	require.Equal(t, "BCM", perfil.CatalogoInstitucion.ClaveInstitucion)

	cat, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, "BCM", cat.ClaveInstitucion)
	require.Equal(t, "Banco", cat.NombreCorto)
}

func TestGraphQLClient_Create_NetworkAmbiguity_UnknownOutcome(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "graphql",
		Credentials: auth.StaticTokenProvider("tok"), GraphQL: &client.GraphQLOptions{EndpointURL: srv.URL},
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

func TestGraphQLClient_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target: srv.URL, Insecure: true, Transport: "graphql",
		Credentials: auth.StaticTokenProvider("tok"), GraphQL: &client.GraphQLOptions{EndpointURL: srv.URL},
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, errors.HasGRPCCode(err, codes.Unauthenticated))
}

func TestGraphQLClient_RejectsNonLoopbackPlaintext(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "pay.tupago.mx:443",
		Insecure:    true,
		Transport:   "graphql",
		Credentials: auth.StaticTokenProvider("tok"),
		GraphQL:     &client.GraphQLOptions{EndpointURL: "http://pay.tupago.mx"},
	})
	require.Error(t, err, "non-loopback plaintext must be rejected (fail-closed)")
	require.True(t, strings.Contains(err.Error(), "loopback") || strings.Contains(err.Error(), "TLS"))
}
