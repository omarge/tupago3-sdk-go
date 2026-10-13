package graphql_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client/graphql"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// fakeGQL is a configurable fake TUPAGO3 GraphQL backend. It validates the SDK's
// GraphQL adapter behaviour without any real egress.
type fakeGQL struct {
	t        *testing.T
	calls    int32
	lastAuth string
	lastOp   string
	lastVars map[string]interface{}
	handler  func(w http.ResponseWriter, r *http.Request)
}

func (b *fakeGQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&b.calls, 1)
	b.lastAuth = r.Header.Get("Authorization")
	body, _ := io.ReadAll(r.Body)
	var req struct {
		OperationName string                 `json:"operationName"`
		Variables     map[string]interface{} `json:"variables"`
	}
	_ = json.Unmarshal(body, &req)
	b.lastOp = req.OperationName
	b.lastVars = req.Variables
	b.handler(w, r)
}

func (b *fakeGQL) count() int { return int(atomic.LoadInt32(&b.calls)) }

func newGQL(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) (*fakeGQL, *httptest.Server) {
	b := &fakeGQL{t: t, handler: h}
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)
	return b, srv
}

func newTransport(t *testing.T, srv *httptest.Server, token string) *graphql.Transport {
	tr, err := graphql.NewTransport(&graphql.Options{
		BaseURL:     srv.URL,
		Insecure:    true, // loopback plaintext permitted
		Credentials: auth.StaticTokenProvider(token),
	})
	require.NoError(t, err)
	return tr
}

func gqlData(op string, payload string) string {
	return `{"data":{"` + op + `":` + payload + `}}`
}

func gqlError(code, classification, message string) string {
	return `{"errors":[{"message":"` + message + `","extensions":{"code":"` + code + `","classification":"` + classification + `"}}]}`
}

func TestGraphQL_CreateQr_Success(t *testing.T) {
	b, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlData("createPagoQr", `{"qr":"https://pay.tupago/qr/abc","idCuenta":9223372036854775807}`)))
	})
	tr := newTransport(t, srv, "jwt-xyz")

	resp, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta:       9223372036854775807,
		Monto:          123.45,
		IdempotencyKey: "idem-123",
	})
	require.NoError(t, err)
	require.Equal(t, 1, b.count(), "exactly one outbound attempt")
	require.Equal(t, "Bearer jwt-xyz", b.lastAuth, "bearer token propagated")
	require.Equal(t, `{"qr":"https://pay.tupago/qr/abc","idCuenta":9223372036854775807}`, resp.Json, "raw payload parity (gRPC/REST)")
	require.Equal(t, "createPagoQr", b.lastOp)
	// idCuenta must be emitted as a JSON string (GraphQL ID, int64 law)
	in := b.lastVars["input"].(map[string]interface{})
	require.Equal(t, "9223372036854775807", in["idCuenta"], "int64 idCuenta as GraphQL ID string")
	require.Equal(t, "idem-123", b.lastVars["idempotencyKey"], "idempotency key preserved verbatim")
}

func TestGraphQL_CreateQr_NoToken_FailClosed(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {})
	tr, err := graphql.NewTransport(&graphql.Options{BaseURL: srv.URL, Insecure: true}) // no credentials
	require.NoError(t, err)
	_, err = tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsTupagoError(err))
}

func TestGraphQL_CreateQr_IdempotencyRequired(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {})
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{Monto: 1})
	require.Error(t, err)
	require.True(t, sdkerrors.IsTupagoError(err))
}

func TestGraphQL_CreateQr_PendingReconciliation(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlError("PAYMENT_PENDING_RECONCILIATION", "accepted", "PAYMENT_PENDING_RECONCILIATION")))
	})
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsPendingReconciliation(err))
	require.False(t, sdkerrors.IsRetryable(err))
}

func TestGraphQL_CreateQr_IdempotencyConflict(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlError("IDEMPOTENCY_CONFLICT", "conflict", "IDEMPOTENCY_CONFLICT")))
	})
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.AlreadyExists))
	require.False(t, sdkerrors.IsRetryable(err))
}

func TestGraphQL_CreateQr_NetworkAmbiguity_UnknownOutcome(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	})
	tr := newTransport(t, srv, "tok")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := tr.CreateQr(ctx, &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err), "ambiguous send must NOT be request-not-sent")
}

func TestGraphQL_GetCliente_Int64Exact(t *testing.T) {
	b, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlData("cliente", `{"cliente":{"id":"9223372036854775807","nombre":"Demo","claveInstitucion":"BCM","key":"k1"},"catalogoInstitucion":{"id":"7","claveInstitucion":"BCM","nombreCorto":"Banco"}}`)))
	})
	tr := newTransport(t, srv, "tok")
	perfil, err := tr.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 99})
	require.NoError(t, err)
	require.Equal(t, int64(9223372036854775807), perfil.Cliente.Id, "int64 identity must be exact")
	require.Equal(t, "BCM", perfil.Cliente.ClaveInstitucion)
	require.NotNil(t, perfil.CatalogoInstitucion)
	require.Equal(t, "BCM", perfil.CatalogoInstitucion.ClaveInstitucion)
	require.Equal(t, "Banco", perfil.CatalogoInstitucion.NombreCorto)
	require.Equal(t, "cliente", b.lastOp)
}

func TestGraphQL_GetCliente_NotFound(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"cliente":null}}`))
	})
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.NotFound))
}

func TestGraphQL_GetCatalogo_Int64Exact(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlData("catalogoInstitucion", `{"id":"9007199254740993","claveInstitucion":"BCM","nombreCorto":"Banco"}`)))
	})
	tr := newTransport(t, srv, "tok")
	cat, err := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, int64(9007199254740993), cat.Id, "int64 identity must be exact (past MAX_SAFE_INTEGER)")
	require.Equal(t, "BCM", cat.ClaveInstitucion)
}

func TestGraphQL_GetQrStatus_Success(t *testing.T) {
	b, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlData("pagoQrEstatusByCuenta", `[{"status":"ACTIVE","idc":"IDC1"}]`)))
	})
	tr := newTransport(t, srv, "tok")
	resp, err := tr.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 42})
	require.NoError(t, err)
	require.Equal(t, `[{"status":"ACTIVE","idc":"IDC1"}]`, resp.Json)
	require.Equal(t, "pagoQrEstatusByCuenta", b.lastOp)
}

func TestGraphQL_GetTelefonicoStatus_Success(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(gqlData("pagoTelefonicoEstatusByCuenta", `{"status":"PAID"}`)))
	})
	tr := newTransport(t, srv, "tok")
	resp, err := tr.GetTelefonicoStatus(context.Background(), &v1.GetStatusRequest{Idc: "COBRO1", IdCuenta: 7})
	require.NoError(t, err)
	require.Equal(t, `{"status":"PAID"}`, resp.Json)
}

func TestGraphQL_Unauthorized_401(t *testing.T) {
	_, srv := newGQL(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unauthenticated))
}
