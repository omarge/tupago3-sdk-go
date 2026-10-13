package rest_test

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
	"github.com/omarge/tupago3-sdk-go/client/rest"
	sdkerrors "github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// testBackend is a configurable fake TUPAGO3 REST backend used to assert the
// SDK's REST adapter behaviour without any real egress.
type testBackend struct {
	t       *testing.T
	calls   map[string]*int32
	handler func(w http.ResponseWriter, r *http.Request)
}

func (b *testBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if c, ok := b.calls[key]; ok {
		atomic.AddInt32(c, 1)
	}
	if b.handler != nil {
		b.handler(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func newBackend(t *testing.T) *testBackend {
	return &testBackend{t: t, calls: map[string]*int32{}}
}

func (b *testBackend) count(method, path string) int {
	k := method + " " + path
	c, ok := b.calls[k]
	if !ok {
		return 0
	}
	return int(atomic.LoadInt32(c))
}

func (b *testBackend) expect(t *testing.T, method, path string) {
	k := method + " " + path
	b.calls[k] = new(int32)
	_ = t
}

func newTransport(t *testing.T, srv *httptest.Server, token string) *rest.Transport {
	tr, err := rest.NewTransport(&rest.Options{
		BaseURL:     srv.URL,
		Credentials: auth.StaticTokenProvider(token),
	})
	require.NoError(t, err)
	return tr
}

func TestREST_CreateQr_Success(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/msjpagoqrusuario")
	var gotBody []byte
	var gotIdem, gotAuth string
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotIdem = r.Header.Get("Idempotency-Key")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// backend3 wraps the raw Banxico result under "mensaje"
		_, _ = w.Write([]byte(`{"mensaje":{"qr":"https://pay.tupago/qr/abc","idCuenta":9223372036854775807},"emisor":"BANCO","banco":"BCM"}`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "jwt-token-xyz")

	resp, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta:       9223372036854775807,
		Monto:          123.45,
		Concepto:       "Pago",
		IdempotencyKey: "idem-123",
	})
	require.NoError(t, err)
	require.Equal(t, 1, b.count(http.MethodPost, "/api/payments/msjpagoqrusuario"), "exactly one outbound attempt")
	require.Equal(t, "idem-123", gotIdem, "idempotency key propagated verbatim")
	require.Equal(t, "Bearer jwt-token-xyz", gotAuth, "bearer token propagated")
	// raw payload must equal the mensaje field (gRPC parity), with exact int64
	require.Equal(t, `{"qr":"https://pay.tupago/qr/abc","idCuenta":9223372036854775807}`, resp.Json)
	// verify int64 survived the request body exactly
	var reqBody map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(gotBody, &reqBody))
	require.Equal(t, "9223372036854775807", strings.TrimSpace(string(reqBody["idCuenta"])))
}

func TestREST_CreateQr_NoToken_FailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr, err := rest.NewTransport(&rest.Options{BaseURL: srv.URL}) // no credentials
	require.NoError(t, err)
	_, err = tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsTupagoError(err))
}

func TestREST_CreateQr_IdempotencyRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{Monto: 1})
	require.Error(t, err)
	require.True(t, sdkerrors.IsTupagoError(err))
}

func TestREST_CreateQr_Conflict_409(t *testing.T) {
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict) // idempotency conflict
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.AlreadyExists))
	require.False(t, sdkerrors.IsRetryable(err))
}

func TestREST_CreateQr_PendingReconciliation_202(t *testing.T) {
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"PENDING"}`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.CreateQr(context.Background(), &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsPendingReconciliation(err))
	require.False(t, sdkerrors.IsRetryable(err))
}

func TestREST_CreateQr_NetworkAmbiguity_UnknownOutcome(t *testing.T) {
	// A handler that accepts the connection but never responds forces the client
	// context to deadline; per the financial law this MUST map to UnknownOutcome
	// (reconcile, never blind-resubmit), not request-not-sent.
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := tr.CreateQr(ctx, &v1.CreateQrRequest{IdempotencyKey: "k"})
	require.Error(t, err)
	require.True(t, sdkerrors.IsUnknownOutcome(err), "expected UnknownOutcome, got %v", err)
	require.False(t, sdkerrors.IsRequestNotSent(err), "ambiguous send must NOT be request-not-sent")
}

func TestREST_CreateTelefonico_Success(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/msjpagotelefonicousuario")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// telefonico endpoint returns the raw result directly (no mensaje wrapper)
		_, _ = w.Write([]byte(`{"ref":"TEL-123","numeroCelular":5512345678}`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	resp, err := tr.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key:            "k1",
		Monto:          50,
		NumeroCelular:  "5512345678",
		IdempotencyKey: "idem-tel",
	})
	require.NoError(t, err)
	require.Equal(t, 1, b.count(http.MethodPost, "/api/payments/msjpagotelefonicousuario"))
	require.Equal(t, `{"ref":"TEL-123","numeroCelular":5512345678}`, resp.Json)
}

func TestREST_GetQrStatus_Success(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/estatusmsjqr")
	var gotBody []byte
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"status":"ACTIVE","idc":"IDC1"}]`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	resp, err := tr.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 42})
	require.NoError(t, err)
	require.Equal(t, `[{"status":"ACTIVE","idc":"IDC1"}]`, resp.Json)
	require.Contains(t, string(gotBody), `"idc":"IDC1"`)
	require.Contains(t, string(gotBody), `"idCuenta":42`)
}

func TestREST_GetTelefonicoStatus_Success(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/estatusmsjcobrotelefonicousuario")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"PAID"}`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	resp, err := tr.GetTelefonicoStatus(context.Background(), &v1.GetStatusRequest{Idc: "COBRO1", IdCuenta: 7})
	require.NoError(t, err)
	require.Equal(t, `{"status":"PAID"}`, resp.Json)
}

func TestREST_GetCliente_Composition_Int64Exact(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodGet, "/api/clientes/99")
	b.expect(t, http.MethodGet, "/api/catalogo-institucions/clave/BCM")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/clientes/99":
			// exact max int64 id must survive
			_, _ = w.Write([]byte(`{"id":9223372036854775807,"nombre":"Cliente Demo","claveInstitucion":"BCM","key":"k1"}`))
		case "/api/catalogo-institucions/clave/BCM":
			_, _ = w.Write([]byte(`{"id":7,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	perfil, err := tr.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 99})
	require.NoError(t, err)
	require.Equal(t, int64(9223372036854775807), perfil.Cliente.Id, "int64 identity must be exact")
	require.Equal(t, "BCM", perfil.Cliente.ClaveInstitucion)
	require.NotNil(t, perfil.CatalogoInstitucion)
	require.Equal(t, "BCM", perfil.CatalogoInstitucion.ClaveInstitucion)
	require.Equal(t, "Banco", perfil.CatalogoInstitucion.NombreCorto)
}

func TestREST_GetCatalogo_Int64Exact(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodGet, "/api/catalogo-institucions/clave/BCM")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":9007199254740993,"claveInstitucion":"BCM","nombreCorto":"Banco"}`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	cat, err := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, int64(9007199254740993), cat.Id, "int64 identity must be exact (past MAX_SAFE_INTEGER)")
	require.Equal(t, "BCM", cat.ClaveInstitucion)
}

func TestREST_GetCliente_Malformed_FailClosed(t *testing.T) {
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	require.True(t, sdkerrors.IsTupagoError(err))
}

func TestREST_ReadTransient_UnavailableRetryable(t *testing.T) {
	// At the transport level a transient 5xx must surface as a retryable TupagoError.
	// The bounded retry itself is applied by PaymentClient (see client integration).
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/estatusmsjqr")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "X"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unavailable))
	require.True(t, sdkerrors.IsRetryable(err))
	require.Equal(t, 1, b.count(http.MethodPost, "/api/payments/estatusmsjqr"), "transport makes exactly one outbound attempt; retry is a PaymentClient concern")
}

func TestREST_ReadNonRetryable_Immediate(t *testing.T) {
	b := newBackend(t)
	b.expect(t, http.MethodPost, "/api/payments/estatusmsjqr")
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "X"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.NotFound))
	require.False(t, sdkerrors.IsRetryable(err))
	require.Equal(t, 1, b.count(http.MethodPost, "/api/payments/estatusmsjqr"), "non-retryable must not retry")
}

func TestREST_ContextCancelled(t *testing.T) {
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tr.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
}

func TestREST_Unauthorized_401(t *testing.T) {
	b := newBackend(t)
	b.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := httptest.NewServer(b)
	defer srv.Close()
	tr := newTransport(t, srv, "tok")
	_, err := tr.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	require.True(t, sdkerrors.HasGRPCCode(err, codes.Unauthenticated))
}
