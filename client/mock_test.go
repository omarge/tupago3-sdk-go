package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// MockServer is an in-memory PaymentService implementation for tests. It counts
// invocations, records auth headers and idempotency keys, enforces optional
// auth, injects latency and per-method errors, and never performs egress.
type MockServer struct {
	v1.UnimplementedPaymentServiceServer

	mu sync.Mutex

	calls    map[string]int
	lastAuth string
	authReq  bool
	validTok string

	qrKeys  []string
	telKeys []string

	latency time.Duration

	failN    map[string]int
	failCode map[string]codes.Code

	errOverride map[string]error
}

func NewMockServer() *MockServer {
	return &MockServer{
		calls:       map[string]int{},
		failN:       map[string]int{},
		failCode:    map[string]codes.Code{},
		errOverride: map[string]error{},
	}
}

func (m *MockServer) SetAuthRequired(validToken string) {
	m.mu.Lock()
	m.authReq = true
	m.validTok = validToken
	m.mu.Unlock()
}

func (m *MockServer) SetLatency(d time.Duration) {
	m.mu.Lock()
	m.latency = d
	m.mu.Unlock()
}

// FailTimes injects `n` failures of `code` for the given method.
func (m *MockServer) FailTimes(method string, n int, code codes.Code) {
	m.mu.Lock()
	m.failN[method] = n
	m.failCode[method] = code
	m.mu.Unlock()
}

// OverrideError forces an exact error for a method.
func (m *MockServer) OverrideError(method string, err error) {
	m.mu.Lock()
	m.errOverride[method] = err
	m.mu.Unlock()
}

func (m *MockServer) Calls(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[method]
}

func (m *MockServer) LastAuth() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastAuth
}

func (m *MockServer) QrKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.qrKeys))
	copy(out, m.qrKeys)
	return out
}

func (m *MockServer) TelKeys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.telKeys))
	copy(out, m.telKeys)
	return out
}

func (m *MockServer) begin(ctx context.Context, method string) error {
	m.mu.Lock()
	m.calls[method]++
	m.mu.Unlock()

	if m.authReq {
		md, _ := metadata.FromIncomingContext(ctx)
		auth := ""
		if v := md.Get("authorization"); len(v) > 0 {
			auth = v[0]
		}
		m.mu.Lock()
		m.lastAuth = auth
		m.mu.Unlock()
		if m.validTok != "" && auth != "Bearer "+m.validTok {
			return status.Error(codes.Unauthenticated, "invalid or missing token")
		}
	}

	if m.latency > 0 {
		select {
		case <-time.After(m.latency):
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "server-side deadline")
		}
	}
	return nil
}

func (m *MockServer) maybeFail(method string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errOverride[method] != nil {
		return m.errOverride[method]
	}
	if m.failN[method] > 0 {
		m.failN[method]--
		return status.Error(m.failCode[method], "injected "+m.failCode[method].String())
	}
	return nil
}

func (m *MockServer) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if err := m.begin(ctx, "GetCliente"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("GetCliente"); err != nil {
		return nil, err
	}
	return &v1.ClientePerfil{
		Cliente:             &v1.Cliente{Id: req.Id, Nombre: "Cliente Demo", ClaveInstitucion: "BCM", Key: "k1"},
		CatalogoInstitucion: &v1.CatalogoInstitucion{Id: 7, ClaveInstitucion: "BCM", NombreCorto: "Banco"},
	}, nil
}

func (m *MockServer) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	if err := m.begin(ctx, "GetCatalogo"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("GetCatalogo"); err != nil {
		return nil, err
	}
	return &v1.CatalogoInstitucion{Id: 7, ClaveInstitucion: req.ClaveInstitucion, NombreCorto: "Banco"}, nil
}

func (m *MockServer) GetQrStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if err := m.begin(ctx, "GetQrStatus"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("GetQrStatus"); err != nil {
		return nil, err
	}
	return &v1.JsonResponse{Json: `{"status":"ACTIVE","idc":"` + req.Idc + `"}`}, nil
}

func (m *MockServer) GetTelefonicoStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.JsonResponse, error) {
	if err := m.begin(ctx, "GetTelefonicoStatus"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("GetTelefonicoStatus"); err != nil {
		return nil, err
	}
	return &v1.JsonResponse{Json: `{"status":"PAID","idc":"` + req.Idc + `"}`}, nil
}

func (m *MockServer) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	m.mu.Lock()
	m.qrKeys = append(m.qrKeys, req.IdempotencyKey)
	m.mu.Unlock()
	if err := m.begin(ctx, "CreateQr"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("CreateQr"); err != nil {
		return nil, err
	}
	return &v1.JsonResponse{Json: `{"qr":"https://pay.tupago/qr/abc"}`}, nil
}

func (m *MockServer) CreateTelefonico(ctx context.Context, req *v1.CreateTelefonicoRequest) (*v1.JsonResponse, error) {
	m.mu.Lock()
	m.telKeys = append(m.telKeys, req.IdempotencyKey)
	m.mu.Unlock()
	if err := m.begin(ctx, "CreateTelefonico"); err != nil {
		return nil, err
	}
	if err := m.maybeFail("CreateTelefonico"); err != nil {
		return nil, err
	}
	return &v1.JsonResponse{Json: `{"ref":"TEL-123"}`}, nil
}

// testServer wraps an in-process gRPC server bound to a REAL loopback TCP
// listener. Using a genuine network address (not a configurable public dialer)
// means the SDK dials the declared Config.Target directly; there is therefore no
// public dialer that could redirect the connection to a remote plaintext peer.
// This is the sanctioned in-process test construction (option B/C of the
// hardening spec), deliberately NOT a public SDK option.
type testServer struct {
	srv     *grpc.Server
	lis     net.Listener
	addr    string
	certPEM []byte
}

// startTestServer starts an in-process gRPC server over a real loopback TCP
// listener using verified TLS. It returns a handle exposing the listen address
// (suitable for Config.Target) and the server certificate PEM (for the client CA
// pool). Callers must call stop() to release the listener.
func startTestServer(t *testing.T, srv v1.PaymentServiceServer) *testServer {
	t.Helper()
	certPEM, keyPEM := generateSelfSigned(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	v1.RegisterPaymentServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	return &testServer{srv: s, lis: lis, addr: lis.Addr().String(), certPEM: certPEM}
}

func (b *testServer) stop() {
	b.srv.Stop()
	_ = b.lis.Close()
}
