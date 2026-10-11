package client_test

import (
	"context"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

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

// bufConnServer wires a MockServer over an in-memory bufconn listener.
type bufConnServer struct {
	srv *grpc.Server
	lis *bufconn.Listener
}

func startBufConn(srv v1.PaymentServiceServer) *bufConnServer {
	lis := bufconn.Listen(4 * 1024 * 1024)
	s := grpc.NewServer()
	v1.RegisterPaymentServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	return &bufConnServer{srv: s, lis: lis}
}

func (b *bufConnServer) dialer() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return b.lis.DialContext(ctx)
	}
}

func (b *bufConnServer) stop() {
	b.srv.Stop()
	_ = b.lis.Close()
}
