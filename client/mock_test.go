package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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

// bufConnServer wires a MockServer over an in-memory bufconn listener using a
// verified TLS transport (self-signed cert + injected CA). Tests exercise the
// SDK's TLS path over an in-memory channel, so no plaintext is ever opened and
// the loopback-plaintext exception is never relied upon. The dialer is injected
// into the SDK via Config.TestDialer (test-only), never via a public option that
// could downgrade TLS.
type bufConnServer struct {
	srv     *grpc.Server
	lis     *bufconn.Listener
	certPEM []byte
}

// genTestCert returns a self-signed PEM pair whose SANs include "localhost" and
// 127.0.0.1/::1, so the SDK's TLS verification (ServerName "localhost") succeeds.
func genTestCert() (certPEM, keyPEM []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("genTestCert: " + err.Error())
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tupago-bufnet-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		panic("genTestCert: " + err.Error())
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic("genTestCert: " + err.Error())
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func startBufConn(srv v1.PaymentServiceServer) *bufConnServer {
	certPEM, keyPEM := genTestCert()
	lis := bufconn.Listen(4 * 1024 * 1024)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic("startBufConn: bad key pair: " + err.Error())
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	v1.RegisterPaymentServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	return &bufConnServer{srv: s, lis: lis, certPEM: certPEM}
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
