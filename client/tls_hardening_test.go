package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

// reqHasBearer reports whether the incoming gRPC context carried a non-empty
// "Bearer" Authorization header (the SDK's JWT contract over any transport).
func reqHasBearer(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, v := range md.Get("authorization") {
		const prefix = "Bearer "
		if len(v) > len(prefix) && v[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// bearerRecorder optionally requires a Bearer token on GetCliente.
type bearerRecorder struct {
	v1.UnimplementedPaymentServiceServer
	requireAuth bool
}

func (s *bearerRecorder) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if s.requireAuth && !reqHasBearer(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing bearer")
	}
	return &v1.ClientePerfil{Cliente: &v1.Cliente{Id: req.Id, Nombre: "ok"}}, nil
}

// startPlaintextServer starts an in-process gRPC server over a REAL loopback TCP
// listener using plaintext (no TLS). Used only to prove loopback plaintext is
// still sanctioned; it can never be reached by a non-loopback target because the
// SDK dials the declared Config.Target directly (no public dialer).
func startPlaintextServer(t *testing.T, srv v1.PaymentServiceServer) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := grpc.NewServer() // plaintext, loopback only
	v1.RegisterPaymentServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), func() { s.Stop(); _ = lis.Close() }
}

// assertPublicAPIAbsent verifies that a public symbol is no longer exposed by a
// package, using `go doc` (compile-time API surface evidence).
func assertPublicAPIAbsent(t *testing.T, pkg, sym string) {
	out, err := exec.Command("go", "doc", pkg).CombinedOutput()
	require.NoError(t, err, "go doc must succeed for %s", pkg)
	assert.NotContains(t, string(out), sym,
		"public API %s must NOT expose %q", pkg, sym)
}

// isDialerFunc reports whether rt matches func(context.Context, string)(net.Conn,error).
func isDialerFunc(rt reflect.Type) bool {
	if rt.Kind() != reflect.Func || rt.NumIn() != 2 || rt.NumOut() != 1 {
		return false
	}
	if rt.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		return false
	}
	if rt.Out(0) != reflect.TypeOf((*net.Conn)(nil)).Elem() {
		return false
	}
	return true
}

// SEC-GO-01: server identity verification cannot be turned off. A consumer that
// sets InsecureSkipVerify=true via the SDK's own TLSConfig is rejected.
func TestSEC01RemoteTLSWithoutCertificateVerificationRejected(t *testing.T) {
	b := startTestServer(t, NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(
		security.WithCACertPEM(b.certPEM),
		security.WithServerName("localhost"),
	)
	require.NoError(t, err)
	tlsCfg.Config.InsecureSkipVerify = true // attempt to disable verification

	_, err = client.NewClient(context.Background(), &client.Config{
		Target:      b.addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "InsecureSkipVerify",
		"disabling certificate verification must be rejected")
}

// SEC-GO-01: the public helper that used to skip verification is gone from the
// production API surface.
func TestSEC02InsecureSkipVerifyRejected(t *testing.T) {
	assertPublicAPIAbsent(t, "github.com/omarge/tupago3-sdk-go/security", "WithInsecureSkipVerify")
}

// SEC-GO-01: a consumer-supplied raw *tls.Config with InsecureSkipVerify=true
// (bypassing NewTLSConfig) is also rejected — the guard is not limited to the
// removed helper.
func TestSEC03CustomTLSConfigCannotDisableVerification(t *testing.T) {
	b := startTestServer(t, NewMockServer())
	defer b.stop()
	cfg := &security.TLSConfig{
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	}
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      b.addr,
		TLS:         cfg,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "InsecureSkipVerify",
		"a raw tls.Config disabling verification must be rejected")
}

// SEC-GO-01: ServerName mismatch fails certificate verification (fail-closed).
func TestSEC04ServerNameMismatchRejected(t *testing.T) {
	b := startTestServer(t, NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(
		security.WithCACertPEM(b.certPEM),
		security.WithServerName("wrong.example.com"),
	)
	require.NoError(t, err)
	_, err = client.NewClient(context.Background(), &client.Config{
		Target:         b.addr,
		TLS:            tlsCfg,
		Credentials:    auth.StaticTokenProvider(testToken),
		ConnectTimeout: 2 * time.Second,
	})
	require.Error(t, err, "hostname mismatch must fail certificate verification")
	assert.NotContains(t, err.Error(), "TLS required")
	assert.NotContains(t, err.Error(), "InsecureSkipVerify")
}

// SEC-GO-01: an untrusted CA chain fails verification (fail-closed).
func TestSEC05UntrustedCARejected(t *testing.T) {
	b := startTestServer(t, NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig() // no CA -> system roots only
	require.NoError(t, err)
	_, err = client.NewClient(context.Background(), &client.Config{
		Target:         b.addr,
		TLS:            tlsCfg,
		Credentials:    auth.StaticTokenProvider(testToken),
		ConnectTimeout: 2 * time.Second,
	})
	require.Error(t, err, "untrusted server certificate must fail closed")
	assert.NotContains(t, err.Error(), "TLS required")
	assert.NotContains(t, err.Error(), "InsecureSkipVerify")
}

// SEC-GO-01: a trusted CA + correct ServerName authenticates the server and the
// RPC succeeds (verified TLS, not just encryption).
func TestSEC06TrustedCAAccepted(t *testing.T) {
	b := startTestServer(t, NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(
		security.WithCACertPEM(b.certPEM),
		security.WithServerName("localhost"),
	)
	require.NoError(t, err)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      b.addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err, "verified TLS with trusted CA must succeed")
}

// SEC-GO-02: a loopback plaintext target (the only sanctioned plaintext path)
// connects to the declared address directly; there is no public dialer that could
// redirect it to a remote plaintext peer.
func TestSEC07DeclaredLoopbackCannotRedirectPlaintextViaPublicAPI(t *testing.T) {
	addr, stop := startPlaintextServer(t, NewMockServer())
	defer stop()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      addr, // loopback, plaintext
		Insecure:    true,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err, "loopback plaintext must connect to the declared target only")
}

// SEC-GO-02: the public Config exposes no dialer field of any kind, so a caller
// cannot inject a connection dialer that returns remote plaintext TCP conns.
func TestSEC08PublicConfigCannotInjectRemoteDialer(t *testing.T) {
	ct := reflect.TypeOf(client.Config{})
	for i := 0; i < ct.NumField(); i++ {
		f := ct.Field(i)
		assert.NotEqual(t, "TestDialer", f.Name, "Config must not expose a public dialer field")
		assert.False(t, isDialerFunc(f.Type),
			"Config field %s must not be a connection dialer func", f.Name)
	}
	assertPublicAPIAbsent(t, "github.com/omarge/tupago3-sdk-go/client", "TestDialer")
}

// SEC-GO-02: a non-loopback target without TLS is rejected at configuration time
// (before any dial), so no remote plaintext channel can open.
func TestSEC09RemotePlaintextRejectedBeforeDial(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "198.51.100.1:443",
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS required")
}

// SEC-GO-02: loopback plaintext remains permitted (regression of the sanctioned
// dev/backend path).
func TestSEC10LoopbackPlaintextStillAllowed(t *testing.T) {
	addr, stop := startPlaintextServer(t, NewMockServer())
	defer stop()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      addr,
		Insecure:    true,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
}

// TLS identity and JWT are independent properties: the Bearer is delivered over
// authenticated TLS, and a missing Bearer is rejected by the server.
func TestSEC11JWTPreservedOnAuthenticatedTLS(t *testing.T) {
	b := startTestServer(t, &bearerRecorder{requireAuth: true})
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(
		security.WithCACertPEM(b.certPEM),
		security.WithServerName("localhost"),
	)
	require.NoError(t, err)

	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      b.addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider("good-token"),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err, "bearer token must be delivered over authenticated TLS")

	bad, err := client.NewClient(context.Background(), &client.Config{
		Target:      b.addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(""),
	})
	require.NoError(t, err)
	defer bad.Close()
	_, err = bad.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated),
		"missing bearer must be rejected over authenticated TLS")
}

// Financial invariant preserved: CreateQr is attempted exactly once and a
// transient post-send failure maps to a non-retryable UnknownOutcome.
func TestSEC12NoRetryCreateQrPreserved(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateQr", 5, codes.Unavailable)
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "sec12",
	})
	require.Error(t, err)
	assert.Equal(t, 1, srv.Calls("CreateQr"), "CreateQr must be attempted exactly once")
}

func TestSEC13NoRetryCreateTelefonicoPreserved(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateTelefonico", 5, codes.Unavailable)
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 10, IdempotencyKey: "sec13",
	})
	require.Error(t, err)
	assert.Equal(t, 1, srv.Calls("CreateTelefonico"), "CreateTelefonico must be attempted exactly once")
}

func TestSEC14UnknownOutcomePreserved(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateQr", 1, codes.Unavailable)
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "sec14",
	})
	require.Error(t, err)
	assert.True(t, errors.IsUnknownOutcome(err), "UNAVAILABLE on sent Create -> UnknownOutcome")
	assert.False(t, errors.IsRetryable(err), "UnknownOutcome must not be retryable")
	assert.Equal(t, 1, srv.Calls("CreateQr"))
}

// The independent consumer module (public API only) still builds and passes
// after removing WithInsecureSkipVerify and TestDialer. The consumer lives in-repo
// (examples/consumer, its own go.mod with a local replace to the SDK) so it is
// deterministically available in CI without depending on a sibling VCS repo.
func TestSEC15ExternalConsumerBuildAndRuntimeGREEN(t *testing.T) {
	if testing.Short() {
		t.Skip("external consumer verification skipped in short mode")
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve test source path")
	}
	// This test file lives at <repo>/client/tls_hardening_test.go; resolve the
	// in-repo consumer module from the repo root rather than the package cwd.
	repoRoot := filepath.Dir(filepath.Dir(thisFile))
	consumerDir := filepath.Join(repoRoot, "examples", "consumer")

	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = consumerDir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "external consumer tests must pass:\n%s", out)
}
