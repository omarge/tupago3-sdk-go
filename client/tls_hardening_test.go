package client_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

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

// plainBufConn is an in-memory bufconn server that serves PLAINTEXT (no TLS).
// Used only to prove loopback plaintext still works when the SDK's policy allows
// it, and that a custom dialer can never downgrade TLS for a remote target.
type plainBufConn struct {
	srv *grpc.Server
	lis *bufconn.Listener
}

func startPlaintextBufConn(srv v1.PaymentServiceServer) *plainBufConn {
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer() // plaintext
	v1.RegisterPaymentServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	return &plainBufConn{srv: s, lis: lis}
}

func (p *plainBufConn) dialer() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return p.lis.DialContext(ctx)
	}
}

func (p *plainBufConn) stop() {
	p.srv.Stop()
	_ = p.lis.Close()
}

// hardeningRecorder is a server that optionally requires a Bearer token and that
// fails CreateQr with Unavailable so the SDK's UnknownOutcome mapping can be
// exercised. It records the number of CreateQr attempts (at-most-once check).
type hardeningRecorder struct {
	v1.UnimplementedPaymentServiceServer
	createCalls int
	requireAuth bool
}

func (s *hardeningRecorder) GetCliente(ctx context.Context, req *v1.GetClienteRequest) (*v1.ClientePerfil, error) {
	if s.requireAuth && !reqHasBearer(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing bearer")
	}
	return &v1.ClientePerfil{Cliente: &v1.Cliente{Id: req.Id, Nombre: "ok"}}, nil
}

func (s *hardeningRecorder) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	s.createCalls++
	if s.requireAuth && !reqHasBearer(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing bearer")
	}
	return nil, status.Error(codes.Unavailable, "injected")
}

// T01: A non-loopback target with no TLS (and no Insecure) is rejected before any
// dialer runs. There is no public option to open a plaintext channel to a remote.
func TestT01RemotePlaintextRejected(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "198.51.100.1:443",
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS required")
}

// T02: Even a test-injected dialer (the only dialer injection path remaining)
// cannot bypass the TLS requirement for a remote target. The dialer must not be
// invoked when the configuration is rejected.
func TestT02PassthroughRemoteDialerRejected(t *testing.T) {
	dialed := 0
	badDialer := func(ctx context.Context, _ string) (net.Conn, error) {
		dialed++
		return nil, fmt.Errorf("dialer must not run")
	}
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "198.51.100.1:443",
		Credentials: auth.StaticTokenProvider(testToken),
		TestDialer:  badDialer,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS required")
	assert.Equal(t, 0, dialed, "dialer must not run when TLS is required for a remote target")
}

// T03: A custom dialer reaches a TLS server, but the SDK enforces its OWN TLS
// config. A CA that does not match the server's certificate fails the handshake
// closed — the dialer cannot override or disable TLS.
func TestT03CustomDialerCannotOverrideTLS(t *testing.T) {
	b := startBufConn(NewMockServer())
	defer b.stop()
	otherCert, _ := genTestCert() // a DIFFERENT CA than the server's
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(otherCert), security.WithServerName("localhost"))
	require.NoError(t, err)
	// With a mismatched CA the TLS handshake never completes, so the connection
	// fails closed during connect (the dialer cannot disable TLS).
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:         "203.0.113.1:443", // declared remote
		TLS:            tlsCfg,
		Credentials:    auth.StaticTokenProvider(testToken),
		TestDialer:     b.dialer(),
		ConnectTimeout: 2 * time.Second,
	})
	require.Error(t, err, "TLS verification with a wrong CA must fail closed")
	assert.NotContains(t, err.Error(), "TLS required", "config was accepted; failure is at the TLS transport layer")
	assert.Nil(t, c)
}

// T04: Insecure (plaintext transport credentials) is rejected for any non-loopback
// target, so the SDK never constructs an insecure transport for a remote peer.
func TestT04InsecureTransportCredentialsRejectedNonLoopback(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "198.51.100.1:443",
		Insecure:    true,
		Credentials: auth.StaticTokenProvider(testToken),
		TestDialer:  func(ctx context.Context, _ string) (net.Conn, error) { return nil, fmt.Errorf("x") },
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext not permitted")
}

// T05: Loopback plaintext remains permitted (policy preserved) and works through a
// test-injected dialer, but ONLY because the declared target is loopback.
func TestT05LoopbackPlaintextAllowed(t *testing.T) {
	p := startPlaintextBufConn(NewMockServer())
	defer p.stop()
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      "127.0.0.1:50051", // loopback
		Credentials: auth.StaticTokenProvider(testToken),
		TestDialer:  p.dialer(),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
}

// T06: A declared remote target with a trusted CA over TLS succeeds — the secure
// path is fully functional through the test dialer.
func TestT06RemoteTLSVerifiedWithTrustedCA(t *testing.T) {
	b := startBufConn(NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(b.certPEM), security.WithServerName("localhost"))
	require.NoError(t, err)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      "203.0.113.1:443", // declared remote
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(testToken),
		TestDialer:  b.dialer(),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err, "TLS with a trusted CA must succeed")
}

// T07: A declared remote target with TLS but no trusted CA fails closed (the
// self-signed server certificate is not in the system roots).
func TestT07RemoteTLSRejectedWithoutTrustedCA(t *testing.T) {
	b := startBufConn(NewMockServer())
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig() // no CA -> system roots only
	require.NoError(t, err)
	// Without a trusted CA the handshake fails closed during connect.
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:         "203.0.113.1:443",
		TLS:            tlsCfg,
		Credentials:    auth.StaticTokenProvider(testToken),
		TestDialer:     b.dialer(),
		ConnectTimeout: 2 * time.Second,
	})
	require.Error(t, err, "untrusted server certificate must fail closed")
	assert.NotContains(t, err.Error(), "TLS required", "config was accepted; failure is at the TLS transport layer")
	assert.Nil(t, c)
}

// T08: The JWT Bearer is delivered over the TLS transport (not logged, not
// stripped). A server requiring the token accepts it; an empty token is rejected.
func TestT08JWTBearerPreservedWithTLS(t *testing.T) {
	b := startBufConn(&hardeningRecorder{requireAuth: true})
	defer b.stop()
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(b.certPEM), security.WithServerName("localhost"))
	require.NoError(t, err)

	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      "203.0.113.1:443",
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider("good-token"),
		TestDialer:  b.dialer(),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err, "bearer token must be delivered over TLS")

	bad, err := client.NewClient(context.Background(), &client.Config{
		Target:      "203.0.113.1:443",
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(""),
		TestDialer:  b.dialer(),
	})
	require.NoError(t, err)
	defer bad.Close()
	_, err = bad.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated), "missing bearer must be rejected over TLS")
}

// T09: The existing bufconn-based client (now TLS) still exercises the RPCs.
func TestT09BufconnTLSStillPasses(t *testing.T) {
	b := startBufConn(NewMockServer())
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
}

// T10/T11/T12: CreateQr is attempted exactly once and a transient post-send
// failure maps to a non-retryable UnknownOutcome.
func TestT10T11T12CreateUnknownOutcomeNonRetryable(t *testing.T) {
	rec := &hardeningRecorder{}
	b := startBufConn(rec)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "id-1"})
	require.Error(t, err)
	assert.Equal(t, 1, rec.createCalls, "CreateQr must be attempted exactly once (T10)")
	assert.True(t, errors.IsUnknownOutcome(err), "transient failure must map to UnknownOutcome (T11)")
	assert.False(t, errors.IsRetryable(err), "UnknownOutcome must not be retryable (T12)")
}

// T13: The independent consumer module (public-API only) still builds and passes
// after the API change. It depends on the local SDK via a go.mod replace.
func TestT13ExternalConsumerBuildsAndPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("external consumer verification skipped in short mode")
	}
	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = "../../tupago3-sdk-go-consumer"
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "external consumer tests must pass:\n%s", out)
}
