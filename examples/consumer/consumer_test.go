package main

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

// selfSignedCA returns a matching cert/key PEM pair for an in-process TLS server.
func selfSignedCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "consumer-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// recordingServer records calls and can enforce auth / return injected errors.
type recordingServer struct {
	v1.UnimplementedPaymentServiceServer
	calls   int
	authReq bool
	qrCode  codes.Code
}

// authorized reflects whether the SDK delivered a non-empty Bearer JWT on the
// request (the realistic contract: the gRPC interceptor reads the Authorization
// metadata). It is the consumer-side analogue of the backend JWT gate.
func authorized(ctx context.Context) bool {
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

func (s *recordingServer) GetCatalogo(ctx context.Context, req *v1.GetCatalogoRequest) (*v1.CatalogoInstitucion, error) {
	s.calls++
	if s.authReq && !authorized(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing token")
	}
	return nil, status.Error(codes.NotFound, "no such institution")
}

func (s *recordingServer) CreateQr(ctx context.Context, req *v1.CreateQrRequest) (*v1.JsonResponse, error) {
	s.calls++
	return nil, status.Error(s.qrCode, "injected")
}

// startTLSBench spins an in-process TLS gRPC server over a real loopback TCP
// listener and returns a connected, public-API client plus the server record.
func startTLSBench(t *testing.T, token string, authReq bool) (*client.PaymentClient, *recordingServer) {
	t.Helper()
	certPEM, keyPEM := selfSignedCA(t)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	rec := &recordingServer{authReq: authReq}
	v1.RegisterPaymentServiceServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(certPEM), security.WithServerName("localhost"))
	require.NoError(t, err)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      lis.Addr().String(),
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(token),
	})
	require.NoError(t, err)
	return c, rec
}

// TestConsumerVerifiesSDK is the independent-consumer certification. It builds the
// client from the public API only and asserts NOT_FOUND, UNAUTHENTICATED,
// UnknownOutcome (non-retryable, exactly-once) and proper resource closure.
func TestConsumerVerifiesSDK(t *testing.T) {
	c, rec := startTLSBench(t, "good-token", true)

	// NOT_FOUND on a read.
	_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "X"})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.NotFound), "consumer must see NOT_FOUND")

	// UNAUTHENTICATED with an empty token.
	bad, err := startTLSBenchNoAuth(t)
	require.NoError(t, err)
	_, err = bad.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "X"})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated), "consumer must see UNAUTHENTICATED")

	// UnknownOutcome on CreateQr: non-retryable and exactly-once.
	rec.qrCode = codes.Unavailable
	before := rec.calls
	_, err = c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "id-1"})
	require.Error(t, err)
	assert.True(t, errors.IsUnknownOutcome(err), "consumer must detect UnknownOutcome")
	assert.False(t, errors.IsRetryable(err), "UnknownOutcome must not be retryable")
	assert.Equal(t, before+1, rec.calls, "CreateQr must be attempted exactly once")

	// Resource closure.
	require.NoError(t, c.Close())
	_, err = c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "X"})
	assert.Error(t, err, "calls after Close must fail")
}

func startTLSBenchNoAuth(t *testing.T) (*client.PaymentClient, error) {
	t.Helper()
	certPEM, keyPEM := selfSignedCA(t)
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})))
	v1.RegisterPaymentServiceServer(srv, &recordingServer{authReq: true})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(certPEM), security.WithServerName("localhost"))
	if err != nil {
		return nil, err
	}
	return client.NewClient(context.Background(), &client.Config{
		Target:      lis.Addr().String(),
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(""),
	})
}
