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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

func generateSelfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tupago-test"},
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
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func startTLSServer(t *testing.T, certPEM, keyPEM []byte, plaintext bool) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var s *grpc.Server
	if plaintext {
		s = grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	} else {
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{c}})))
	}
	v1.RegisterPaymentServiceServer(s, NewMockServer())
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), func() { s.Stop() }
}

// --- Point 6: TLS mutual verification succeeds with injected CA. ---
func TestTLSWithInjectedCA(t *testing.T) {
	certPEM, keyPEM := generateSelfSigned(t)
	addr, stop := startTLSServer(t, certPEM, keyPEM, false)
	defer stop()

	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(certPEM))
	require.NoError(t, err)
	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.NoError(t, err)
	defer c.Close()

	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
}

// --- Point 6: absent CA -> certificate verification fails (fail-closed). ---
func TestTLSWithoutCAFailsClosed(t *testing.T) {
	certPEM, keyPEM := generateSelfSigned(t)
	addr, stop := startTLSServer(t, certPEM, keyPEM, false)
	defer stop()

	tlsCfg, err := security.NewTLSConfig() // no CA -> system roots
	require.NoError(t, err)
	_, err = client.NewClient(context.Background(), &client.Config{
		Target:      addr,
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err, "connection to an untrusted cert must fail closed")
}

// --- Point 6: plaintext rejected for non-loopback target. ---
func TestPlaintextRejectedForNonLoopback(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "192.0.2.1:443", // TEST-NET, non-loopback
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS required")
}

// --- Point 6: plaintext permitted for loopback. ---
func TestPlaintextAllowedForLoopback(t *testing.T) {
	addr, stop := startTLSServer(t, nil, nil, true) // insecure server
	defer stop()

	c, err := client.NewClient(context.Background(), &client.Config{
		Target:      addr, // 127.0.0.1 -> loopback
		Insecure:    false,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
}

// --- Point 6: Insecure is ALWAYS forbidden for non-loopback network targets.
// The removed AllowInsecureNonLoopback public flag used to let callers disable
// TLS for arbitrary remote targets; plaintext off-host is now fail-closed.
func TestInsecureForbiddenForNonLoopback(t *testing.T) {
	_, err := client.NewClient(context.Background(), &client.Config{
		Target:      "192.0.2.1:443", // TEST-NET, non-loopback
		Insecure:    true,
		Credentials: auth.StaticTokenProvider(testToken),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "plaintext not permitted")
}
