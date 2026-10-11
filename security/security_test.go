package security_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/omarge/tupago3-sdk-go/security"
)

func TestIsLoopback(t *testing.T) {
	assert.True(t, security.IsLoopback("127.0.0.1:8080"))
	assert.True(t, security.IsLoopback("::1"))
	assert.True(t, security.IsLoopback("localhost:443"))
	assert.False(t, security.IsLoopback("pay.tupago.mx:443"))
	assert.False(t, security.IsLoopback("192.168.1.1:443"))
}

func TestRequireTLSForTarget(t *testing.T) {
	// loopback plaintext allowed
	require.NoError(t, security.RequireTLSForTarget("127.0.0.1:8080", false))
	// non-loopback without TLS rejected
	require.Error(t, security.RequireTLSForTarget("pay.tupago.mx:443", false))
	// non-loopback with TLS allowed
	require.NoError(t, security.RequireTLSForTarget("pay.tupago.mx:443", true))
}

func TestNewTLSConfigWithInvalidCA(t *testing.T) {
	_, err := security.NewTLSConfig(security.WithCACertPEM([]byte("not-pem")))
	require.Error(t, err)

	ca := `-----BEGIN CERTIFICATE-----
MIIBdummy
-----END CERTIFICATE-----`
	_, err = security.NewTLSConfig(security.WithCACertPEM([]byte(ca)))
	require.Error(t, err) // invalid PEM content -> parse error
}

func TestNewTLSConfigBaseline(t *testing.T) {
	cfg, err := security.NewTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.Config)
}
