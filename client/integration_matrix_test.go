package client_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	"github.com/omarge/tupago3-sdk-go/security"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// TestBackend3F03Matrix runs the full F03-R3 positive+negative read matrix for
// a single operator-issued, scoped JWT (token A or B) against the real, isolated
// cert/loopback backend. It is gated behind explicit env vars so it can never
// silently probe production (TUPAGO_BACKEND_ADDR must never be 9090).
//
// Required env (runtime, never committed):
//   - TUPAGO_BACKEND_ADDR   isolated gRPC TLS endpoint (e.g. localhost:29091)
//   - TUPAGO_GRPC_CA_PATH   public CA cert for serverName=localhost verification
//   - TUPAGO_JWT            scoped operator JWT (A or B) — never printed/logged
//   - TUPAGO_LABEL          "A" (userId 910001) or "B" (userId 910002)
func TestBackend3F03Matrix(t *testing.T) {
	addr := os.Getenv("TUPAGO_BACKEND_ADDR")
	if addr == "" {
		t.Skipf("BLOCKED: TUPAGO_BACKEND_ADDR not set; skipping F03 matrix (never defaults to 9090).")
	}
	caPath := os.Getenv("TUPAGO_GRPC_CA_PATH")
	if caPath == "" {
		t.Skipf("BLOCKED: TUPAGO_GRPC_CA_PATH not set; skipping F03 matrix (verification must stay on).")
	}
	jwt := os.Getenv("TUPAGO_JWT")
	if jwt == "" {
		t.Skipf("BLOCKED: TUPAGO_JWT not set; skipping F03 matrix (no operator token).")
	}
	label := os.Getenv("TUPAGO_LABEL")
	if label != "A" && label != "B" {
		t.Skipf("BLOCKED: TUPAGO_LABEL must be A or B; got %q.", label)
	}

	pem, err := os.ReadFile(caPath)
	require.NoError(t, err)
	tlsCfg, err := security.NewTLSConfig(security.WithCACertPEM(pem), security.WithServerName("localhost"))
	require.NoError(t, err)

	ownerID := int64(910001)
	foreignID := int64(910002)
	if label == "B" {
		ownerID, foreignID = 910002, 910001
	}

	ctx := context.Background()
	buildCreds := func(tok string) *client.Config {
		return &client.Config{
			Target:          addr,
			ConnectTimeout:  5 * time.Second,
			TLS:             tlsCfg,
			Credentials:     auth.StaticTokenProvider(tok),
		}
	}

	// Positive: owner-owned cliente is readable (auth + ownership OK).
	c, err := client.NewClient(ctx, buildCreds(jwt))
	require.NoError(t, err)
	defer c.Close()
	owner, err := c.GetCliente(ctx, &v1.GetClienteRequest{Id: ownerID})
	require.NoError(t, err, "TOKEN[%s] GetCliente(%d) must be OK", label, ownerID)
	require.NotNil(t, owner)

	// Positive: foreign cliente is NOT_FOUND for a scoped caller (auth works,
	// ownership enforced fail-closed).
	_, ferr := c.GetCliente(ctx, &v1.GetClienteRequest{Id: foreignID})
	require.Error(t, ferr, "TOKEN[%s] GetCliente(%d) must error", label, foreignID)
	assert.True(t, errors.HasGRPCCode(ferr, codes.NotFound),
		"TOKEN[%s] GetCliente(%d) must be NOT_FOUND, got: %v", label, foreignID, ferr)

	// Positive: institution catalog readable.
	_, cerr := c.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "TST99"})
	require.NoError(t, cerr, "TOKEN[%s] GetCatalogo(TST99) must be OK", label)

	// Negative: invalid token -> UNAUTHENTICATED.
	bad, err := client.NewClient(ctx, buildCreds("invalid.invalid.invalid"))
	require.NoError(t, err)
	defer bad.Close()
	_, berr := bad.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "TST99"})
	require.Error(t, berr)
	assert.True(t, errors.HasGRPCCode(berr, codes.Unauthenticated),
		"INVALID must be UNAUTHENTICATED, got: %v", berr)

	// Negative: absent JWT via raw connection -> UNAUTHENTICATED.
	rawConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg.Config)))
	require.NoError(t, err)
	defer rawConn.Close()
	absent := v1.NewPaymentServiceClient(rawConn)
	_, aerr := absent.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "TST99"})
	require.Error(t, aerr)
	assert.True(t, errors.HasGRPCCode(aerr, codes.Unauthenticated),
		"NO-JWT must be UNAUTHENTICATED, got: %v", aerr)
}
