package client_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

// forgeHS512JWT builds a synthetic HS512 JWT from a base64-encoded secret. The
// secret is read from the environment at runtime; it is NEVER hard-coded here.
// HS512 matches the backend's JWT_ALGORITHM (MacAlgorithm.HS512). The claims
// mirror what the backend's JwtServerInterceptor / SecurityUtils expect:
//   - sub    : principal login (used as the authentication name)
//   - userId : numeric owner id (SecurityUtils.USER_ID_CLAIM, used for ownership)
//   - auth   : authority list (SecurityUtils.AUTHORITIES_CLAIM)
func forgeHS512JWT(t *testing.T, base64Secret, sub string, userID int64, auth []string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(base64Secret)
	require.NoError(t, err)
	header, _ := json.Marshal(map[string]string{"alg": "HS512", "typ": "JWT"})
	now := time.Now()
	payload, _ := json.Marshal(map[string]interface{}{
		"sub":    sub,
		"userId": userID,
		"auth":   auth,
		"iat":    now.Unix(),
		"exp":    now.Add(time.Hour).Unix(),
	})
	seg := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signing := seg(header) + "." + seg(payload)
	mac := hmac.New(sha512.New, raw)
	mac.Write([]byte(signing))
	return signing + "." + seg(mac.Sum(nil))
}

func backendReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TestBackend3RealReads exercises the four read RPCs against the real, isolated
// dev backend (gRPC loopback, local Postgres/Redis, synthetic JWT). Create RPCs
// are intentionally NOT exercised here (see the in-memory financial simulator).
//
// Required (runtime, not committed) env:
//   - TUPAGO_BACKEND_ADDR        explicit isolated cert/loopback endpoint (NO default; never 9090)
//   - TUPAGO_JWT_BASE64_SECRET   dev base64 JWT secret (for the "valid JWT" case)
func TestBackend3RealReads(t *testing.T) {
	addr := os.Getenv("TUPAGO_BACKEND_ADDR")
	if addr == "" {
		// No explicit target: never default to 127.0.0.1:9090 (which on a production
		// host collides with the live backend gRPC port). Require an explicit,
		// isolated cert/loopback endpoint so the suite can never silently probe prod.
		t.Skipf("BLOCKED: TUPAGO_BACKEND_ADDR not set; skipping real integration (point it at an isolated cert/loopback endpoint).")
	}
	if !backendReachable(addr) {
		t.Skipf("BLOCKED: backend real gRPC endpoint %s not reachable; skipping real integration (safe tests continue).", addr)
	}

	ctx := context.Background()

	// Honour explicit TLS+CA when the lab CA is provided (loopback cert env serves
	// TLS). Fall back to explicit Insecure(loopback) only for a plaintext dev backend.
	// Verification is never disabled; serverName is pinned to "localhost".
	caPath := os.Getenv("TUPAGO_GRPC_CA_PATH")
	buildCreds := func(t *testing.T, token string) *client.Config {
		cfg := &client.Config{Target: addr, ConnectTimeout: 5 * time.Second,
			Credentials: auth.StaticTokenProvider(token)}
		if caPath != "" {
			pem, rerr := os.ReadFile(caPath)
			require.NoError(t, rerr)
			tlsCfg, cerr := security.NewTLSConfig(security.WithCACertPEM(pem), security.WithServerName("localhost"))
			require.NoError(t, cerr)
			cfg.TLS = tlsCfg
		} else {
			cfg.Insecure = true
		}
		return cfg
	}

	// Absent token: raw connection without per-RPC credentials -> UNAUTHENTICATED.
	var absentRawCreds credentials.TransportCredentials
	if caPath != "" {
		pem, rerr := os.ReadFile(caPath)
		require.NoError(t, rerr)
		tlsCfg, cerr := security.NewTLSConfig(security.WithCACertPEM(pem), security.WithServerName("localhost"))
		require.NoError(t, cerr)
		absentRawCreds = credentials.NewTLS(tlsCfg.Config)
	} else {
		absentRawCreds = insecure.NewCredentials()
	}
	rawConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(absentRawCreds))
	require.NoError(t, err)
	defer rawConn.Close()
	absent := v1.NewPaymentServiceClient(rawConn)
	_, err = absent.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated),
		"absent JWT must be rejected with UNAUTHENTICATED, got: %v", err)

	// Invalid token -> UNAUTHENTICATED.
	badC, err := client.NewClient(ctx, buildCreds(t, "not-a-valid-token"))
	require.NoError(t, err)
	defer badC.Close()
	_, err = badC.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated),
		"invalid JWT must be rejected with UNAUTHENTICATED, got: %v", err)

	// Valid synthetic HS512 JWT (if secret supplied). The backend's loopback
	// gRPC transport is plaintext (TLS off, loopback bind permitted by
	// GrpcTransportSecurity.enforce), so we connect with Insecure: true. We
	// assert that the request is authenticated (NOT UNAUTHENTICATED) and, for
	// GetCliente(id=1), that ownership resolution returns the entity owned by
	// the JWT principal (prodgcp / userId=2000).
	// Operator-supplied scoped token (F03 A/B matrix): if TUPAGO_JWT is set, use it
	// directly instead of forging. Never printed, logged, or written to disk.
	if operatorTok := os.Getenv("TUPAGO_JWT"); operatorTok != "" {
		validC, err := client.NewClient(ctx, buildCreds(t, operatorTok))
		require.NoError(t, err)
		defer validC.Close()
		_, cerr := validC.GetCliente(ctx, &v1.GetClienteRequest{Id: 1})
		require.NoError(t, cerr, "valid operator JWT must be authenticated (NOT UNAUTHENTICATED)")
		return
	}
	secret := os.Getenv("TUPAGO_JWT_BASE64_SECRET")
	if secret == "" {
		t.Logf("TUPAGO_JWT_BASE64_SECRET not set; skipping valid-JWT read assertions (auth-required cases still verified).")
		return
	}
	// prodgcp (user id 2000) owns cliente id=1 in the dev/local dataset.
	tok := forgeHS512JWT(t, secret, "prodgcp", 2000, []string{"ROLE_USER"})
	validC, err := client.NewClient(ctx, buildCreds(t, tok))
	require.NoError(t, err)
	defer validC.Close()

	// Ownership proof: GetCliente(1) must succeed and return the entity owned
	// by the authenticated principal (fail-closed auth path is verified above).
	c, cerr := validC.GetCliente(ctx, &v1.GetClienteRequest{Id: 1})
	require.NoError(t, cerr, "GetCliente(1) must succeed with a valid HS512 JWT (ownership)")
	require.NotNil(t, c)
	assert.Equal(t, int64(1), c.GetCliente().GetId())
	assert.Equal(t, "Cliente ProdGCP", c.GetCliente().GetNombre())

	// Unknown cliente -> NOT_FOUND (authenticated, but entity absent).
	_, nfErr := validC.GetCliente(ctx, &v1.GetClienteRequest{Id: 999})
	require.Error(t, nfErr)
	assert.True(t, errors.HasGRPCCode(nfErr, codes.NotFound),
		"GetCliente(999) must be NOT_FOUND for an authenticated caller, got: %v", nfErr)

	for _, name := range []string{"GetCatalogo", "GetQrStatus", "GetTelefonicoStatus"} {
		name := name
		t.Run("valid-"+name, func(t *testing.T) {
			var rerr error
			switch name {
			case "GetCatalogo":
				_, rerr = validC.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
			case "GetQrStatus":
				_, rerr = validC.GetQrStatus(ctx, &v1.GetStatusRequest{Idc: "nope", IdCuenta: 1})
			case "GetTelefonicoStatus":
				_, rerr = validC.GetTelefonicoStatus(ctx, &v1.GetStatusRequest{Idc: "nope", IdCuenta: 1})
			}
			// The dev dataset has no matching record, so these return NOT_FOUND.
			// The gate we certify is authentication: the request must NOT be
			// UNAUTHENTICATED for a valid HS512 JWT.
			require.Error(t, rerr, "%s should return an error (NOT_FOUND expected)", name)
			assert.False(t, errors.HasGRPCCode(rerr, codes.Unauthenticated),
				"%s must be authenticated (NOT UNAUTHENTICATED) with a valid HS512 JWT, got: %v", name, rerr)
		})
	}
}
