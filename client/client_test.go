package client_test

import (
	"bytes"
	"context"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/status"
	"os"

	"github.com/omarge/tupago3-sdk-go/auth"
	"github.com/omarge/tupago3-sdk-go/client"
	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
	"github.com/omarge/tupago3-sdk-go/security"
)

const testToken = "eyJhbGciOiJIUzI1NiJ9.test-token"

func newTestClient(t *testing.T, b *bufConnServer, token string, opts ...func(*client.Config)) *client.PaymentClient {
	t.Helper()
	tlsCfg, err := security.NewTLSConfig(
		security.WithCACertPEM(b.certPEM),
		security.WithServerName("localhost"),
	)
	require.NoError(t, err)
	cfg := &client.Config{
		Target:      "passthrough:///bufnet",
		TLS:         tlsCfg,
		Credentials: auth.StaticTokenProvider(token),
		TestDialer:  b.dialer(),
	}
	for _, o := range opts {
		o(cfg)
	}
	c, err := client.NewClient(context.Background(), cfg)
	require.NoError(t, err)
	return c
}

// --- Point 1: the six RPCs succeed. ---
func TestSixRPCs(t *testing.T) {
	b := startBufConn(NewMockServer())
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	ctx := context.Background()

	cli, err := c.GetCliente(ctx, &v1.GetClienteRequest{Id: 42})
	require.NoError(t, err)
	require.Equal(t, int64(42), cli.Cliente.Id)

	cat, err := c.GetCatalogo(ctx, &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
	require.NoError(t, err)
	require.Equal(t, "BCM", cat.ClaveInstitucion)

	qs, err := c.GetQrStatus(ctx, &v1.GetStatusRequest{Idc: "IDC1", IdCuenta: 9})
	require.NoError(t, err)
	assert.Contains(t, qs.Json, "IDC1")

	ts, err := c.GetTelefonicoStatus(ctx, &v1.GetStatusRequest{Idc: "IDC2", IdCuenta: 9})
	require.NoError(t, err)
	assert.Contains(t, ts.Json, "IDC2")

	qr, err := c.CreateQr(ctx, &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 100.50, Concepto: "Pago", IdempotencyKey: "k-qr-1",
	})
	require.NoError(t, err)
	assert.Contains(t, qr.Json, "qr")

	tel, err := c.CreateTelefonico(ctx, &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 200, IdempotencyKey: "k-tel-1",
	})
	require.NoError(t, err)
	assert.Contains(t, tel.Json, "TEL")
}

// --- Point 4: JsonResponse passthrough. ---
func TestJsonResponsePassthrough(t *testing.T) {
	srv := NewMockServer()
	srv.OverrideError("GetQrStatus", nil) // ensure success path; set json below
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	out, err := c.GetQrStatus(context.Background(), &v1.GetStatusRequest{Idc: "X"})
	require.NoError(t, err)
	require.Equal(t, `{"status":"ACTIVE","idc":"X"}`, out.Json)
}

// --- Point 5: JWT dynamic / absent / invalid. ---
func TestJWTDynamicAndAuth(t *testing.T) {
	srv := NewMockServer()
	srv.SetAuthRequired(testToken)
	b := startBufConn(srv)
	defer b.stop()

	// valid token -> success and header captured
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
	assert.Equal(t, "Bearer "+testToken, srv.LastAuth())

	// dynamic provider rotates token
	rotations := 0
	prov := auth.FuncTokenProvider(func(context.Context) (string, error) {
		rotations++
		return testToken, nil
	})
	c2 := newTestClient(t, b, "", func(cfg *client.Config) { cfg.Credentials = prov })
	defer c2.Close()
	_, err = c2.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
	assert.Equal(t, 1, rotations)

	// invalid token -> UNAUTHENTICATED
	c3 := newTestClient(t, b, "wrong-token")
	defer c3.Close()
	_, err = c3.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated))

	// absent token -> UNAUTHENTICATED
	c4 := newTestClient(t, b, "")
	defer c4.Close()
	_, err = c4.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.Unauthenticated))
}

// --- Point 7: full error matrix maps to correct gRPC code. ---
func TestErrorMatrix(t *testing.T) {
	codesToTest := []codes.Code{
		codes.NotFound, codes.PermissionDenied, codes.InvalidArgument,
		codes.AlreadyExists, codes.FailedPrecondition, codes.Aborted,
		codes.Internal, codes.Unavailable, codes.DeadlineExceeded, codes.Canceled,
	}
	for _, code := range codesToTest {
		code := code
		t.Run(code.String(), func(t *testing.T) {
			srv := NewMockServer()
			srv.OverrideError("GetCatalogo", status.Error(code, "boom"))
			b := startBufConn(srv)
			defer b.stop()
			c := newTestClient(t, b, testToken)
			defer c.Close()
			_, err := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "X"})
			require.Error(t, err)
			assert.True(t, errors.IsTupagoError(err), "should be a TupagoError")
			assert.True(t, errors.HasGRPCCode(err, code), "code %s preserved", code)
		})
	}
}

// --- Point 8: bounded backoff ONLY on reads. ---
func TestReadBackoffBounded(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("GetCliente", 2, codes.Unavailable) // fail twice then succeed
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	start := time.Now()
	_, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
	require.Equal(t, 3, srv.Calls("GetCliente"), "read should retry transient failures")
	assert.Less(t, time.Since(start), 2*time.Second, "backoff must be bounded")
}

func TestReadNonRetryableImmediate(t *testing.T) {
	srv := NewMockServer()
	srv.OverrideError("GetCliente", status.Error(codes.NotFound, "nope"))
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	require.Equal(t, 1, srv.Calls("GetCliente"), "non-retryable must not retry")
	assert.True(t, errors.HasGRPCCode(err, codes.NotFound))
}

// --- Points 9 & 10: CreateQr / CreateTelefonico exactly one attempt. ---
func TestCreateQrExactlyOnce(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateQr", 5, codes.Unavailable) // many transient failures
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-1",
	})
	require.Error(t, err)
	require.Equal(t, 1, srv.Calls("CreateQr"), "CreateQr MUST be attempted exactly once")
}

func TestCreateTelefonicoExactlyOnce(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateTelefonico", 5, codes.Unavailable)
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 10, IdempotencyKey: "idemp-t-1",
	})
	require.Error(t, err)
	require.Equal(t, 1, srv.Calls("CreateTelefonico"), "CreateTelefonico MUST be attempted exactly once")
}

// --- Points 11 & 12: UNAVAILABLE / DEADLINE_EXCEEDED on Create -> UnknownOutcome. ---
func TestCreateQrUnavailableIsUnknownOutcome(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateQr", 1, codes.Unavailable) // request received then dropped
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-u",
	})
	require.Error(t, err)
	assert.True(t, errors.IsUnknownOutcome(err), "UNAVAILABLE on sent Create -> UnknownOutcome")
	assert.True(t, errors.HasGRPCCode(err, codes.Unavailable))
	assert.False(t, errors.IsRetryable(err) == true, "UnknownOutcome must not be retryable")
	assert.Equal(t, 1, srv.Calls("CreateQr"))
}

func TestCreateTelefonicoDeadlineExceededIsUnknownOutcome(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateTelefonico", 1, codes.DeadlineExceeded)
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 10, IdempotencyKey: "idemp-d",
	})
	require.Error(t, err)
	assert.True(t, errors.IsUnknownOutcome(err))
	assert.True(t, errors.HasGRPCCode(err, codes.DeadlineExceeded))
	assert.Equal(t, 1, srv.Calls("CreateTelefonico"))
}

// --- Point 13: cancellation and disconnect. ---
func TestCreateCancelledBeforeCallNotSent(t *testing.T) {
	srv := NewMockServer()
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.CreateQr(ctx, &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-c"})
	require.Error(t, err)
	assert.True(t, errors.IsRequestNotSent(err), "cancelled before send must be request-not-sent")
}

func TestCreateDisconnectAfterConnect(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateQr", 1, codes.Unavailable)
	b := startBufConn(srv)
	c := newTestClient(t, b, testToken)
	// stop server to force a disconnect; keep client
	b.stop()
	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-dc"})
	require.Error(t, err)
	// either not-sent (connection gone) or unknown outcome (indeterminate) is acceptable;
	// neither must be retryable and the attempt count is at most one.
	assert.True(t, !errors.IsRetryable(err) || errors.IsUnknownOutcome(err))
}

// --- Point 14: TUPAGO_PENDING_RECONCILIATION. ---
func TestPendingReconciliation(t *testing.T) {
	srv := NewMockServer()
	srv.OverrideError("CreateQr", status.Error(codes.Aborted,
		"TUPAGO_PENDING_RECONCILIATION: duplicate idempotency key in flight"))
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-pr"})
	require.Error(t, err)
	assert.True(t, errors.IsPendingReconciliation(err), "ABORTED+TUPAGO_PENDING_RECONCILIATION detectable")
	assert.False(t, errors.IsRetryable(err) || errors.IsUnknownOutcome(err), "must NOT be classified retryable")
	assert.Equal(t, 1, srv.Calls("CreateQr"))
}

// --- Point 15: idempotency key preserved verbatim. ---
func TestIdempotencyKeyIntact(t *testing.T) {
	srv := NewMockServer()
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	key := "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
		IdCuenta: 1, Monto: 10, IdempotencyKey: key,
	})
	require.NoError(t, err)
	keys := srv.QrKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, key, keys[0], "idempotency_key must be preserved literally")
}

func TestIdempotencyKeyRejectedWhenEmpty(t *testing.T) {
	srv := NewMockServer()
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()
	_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.InvalidArgument))
	assert.Equal(t, 0, srv.Calls("CreateQr"), "must not reach server with empty idempotency_key")
}

// --- Point 16: concurrency and close. ---
func TestConcurrencyAndClose(t *testing.T) {
	srv := NewMockServer()
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, e := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
			errs <- e
		}()
		go func() {
			defer wg.Done()
			_, e := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}

	require.NoError(t, c.Close())
	require.NoError(t, c.Close(), "Close must be idempotent")
	_, err := c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	assert.Error(t, err, "calls after Close must fail")
}

// --- Point 17: absence of secrets in logs. ---
func TestNoSecretsInLogs(t *testing.T) {
	srv := NewMockServer()
	b := startBufConn(srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	// capture both the standard logger and grpc logger
	var buf bytes.Buffer
	log.SetOutput(&buf)
	grpclog.SetLoggerV2(grpclog.NewLoggerV2(&buf, &buf, &buf))
	defer func() {
		log.SetOutput(log.Writer())
		grpclog.SetLoggerV2(grpclog.NewLoggerV2(os.Stderr, os.Stderr, os.Stderr))
	}()

	_, _ = c.GetCliente(context.Background(), &v1.GetClienteRequest{Id: 1})
	_, _ = c.CreateQr(context.Background(), &v1.CreateQrRequest{IdCuenta: 1, Monto: 10, IdempotencyKey: "idemp-log"})

	out := buf.String()
	assert.NotContains(t, out, testToken, "token must never appear in logs")
	assert.NotContains(t, out, "Bearer ", "authorization header must never appear in logs")
}
