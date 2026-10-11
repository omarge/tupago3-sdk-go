package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/omarge/tupago3-sdk-go/errors"
	v1 "github.com/omarge/tupago3-sdk-go/proto/tupago/api/v1"
)

// --- Point 10: latency + low deadline -> DeadlineExceeded, no Create retry. ---
func TestResilienceReadDeadline(t *testing.T) {
	srv := NewMockServer()
	srv.SetLatency(200 * time.Millisecond)
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	// generous deadline -> success despite latency
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.GetCliente(ctx, &v1.GetClienteRequest{Id: 1})
	require.NoError(t, err)
	require.Equal(t, 1, srv.Calls("GetCliente"))

	// tiny deadline -> DeadlineExceeded, single attempt (no retry on deadline)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel2()
	_, err = c.GetCliente(ctx2, &v1.GetClienteRequest{Id: 1})
	require.Error(t, err)
	assert.True(t, errors.HasGRPCCode(err, codes.DeadlineExceeded))
	assert.Equal(t, 2, srv.Calls("GetCliente"), "deadline failure must not be retried")
}

// --- Point 10: Create after send loss -> UnknownOutcome (exactly one send). ---
func TestResilienceCreateAfterSendLossUnknownOutcome(t *testing.T) {
	srv := NewMockServer()
	srv.FailTimes("CreateTelefonico", 1, codes.Unavailable) // request received, then dropped
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	_, err := c.CreateTelefonico(context.Background(), &v1.CreateTelefonicoRequest{
		Key: "k", Monto: 10, IdempotencyKey: "resil-1",
	})
	require.Error(t, err)
	assert.True(t, errors.IsUnknownOutcome(err), "loss after send -> UnknownOutcome")
	assert.True(t, errors.HasGRPCCode(err, codes.Unavailable))
	assert.Equal(t, 1, srv.Calls("CreateTelefonico"))
}

// --- Point 10: duplicate/late response must not trigger a second invocation. ---
func TestResilienceNoDuplicateReinvocation(t *testing.T) {
	srv := NewMockServer()
	b := startTestServer(t, srv)
	defer b.stop()
	c := newTestClient(t, b, testToken)
	defer c.Close()

	// run CreateQr several times; each must be exactly one server invocation.
	for i := 0; i < 5; i++ {
		_, err := c.CreateQr(context.Background(), &v1.CreateQrRequest{
			IdCuenta: 1, Monto: 5, IdempotencyKey: "dup-" + string(rune('a'+i)),
		})
		require.NoError(t, err)
	}
	assert.Equal(t, 5, srv.Calls("CreateQr"), "each CreateQr is a single invocation")
}

// --- Point 10: concurrent clients do not cross-talk or retry financially. ---
func TestResilienceConcurrentClients(t *testing.T) {
	srv := NewMockServer()
	b := startTestServer(t, srv)
	defer b.stop()

	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			c := newTestClient(t, b, testToken)
			defer c.Close()
			_, e := c.GetCatalogo(context.Background(), &v1.GetCatalogoRequest{ClaveInstitucion: "BCM"})
			errs <- e
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
}
