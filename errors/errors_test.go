package errors_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tuerrors "github.com/omarge/tupago3-sdk-go/errors"
)

func TestMapRPCErrorPreservesCode(t *testing.T) {
	err := tuerrors.MapRPCError(status.Error(codes.NotFound, "nope"), "GetCliente")
	require.True(t, tuerrors.IsTupagoError(err))
	assert.True(t, tuerrors.HasGRPCCode(err, codes.NotFound))
}

func TestMapCreateErrorUnknownOutcomeWhenSent(t *testing.T) {
	err := tuerrors.MapCreateError(status.Error(codes.Unavailable, "drop"), "CreateQr", true)
	require.True(t, tuerrors.IsUnknownOutcome(err))
	assert.True(t, tuerrors.HasGRPCCode(err, codes.Unavailable))
	assert.False(t, tuerrors.IsRetryable(err))
}

func TestMapCreateErrorNotSent(t *testing.T) {
	err := tuerrors.MapCreateError(status.Error(codes.Unavailable, "conn refused"), "CreateQr", false)
	require.Error(t, err)
	assert.True(t, tuerrors.IsRequestNotSent(err))
	assert.False(t, tuerrors.IsUnknownOutcome(err))
}

func TestMapCreateErrorPendingReconciliation(t *testing.T) {
	err := tuerrors.MapCreateError(
		status.Error(codes.Aborted, "TUPAGO_PENDING_RECONCILIATION: dup"), "CreateQr", true)
	require.True(t, tuerrors.IsPendingReconciliation(err))
	assert.False(t, tuerrors.IsRetryable(err))
	assert.False(t, tuerrors.IsUnknownOutcome(err))
}

func TestMapCreateErrorDefiniteOutcome(t *testing.T) {
	err := tuerrors.MapCreateError(status.Error(codes.AlreadyExists, "dup key"), "CreateQr", true)
	require.True(t, tuerrors.HasGRPCCode(err, codes.AlreadyExists))
	assert.False(t, tuerrors.IsUnknownOutcome(err))
	assert.False(t, tuerrors.IsPendingReconciliation(err))
}

func TestPredicatesAndWrapping(t *testing.T) {
	base := tuerrors.NewInvalidArgument("CreateQr", "bad monto")
	// wrapped gRPC error keeps detection
	wrapped := tuerrors.MapRPCError(status.Error(codes.InvalidArgument, base.Error()), "CreateQr")
	assert.True(t, tuerrors.HasGRPCCode(wrapped, codes.InvalidArgument))

	var te *tuerrors.TupagoError
	require.True(t, errors.As(wrapped, &te))
}

func TestConfigError(t *testing.T) {
	e := tuerrors.NewConfigError("Target", "required")
	assert.Contains(t, e.Error(), "Target")
}
