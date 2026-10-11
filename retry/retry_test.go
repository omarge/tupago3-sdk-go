package retry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/omarge/tupago3-sdk-go/retry"
)

func TestIsRetryableRead(t *testing.T) {
	assert.True(t, retry.IsRetryableRead(status.Error(codes.Unavailable, "x")))
	assert.True(t, retry.IsRetryableRead(status.Error(codes.DeadlineExceeded, "x")))
	assert.False(t, retry.IsRetryableRead(status.Error(codes.NotFound, "x")))
	assert.False(t, retry.IsRetryableRead(status.Error(codes.Canceled, "x")))
	assert.False(t, retry.IsRetryableRead(nil))
}

func TestNoRetryInvokesOnce(t *testing.T) {
	p := retry.NoRetry()
	calls := 0
	err := p.Do(context.Background(), func(context.Context) error {
		calls++
		return status.Error(codes.Unavailable, "boom")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "NoRetry must invoke exactly once")
}

func TestBoundedBackoffRetriesThenSucceeds(t *testing.T) {
	p := &retry.Policy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	calls := 0
	err := p.Do(context.Background(), func(context.Context) error {
		calls++
		if calls < 3 {
			return status.Error(codes.Unavailable, "transient")
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestBoundedBackoffStopsOnNonRetryable(t *testing.T) {
	p := &retry.Policy{MaxAttempts: 10, BaseDelay: time.Millisecond}
	calls := 0
	err := p.Do(context.Background(), func(context.Context) error {
		calls++
		return status.Error(codes.NotFound, "nope")
	})
	require.Error(t, err)
	assert.Equal(t, 1, calls, "non-retryable must not be retried")
}

func TestPolicyRespectsContextCancellation(t *testing.T) {
	p := &retry.Policy{MaxAttempts: 10, BaseDelay: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := p.Do(ctx, func(context.Context) error {
		calls++
		return status.Error(codes.Unavailable, "x")
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled) || calls <= 1)
}
