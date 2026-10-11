// Package retry provides bounded, read-only retry with backoff. Create RPCs use
// NoRetry: they must never be retried automatically (see the financial
// invariants in the SDK contract).
package retry

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Policy controls retry behaviour. MaxAttempts==1 means no retry.
type Policy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	MaxElapsed  time.Duration
}

// NoRetry forbids automatic retries (used for Create operations).
func NoRetry() *Policy {
	return &Policy{MaxAttempts: 1}
}

// BoundedReadBackoff retries transient read failures with capped backoff.
func BoundedReadBackoff() *Policy {
	return &Policy{
		MaxAttempts: 4,
		BaseDelay:   20 * time.Millisecond,
		MaxDelay:    200 * time.Millisecond,
		MaxElapsed:  1 * time.Second,
	}
}

// Default returns a sensible default policy (bounded read backoff).
func Default() *Policy { return BoundedReadBackoff() }

// IsRetryableRead reports whether a gRPC error is a transient read failure that
// may be retried with bounded backoff. CANCELLED is intentionally excluded.
func IsRetryableRead(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Internal, codes.Unknown:
		return true
	default:
		return false
	}
}

func (p *Policy) backoff(attempt int) time.Duration {
	if p == nil || p.BaseDelay <= 0 {
		return 0
	}
	d := p.BaseDelay * time.Duration(1<<uint(attempt-1))
	if p.MaxDelay > 0 && d > p.MaxDelay {
		d = p.MaxDelay
	}
	return d
}

// Do runs op, retrying (with backoff) only on IsRetryableRead, until success,
// a non-retryable error, MaxAttempts, ctx cancellation, or MaxElapsed.
func (p *Policy) Do(ctx context.Context, op func(ctx context.Context) error) error {
	if p == nil {
		p = NoRetry()
	}
	var lastErr error
	start := time.Now()
	for attempt := 0; attempt < p.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := p.backoff(attempt)
			if delay > 0 {
				select {
				case <-ctx.Done():
					if lastErr != nil {
						return lastErr
					}
					return ctx.Err()
				case <-time.After(delay):
				}
			}
		}
		lastErr = op(ctx)
		if lastErr == nil {
			return nil
		}
		if !IsRetryableRead(lastErr) {
			return lastErr
		}
		if p.MaxElapsed > 0 && time.Since(start) > p.MaxElapsed {
			return lastErr
		}
	}
	return lastErr
}
